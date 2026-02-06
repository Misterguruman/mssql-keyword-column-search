"""Tests for keyword_search.py."""

import csv
import os
from unittest.mock import MagicMock, call, patch

import pytest

import keyword_search


# ---------- escape_like_pattern ----------

class TestEscapeLikePattern:

    def test_plain_text(self):
        assert keyword_search.escape_like_pattern("hello") == "hello"

    def test_percent(self):
        assert keyword_search.escape_like_pattern("100%") == "100\\%"

    def test_underscore(self):
        assert keyword_search.escape_like_pattern("some_thing") == "some\\_thing"

    def test_bracket(self):
        assert keyword_search.escape_like_pattern("[test]") == "\\[test]"

    def test_backslash(self):
        assert keyword_search.escape_like_pattern("back\\slash") == "back\\\\slash"

    def test_combined(self):
        result = keyword_search.escape_like_pattern("100% [done]_ok\\end")
        assert result == "100\\% \\[done]\\_ok\\\\end"

    def test_custom_escape_char(self):
        result = keyword_search.escape_like_pattern("50%", escape_char="!")
        assert result == "50!%"


# ---------- parse_args ----------

class TestParseArgs:

    def test_csv_mode(self, tmp_path):
        kw_file = tmp_path / "kw.txt"
        kw_file.write_text("test\n")
        csv_file = tmp_path / "data.csv"
        csv_file.write_text("a,b\n1,2\n")

        args = keyword_search.parse_args([
            "--csv", str(csv_file),
            "-k", str(kw_file),
        ])
        assert args.csv_path == str(csv_file)
        assert args.keywords == str(kw_file)
        assert args.output == "results.csv"

    def test_db_mode(self, tmp_path):
        kw_file = tmp_path / "kw.txt"
        kw_file.write_text("test\n")

        args = keyword_search.parse_args([
            "-s", "myserver",
            "-d", "mydb",
            "-t", "mytable",
            "-a", "windows",
            "-k", str(kw_file),
        ])
        assert args.server == "myserver"
        assert args.database == "mydb"
        assert args.table == "mytable"
        assert args.auth == "windows"

    def test_db_mode_defaults(self, tmp_path):
        kw_file = tmp_path / "kw.txt"
        kw_file.write_text("test\n")

        args = keyword_search.parse_args([
            "-s", "srv", "-d", "db", "-t", "tbl", "-a", "windows",
            "-k", str(kw_file),
        ])
        assert args.port == 1433
        assert args.driver == "ODBC Driver 17 for SQL Server"
        assert args.output == "results.csv"

    def test_missing_required_args(self, tmp_path):
        kw_file = tmp_path / "kw.txt"
        kw_file.write_text("test\n")

        with pytest.raises(SystemExit):
            keyword_search.parse_args(["-k", str(kw_file)])

    def test_mutual_exclusivity(self, tmp_path):
        kw_file = tmp_path / "kw.txt"
        kw_file.write_text("test\n")
        csv_file = tmp_path / "data.csv"
        csv_file.write_text("a\n1\n")

        with pytest.raises(SystemExit):
            keyword_search.parse_args([
                "--csv", str(csv_file),
                "-s", "srv", "-d", "db", "-t", "tbl", "-a", "sql",
                "-u", "user", "-p", "pass",
                "-k", str(kw_file),
            ])

    def test_sql_auth_requires_credentials(self, tmp_path):
        kw_file = tmp_path / "kw.txt"
        kw_file.write_text("test\n")

        with pytest.raises(SystemExit):
            keyword_search.parse_args([
                "-s", "srv", "-d", "db", "-t", "tbl", "-a", "sql",
                "-k", str(kw_file),
            ])

    def test_azure_interactive_requires_username(self, tmp_path):
        kw_file = tmp_path / "kw.txt"
        kw_file.write_text("test\n")

        with pytest.raises(SystemExit):
            keyword_search.parse_args([
                "-s", "srv", "-d", "db", "-t", "tbl", "-a", "azure-interactive",
                "-k", str(kw_file),
            ])

    def test_missing_db_args(self, tmp_path):
        kw_file = tmp_path / "kw.txt"
        kw_file.write_text("test\n")

        with pytest.raises(SystemExit):
            keyword_search.parse_args([
                "-s", "srv", "-d", "db",
                "-k", str(kw_file),
            ])

    def test_keyword_file_not_found(self):
        with pytest.raises(SystemExit):
            keyword_search.parse_args([
                "--csv", "data.csv",
                "-k", "/nonexistent/keywords.txt",
            ])


# ---------- load_keywords ----------

class TestLoadKeywords:

    def test_basic(self, tmp_path):
        kw_file = tmp_path / "kw.txt"
        kw_file.write_text("apple\nbanana\ncherry\n")
        result = keyword_search.load_keywords(str(kw_file))
        assert result == ["apple", "banana", "cherry"]

    def test_whitespace_stripping(self, tmp_path):
        kw_file = tmp_path / "kw.txt"
        kw_file.write_text("  apple  \n\tbanana\t\n")
        result = keyword_search.load_keywords(str(kw_file))
        assert result == ["apple", "banana"]

    def test_blank_lines_removed(self, tmp_path):
        kw_file = tmp_path / "kw.txt"
        kw_file.write_text("apple\n\n\nbanana\n\n")
        result = keyword_search.load_keywords(str(kw_file))
        assert result == ["apple", "banana"]

    def test_deduplication_case_insensitive(self, tmp_path):
        kw_file = tmp_path / "kw.txt"
        kw_file.write_text("Apple\napple\nAPPLE\nBanana\n")
        result = keyword_search.load_keywords(str(kw_file))
        assert result == ["Apple", "Banana"]

    def test_empty_file(self, tmp_path):
        kw_file = tmp_path / "kw.txt"
        kw_file.write_text("")
        result = keyword_search.load_keywords(str(kw_file))
        assert result == []

    def test_bom_handling(self, tmp_path):
        kw_file = tmp_path / "kw.txt"
        kw_file.write_bytes(b"\xef\xbb\xbfapple\nbanana\n")
        result = keyword_search.load_keywords(str(kw_file))
        assert result == ["apple", "banana"]


# ---------- build_connection_string ----------

class TestBuildConnectionString:

    def _make_args(self, **kwargs):
        defaults = {
            "server": "myserver",
            "database": "mydb",
            "port": 1433,
            "driver": "ODBC Driver 17 for SQL Server",
            "auth": "sql",
            "username": "user",
            "password": "pass",
        }
        defaults.update(kwargs)

        class Args:
            pass

        args = Args()
        for k, v in defaults.items():
            setattr(args, k, v)
        return args

    def test_sql_auth(self):
        args = self._make_args(auth="sql")
        result = keyword_search.build_connection_string(args)
        assert "DRIVER={ODBC Driver 17 for SQL Server}" in result
        assert "SERVER=myserver,1433" in result
        assert "DATABASE=mydb" in result
        assert "UID=user" in result
        assert "PWD=pass" in result
        assert "Trusted_Connection" not in result

    def test_windows_auth(self):
        args = self._make_args(auth="windows", username=None, password=None)
        result = keyword_search.build_connection_string(args)
        assert "Trusted_Connection=yes" in result
        assert "UID" not in result

    def test_azure_password_auth(self):
        args = self._make_args(auth="azure-password")
        result = keyword_search.build_connection_string(args)
        assert "UID=user" in result
        assert "PWD=pass" in result
        assert "Authentication=ActiveDirectoryPassword" in result

    def test_azure_interactive_auth(self):
        args = self._make_args(auth="azure-interactive", password=None)
        result = keyword_search.build_connection_string(args)
        assert "UID=user" in result
        assert "Authentication=ActiveDirectoryInteractive" in result
        assert "PWD" not in result

    def test_custom_port(self):
        args = self._make_args(port=5000)
        result = keyword_search.build_connection_string(args)
        assert "SERVER=myserver,5000" in result

    def test_driver_already_in_braces(self):
        args = self._make_args(driver="{ODBC Driver 18 for SQL Server}")
        result = keyword_search.build_connection_string(args)
        assert "DRIVER={ODBC Driver 18 for SQL Server}" in result
        assert "{{" not in result


# ---------- get_table_columns ----------

class TestGetTableColumns:

    def test_simple_table(self):
        cursor = MagicMock()
        cursor.fetchall.return_value = [("col1",), ("col2",), ("col3",)]

        result = keyword_search.get_table_columns(cursor, "MyTable")

        assert result == ["col1", "col2", "col3"]
        cursor.execute.assert_called_once()
        call_args = cursor.execute.call_args
        assert "TABLE_NAME = ?" in call_args[0][0]
        assert call_args[0][1] == ("MyTable",)

    def test_schema_qualified(self):
        cursor = MagicMock()
        cursor.fetchall.return_value = [("id",), ("name",)]

        result = keyword_search.get_table_columns(cursor, "dbo.MyTable")

        assert result == ["id", "name"]
        call_args = cursor.execute.call_args
        assert "TABLE_SCHEMA = ?" in call_args[0][0]
        assert call_args[0][1] == ("dbo", "MyTable")

    def test_table_not_found(self):
        cursor = MagicMock()
        cursor.fetchall.return_value = []

        with pytest.raises(ValueError, match="Table not found"):
            keyword_search.get_table_columns(cursor, "NoSuchTable")


# ---------- _quote_identifier ----------

class TestQuoteIdentifier:

    def test_simple(self):
        assert keyword_search._quote_identifier("MyTable") == "[MyTable]"

    def test_with_bracket(self):
        assert keyword_search._quote_identifier("My]Table") == "[My]]Table]"

    def test_schema_qualified(self):
        assert keyword_search._quote_identifier("dbo.MyTable") == "[dbo].[MyTable]"

    def test_schema_with_brackets(self):
        # Splits on first '.': schema="my]", table="schema.my]table"
        assert keyword_search._quote_identifier("my].schema.my]table") == "[my]]].[schema.my]]table]"


# ---------- search_csv ----------

class TestSearchCsv:

    def test_basic_match(self, tmp_path):
        csv_file = tmp_path / "data.csv"
        csv_file.write_text("name,city\nAlice,New York\nBob,Boston\n")
        results = keyword_search.search_csv(str(csv_file), ["Alice"])
        assert ("name", "Alice") in results

    def test_case_insensitive(self, tmp_path):
        csv_file = tmp_path / "data.csv"
        csv_file.write_text("name,city\nAlice,New York\n")
        results = keyword_search.search_csv(str(csv_file), ["alice"])
        assert ("name", "alice") in results

    def test_substring_match(self, tmp_path):
        csv_file = tmp_path / "data.csv"
        csv_file.write_text("name,city\nAlice,New York\n")
        results = keyword_search.search_csv(str(csv_file), ["York"])
        assert ("city", "York") in results

    def test_no_match(self, tmp_path):
        csv_file = tmp_path / "data.csv"
        csv_file.write_text("name,city\nAlice,New York\n")
        results = keyword_search.search_csv(str(csv_file), ["Chicago"])
        assert results == []

    def test_empty_csv(self, tmp_path):
        csv_file = tmp_path / "data.csv"
        csv_file.write_text("")
        results = keyword_search.search_csv(str(csv_file), ["test"])
        assert results == []

    def test_multiple_keywords_multiple_columns(self, tmp_path):
        csv_file = tmp_path / "data.csv"
        csv_file.write_text("name,city,state\nAlice,New York,NY\nBob,Boston,MA\n")
        results = keyword_search.search_csv(str(csv_file), ["Alice", "Boston", "MA"])
        assert ("name", "Alice") in results
        assert ("city", "Boston") in results
        assert ("state", "MA") in results

    def test_bom_csv(self, tmp_path):
        csv_file = tmp_path / "data.csv"
        csv_file.write_bytes(b"\xef\xbb\xbfname,city\nAlice,Boston\n")
        results = keyword_search.search_csv(str(csv_file), ["Alice"])
        assert ("name", "Alice") in results


# ---------- write_results ----------

class TestWriteResults:

    def test_basic_output(self, tmp_path):
        output = tmp_path / "out.csv"
        results = [("name", "Alice"), ("city", "Boston")]
        keyword_search.write_results(results, str(output))

        with open(output, newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            rows = list(reader)

        assert rows[0] == ["column_name", "keyword"]
        assert rows[1] == ["name", "Alice"]
        assert rows[2] == ["city", "Boston"]

    def test_empty_results(self, tmp_path):
        output = tmp_path / "out.csv"
        keyword_search.write_results([], str(output))

        with open(output, newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            rows = list(reader)

        assert len(rows) == 1
        assert rows[0] == ["column_name", "keyword"]


# ---------- search_database ----------

class TestSearchDatabase:

    def test_search_creates_temp_table_and_queries_columns(self):
        cursor = MagicMock()
        # fetchall returns matches for first column only
        cursor.fetchall.side_effect = [
            [("apple",)],  # col1 matches "apple"
            [],             # col2 no matches
        ]

        results = keyword_search.search_database(
            cursor, "MyTable", ["col1", "col2"], ["apple", "banana"]
        )

        # Verify temp table creation
        create_call = cursor.execute.call_args_list[0]
        assert "#Keywords" in create_call[0][0]

        # Verify executemany for keyword insertion
        cursor.executemany.assert_called_once()
        insert_args = cursor.executemany.call_args
        assert "INSERT INTO #Keywords" in insert_args[0][0]
        assert len(insert_args[0][1]) == 2

        # Verify per-column queries
        col1_query = cursor.execute.call_args_list[1][0][0]
        assert "[col1]" in col1_query
        assert "[MyTable]" in col1_query

        col2_query = cursor.execute.call_args_list[2][0][0]
        assert "[col2]" in col2_query

        # Verify cleanup
        cleanup_call = cursor.execute.call_args_list[3][0][0]
        assert "DROP TABLE" in cleanup_call
        assert "#Keywords" in cleanup_call

        assert results == [("col1", "apple")]

    def test_search_with_large_keyword_list(self):
        cursor = MagicMock()
        cursor.fetchall.return_value = []

        keywords = [f"keyword_{i}" for i in range(1200)]
        keyword_search.search_database(cursor, "T", ["c1"], keywords)

        # Should have 3 batches: 500, 500, 200
        assert cursor.executemany.call_count == 3

    def test_search_cleanup_on_error(self):
        cursor = MagicMock()
        cursor.fetchall.side_effect = Exception("DB error")

        with pytest.raises(Exception, match="DB error"):
            keyword_search.search_database(
                cursor, "T", ["c1"], ["kw"]
            )

        # Cleanup should still happen
        last_call = cursor.execute.call_args_list[-1][0][0]
        assert "DROP TABLE" in last_call


# ---------- main ----------

class TestMain:

    def test_csv_mode_integration(self, tmp_path):
        kw_file = tmp_path / "keywords.txt"
        kw_file.write_text("Alice\nBoston\n")

        csv_file = tmp_path / "data.csv"
        csv_file.write_text("name,city\nAlice,New York\nBob,Boston\n")

        output = tmp_path / "results.csv"

        result = keyword_search.main([
            "--csv", str(csv_file),
            "-k", str(kw_file),
            "-o", str(output),
        ])

        assert result == 0
        assert output.exists()

        with open(output, newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            rows = list(reader)

        assert rows[0] == ["column_name", "keyword"]
        matches = {(r[0], r[1]) for r in rows[1:]}
        assert ("name", "Alice") in matches
        assert ("city", "Boston") in matches

    def test_empty_keywords_error(self, tmp_path):
        kw_file = tmp_path / "keywords.txt"
        kw_file.write_text("\n\n\n")

        csv_file = tmp_path / "data.csv"
        csv_file.write_text("name\nAlice\n")

        result = keyword_search.main([
            "--csv", str(csv_file),
            "-k", str(kw_file),
        ])

        assert result == 1

    def test_missing_args_returns_error(self):
        result = keyword_search.main([])
        assert result != 0

    @patch("keyword_search.connect_to_database")
    def test_db_mode_integration(self, mock_connect, tmp_path):
        kw_file = tmp_path / "keywords.txt"
        kw_file.write_text("test_kw\n")
        output = tmp_path / "results.csv"

        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor

        # get_table_columns
        mock_cursor.fetchall.side_effect = [
            [("col1",), ("col2",)],  # columns
            [("test_kw",)],           # col1 matches
            [],                       # col2 no match
        ]

        result = keyword_search.main([
            "-s", "srv", "-d", "db", "-t", "tbl", "-a", "windows",
            "-k", str(kw_file),
            "-o", str(output),
        ])

        assert result == 0
        assert output.exists()
        mock_connect.assert_called_once()
        mock_conn.close.assert_called_once()
