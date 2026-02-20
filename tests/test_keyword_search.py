"""Tests for keyword_search.py."""

import csv
import os
import re
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


# ---------- classify_keywords ----------

class TestClassifyKeywords:

    def test_plain_keywords(self):
        result = keyword_search.classify_keywords(["hello", "SSN", "Confidential"])
        assert result == [("hello", False), ("SSN", False), ("Confidential", False)]

    def test_backslash_d(self):
        result = keyword_search.classify_keywords([r"\d{3}-\d{2}-\d{4}"])
        assert result == [(r"\d{3}-\d{2}-\d{4}", True)]

    def test_backslash_w(self):
        result = keyword_search.classify_keywords([r"\w+@\w+"])
        assert result == [(r"\w+@\w+", True)]

    def test_backslash_s(self):
        result = keyword_search.classify_keywords([r"hello\sworld"])
        assert result == [(r"hello\sworld", True)]

    def test_backslash_b(self):
        result = keyword_search.classify_keywords([r"\bword\b"])
        assert result == [(r"\bword\b", True)]

    def test_uppercase_variants(self):
        for seq in [r"\D+", r"\W+", r"\S+", r"\B"]:
            result = keyword_search.classify_keywords([seq])
            assert result[0][1] is True, f"{seq} should be detected as regex"

    def test_character_class(self):
        result = keyword_search.classify_keywords(["[a-zA-Z]"])
        assert result == [("[a-zA-Z]", True)]

    def test_quantifier_braces(self):
        result = keyword_search.classify_keywords([r"x{3}"])
        assert result == [(r"x{3}", True)]

    def test_quantifier_brace_range(self):
        result = keyword_search.classify_keywords([r"x{2,4}"])
        assert result == [(r"x{2,4}", True)]

    def test_anchor_caret(self):
        result = keyword_search.classify_keywords(["^Start"])
        assert result == [("^Start", True)]

    def test_anchor_dollar(self):
        result = keyword_search.classify_keywords(["end$"])
        assert result == [("end$", True)]

    def test_plain_percent_no_false_positive(self):
        result = keyword_search.classify_keywords(["100%"])
        assert result == [("100%", False)]

    def test_plain_cpp_no_false_positive(self):
        result = keyword_search.classify_keywords(["C++"])
        assert result == [("C++", False)]

    def test_plain_mr_smith_no_false_positive(self):
        result = keyword_search.classify_keywords(["Mr. Smith"])
        assert result == [("Mr. Smith", False)]

    def test_invalid_regex_falls_back_to_literal(self, capsys):
        # \d triggers detection, unclosed paren makes it invalid regex
        result = keyword_search.classify_keywords([r"\d("])
        assert result == [(r"\d(", False)]
        captured = capsys.readouterr()
        assert "Warning" in captured.out
        assert "treating as literal" in captured.out

    def test_mixed_keywords(self):
        keywords = ["Confidential", r"\d{3}-\d{2}-\d{4}", "SSN", "[A-Z]{2}"]
        result = keyword_search.classify_keywords(keywords)
        assert result == [
            ("Confidential", False),
            (r"\d{3}-\d{2}-\d{4}", True),
            ("SSN", False),
            ("[A-Z]{2}", True),
        ]


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


# ---------- discover_regex_function ----------

class TestDiscoverRegexFunction:

    def test_finds_known_function(self):
        cursor = MagicMock()
        # First call: find candidates
        cursor.fetchall.side_effect = [
            [("dbo", "RegexMatch", 12345)],  # candidates
            [
                ("", "bit", True),           # return param
                ("@input", "nvarchar", False),  # input 1
                ("@pattern", "nvarchar", False),  # input 2
            ],
        ]

        result = keyword_search.discover_regex_function(cursor)
        assert result == "dbo.RegexMatch"

    def test_no_candidates(self):
        cursor = MagicMock()
        cursor.fetchall.return_value = []

        result = keyword_search.discover_regex_function(cursor)
        assert result is None

    def test_rejects_wrong_signature_no_bit_return(self):
        cursor = MagicMock()
        cursor.fetchall.side_effect = [
            [("dbo", "RegexMatch", 12345)],
            [
                ("", "int", True),              # wrong return type
                ("@input", "nvarchar", False),
                ("@pattern", "nvarchar", False),
            ],
        ]

        result = keyword_search.discover_regex_function(cursor)
        assert result is None

    def test_rejects_wrong_signature_too_few_string_params(self):
        cursor = MagicMock()
        cursor.fetchall.side_effect = [
            [("dbo", "RegexMatch", 12345)],
            [
                ("", "bit", True),
                ("@input", "nvarchar", False),
                ("@flags", "int", False),       # not a string param
            ],
        ]

        result = keyword_search.discover_regex_function(cursor)
        assert result is None

    def test_picks_first_valid_from_multiple_candidates(self):
        cursor = MagicMock()
        cursor.fetchall.side_effect = [
            [
                ("dbo", "RegexMatch", 111),
                ("util", "fn_RegexMatch", 222),
            ],
            # First candidate: wrong signature
            [
                ("", "int", True),
                ("@input", "nvarchar", False),
                ("@pattern", "nvarchar", False),
            ],
            # Second candidate: valid
            [
                ("", "bit", True),
                ("@input", "nvarchar", False),
                ("@pattern", "varchar", False),
            ],
        ]

        result = keyword_search.discover_regex_function(cursor)
        assert result == "util.fn_RegexMatch"


# ---------- search_csv ----------

class TestSearchCsv:

    def test_basic_match(self, tmp_path):
        csv_file = tmp_path / "data.csv"
        csv_file.write_text("name,city\nAlice,New York\nBob,Boston\n")
        results = keyword_search.search_csv(str(csv_file), [("Alice", False)])
        assert ("name", "Alice") in results

    def test_case_insensitive(self, tmp_path):
        csv_file = tmp_path / "data.csv"
        csv_file.write_text("name,city\nAlice,New York\n")
        results = keyword_search.search_csv(str(csv_file), [("alice", False)])
        assert ("name", "alice") in results

    def test_substring_match(self, tmp_path):
        csv_file = tmp_path / "data.csv"
        csv_file.write_text("name,city\nAlice,New York\n")
        results = keyword_search.search_csv(str(csv_file), [("York", False)])
        assert ("city", "York") in results

    def test_no_match(self, tmp_path):
        csv_file = tmp_path / "data.csv"
        csv_file.write_text("name,city\nAlice,New York\n")
        results = keyword_search.search_csv(str(csv_file), [("Chicago", False)])
        assert results == []

    def test_empty_csv(self, tmp_path):
        csv_file = tmp_path / "data.csv"
        csv_file.write_text("")
        results = keyword_search.search_csv(str(csv_file), [("test", False)])
        assert results == []

    def test_multiple_keywords_multiple_columns(self, tmp_path):
        csv_file = tmp_path / "data.csv"
        csv_file.write_text("name,city,state\nAlice,New York,NY\nBob,Boston,MA\n")
        classified = [("Alice", False), ("Boston", False), ("MA", False)]
        results = keyword_search.search_csv(str(csv_file), classified)
        assert ("name", "Alice") in results
        assert ("city", "Boston") in results
        assert ("state", "MA") in results

    def test_bom_csv(self, tmp_path):
        csv_file = tmp_path / "data.csv"
        csv_file.write_bytes(b"\xef\xbb\xbfname,city\nAlice,Boston\n")
        results = keyword_search.search_csv(str(csv_file), [("Alice", False)])
        assert ("name", "Alice") in results

    def test_regex_match(self, tmp_path):
        csv_file = tmp_path / "data.csv"
        csv_file.write_text("id,ssn\n1,123-45-6789\n2,N/A\n")
        results = keyword_search.search_csv(
            str(csv_file), [(r"\d{3}-\d{2}-\d{4}", True)]
        )
        assert ("ssn", r"\d{3}-\d{2}-\d{4}") in results
        assert len(results) == 1

    def test_regex_case_insensitive(self, tmp_path):
        csv_file = tmp_path / "data.csv"
        csv_file.write_text("code,value\nABC,xyz\n")
        results = keyword_search.search_csv(
            str(csv_file), [("[a-z]{3}", True)]
        )
        assert ("code", "[a-z]{3}") in results
        assert ("value", "[a-z]{3}") in results

    def test_regex_no_match(self, tmp_path):
        csv_file = tmp_path / "data.csv"
        csv_file.write_text("name,city\nAlice,Boston\n")
        results = keyword_search.search_csv(
            str(csv_file), [(r"\d{3}-\d{2}-\d{4}", True)]
        )
        assert results == []

    def test_mixed_plain_and_regex(self, tmp_path):
        csv_file = tmp_path / "data.csv"
        csv_file.write_text("name,ssn\nAlice,123-45-6789\nBob,N/A\n")
        classified = [("Alice", False), (r"\d{3}-\d{2}-\d{4}", True)]
        results = keyword_search.search_csv(str(csv_file), classified)
        assert ("name", "Alice") in results
        assert ("ssn", r"\d{3}-\d{2}-\d{4}") in results


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

        classified = [("apple", False), ("banana", False)]
        results = keyword_search.search_database(
            cursor, "MyTable", ["col1", "col2"], classified
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

        classified = [(f"keyword_{i}", False) for i in range(1200)]
        keyword_search.search_database(cursor, "T", ["c1"], classified)

        # Should have 3 batches: 500, 500, 200
        assert cursor.executemany.call_count == 3

    def test_search_cleanup_on_error(self):
        cursor = MagicMock()
        cursor.fetchall.side_effect = Exception("DB error")

        classified = [("kw", False)]
        with pytest.raises(Exception, match="DB error"):
            keyword_search.search_database(
                cursor, "T", ["c1"], classified
            )

        # Cleanup should still happen
        last_call = cursor.execute.call_args_list[-1][0][0]
        assert "DROP TABLE" in last_call

    def test_regex_with_clr_function(self):
        cursor = MagicMock()
        # col1 LIKE query (plain) -> no match
        # col1 CLR query (regex) -> match found
        cursor.fetchall.side_effect = [
            [],  # col1 plain LIKE: no matches
        ]
        cursor.fetchone.side_effect = [
            (1,),  # col1 regex CLR: match
        ]

        classified = [("apple", False), (r"\d{3}", True)]
        results = keyword_search.search_database(
            cursor, "T", ["col1"], classified, regex_fn="dbo.RegexMatch"
        )

        assert ("col1", r"\d{3}") in results
        # Verify CLR function was used in query
        clr_calls = [
            c for c in cursor.execute.call_args_list
            if "RegexMatch" in str(c)
        ]
        assert len(clr_calls) == 1

    def test_regex_client_side_fallback(self):
        cursor = MagicMock()
        # col1 LIKE query (plain) -> no match
        # col1 distinct values for client-side regex
        cursor.fetchall.side_effect = [
            [],                          # col1 plain LIKE: no matches
            [("123-45-6789",), ("N/A",)],  # col1 distinct values
        ]

        classified = [("apple", False), (r"\d{3}-\d{2}-\d{4}", True)]
        results = keyword_search.search_database(
            cursor, "T", ["col1"], classified, regex_fn=None
        )

        assert ("col1", r"\d{3}-\d{2}-\d{4}") in results

    def test_regex_client_side_no_match(self):
        cursor = MagicMock()
        cursor.fetchall.side_effect = [
            [],                    # col1 plain LIKE: no matches
            [("hello",), ("world",)],  # col1 distinct values
        ]

        classified = [("apple", False), (r"\d{3}", True)]
        results = keyword_search.search_database(
            cursor, "T", ["col1"], classified, regex_fn=None
        )

        assert results == []

    def test_regex_only_no_temp_table(self):
        cursor = MagicMock()
        cursor.fetchall.side_effect = [
            [("abc123",)],  # col1 distinct values
        ]

        classified = [(r"\d+", True)]
        results = keyword_search.search_database(
            cursor, "T", ["col1"], classified, regex_fn=None
        )

        assert ("col1", r"\d+") in results
        # Verify no temp table was created (no #Keywords in any call)
        for c in cursor.execute.call_args_list:
            assert "#Keywords" not in str(c) or "DROP" in str(c)

    def test_plain_only_no_distinct_query(self):
        cursor = MagicMock()
        cursor.fetchall.side_effect = [
            [("apple",)],  # col1 matches
        ]

        classified = [("apple", False)]
        results = keyword_search.search_database(
            cursor, "T", ["col1"], classified, regex_fn=None
        )

        assert results == [("col1", "apple")]
        # Verify no DISTINCT query was issued
        for c in cursor.execute.call_args_list:
            assert "DISTINCT CAST" not in str(c)


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

    def test_csv_mode_with_mixed_keywords(self, tmp_path):
        kw_file = tmp_path / "keywords.txt"
        kw_file.write_text("Alice\n\\d{3}-\\d{2}-\\d{4}\n")

        csv_file = tmp_path / "data.csv"
        csv_file.write_text("name,ssn\nAlice,123-45-6789\nBob,N/A\n")

        output = tmp_path / "results.csv"

        result = keyword_search.main([
            "--csv", str(csv_file),
            "-k", str(kw_file),
            "-o", str(output),
        ])

        assert result == 0
        with open(output, newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            rows = list(reader)

        matches = {(r[0], r[1]) for r in rows[1:]}
        assert ("name", "Alice") in matches
        assert ("ssn", r"\d{3}-\d{2}-\d{4}") in matches

    @patch("keyword_search.connect_to_database")
    def test_db_mode_integration(self, mock_connect, tmp_path):
        kw_file = tmp_path / "keywords.txt"
        kw_file.write_text("test_kw\n")
        output = tmp_path / "results.csv"

        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor

        # get_table_columns, then LIKE queries per column
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
