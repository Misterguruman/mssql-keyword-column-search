"""Keyword Column Search Tool.

Identifies which columns in SQL Server tables or CSV files contain
specific keywords. Given a list of keywords and a data source, reports
which columns contain which keywords.
"""

import argparse
import csv
import os
import re
import sys


def parse_args(argv=None):
    """Parse and validate command-line arguments.

    Args:
        argv: Argument list to parse. Defaults to sys.argv[1:].

    Returns:
        argparse.Namespace with validated arguments.
    """
    parser = argparse.ArgumentParser(
        description="Search database tables or CSV files for keyword matches by column."
    )

    parser.add_argument(
        "-k", "--keywords", required=True,
        help="Path to text file containing keywords (one per line)."
    )
    parser.add_argument(
        "-o", "--output", default="results.csv",
        help="Output CSV path (default: results.csv)."
    )

    # CSV mode
    parser.add_argument(
        "--csv", dest="csv_path", default=None,
        help="Path to CSV file to search."
    )

    # Database mode
    parser.add_argument("-s", "--server", default=None, help="SQL Server hostname.")
    parser.add_argument("-d", "--database", default=None, help="Database name.")
    parser.add_argument("-t", "--table", default=None, help="Table name to search.")
    parser.add_argument(
        "-a", "--auth", default=None,
        choices=["sql", "windows", "azure-password", "azure-interactive"],
        help="Authentication type."
    )
    parser.add_argument("-u", "--username", default=None, help="Username for authentication.")
    parser.add_argument("-p", "--password", default=None, help="Password for authentication.")
    parser.add_argument("--port", type=int, default=1433, help="SQL Server port (default: 1433).")
    parser.add_argument(
        "--driver", default="ODBC Driver 17 for SQL Server",
        help="ODBC driver name (default: 'ODBC Driver 17 for SQL Server')."
    )

    args = parser.parse_args(argv)

    # Mutual exclusivity validation
    csv_mode = args.csv_path is not None
    db_args = [args.server, args.database, args.table, args.auth]
    db_mode = any(a is not None for a in db_args)

    if csv_mode and db_mode:
        parser.error("Cannot use --csv with database arguments (--server, --database, --table, --auth).")

    if not csv_mode and not db_mode:
        parser.error("Must specify either --csv or database arguments (--server, --database, --table, --auth).")

    if db_mode:
        missing = []
        if args.server is None:
            missing.append("--server")
        if args.database is None:
            missing.append("--database")
        if args.table is None:
            missing.append("--table")
        if args.auth is None:
            missing.append("--auth")
        if missing:
            parser.error(f"Database mode requires: {', '.join(missing)}")

        if args.auth in ("sql", "azure-password"):
            if args.username is None or args.password is None:
                parser.error(f"Auth type '{args.auth}' requires --username and --password.")
        elif args.auth == "azure-interactive":
            if args.username is None:
                parser.error("Auth type 'azure-interactive' requires --username.")

    # Validate keyword file exists
    if not os.path.isfile(args.keywords):
        parser.error(f"Keyword file not found: {args.keywords}")

    return args


def load_keywords(filepath):
    """Read keywords from a text file.

    Opens with utf-8-sig encoding to handle BOM from Notepad.
    Strips whitespace, removes blank lines, deduplicates case-insensitively.

    Args:
        filepath: Path to text file with one keyword per line.

    Returns:
        List of unique keywords (preserving first occurrence's casing).
    """
    with open(filepath, encoding="utf-8-sig") as f:
        lines = f.readlines()

    seen = set()
    keywords = []
    for line in lines:
        kw = line.strip()
        if not kw:
            continue
        lower = kw.lower()
        if lower not in seen:
            seen.add(lower)
            keywords.append(kw)
    return keywords


_REGEX_BACKSLASH_SEQUENCES = re.compile(r"\\[dDwWsSbB]")
_REGEX_CHAR_CLASS = re.compile(r"\[.*?\]")
_REGEX_QUANTIFIER_BRACE = re.compile(r"\{\d+(?:,\d*)?\}")


def _looks_like_regex(keyword):
    """Check if a keyword contains conservative regex-specific syntax.

    Args:
        keyword: The raw keyword string.

    Returns:
        True if the keyword appears to contain regex syntax.
    """
    if _REGEX_BACKSLASH_SEQUENCES.search(keyword):
        return True
    if _REGEX_CHAR_CLASS.search(keyword):
        return True
    if _REGEX_QUANTIFIER_BRACE.search(keyword):
        return True
    if keyword.startswith("^") or keyword.endswith("$"):
        return True
    return False


def classify_keywords(keywords):
    """Classify keywords as plain literals or regex patterns.

    Scans each keyword for conservative regex indicators. If detected,
    validates with re.compile(). Falls back to literal if compilation fails.

    Args:
        keywords: List of keyword strings.

    Returns:
        List of (keyword_text, is_regex) tuples.
    """
    classified = []
    for kw in keywords:
        if _looks_like_regex(kw):
            try:
                re.compile(kw)
                classified.append((kw, True))
            except re.error:
                print(f"  Warning: '{kw}' looks like regex but failed to compile"
                      " - treating as literal")
                classified.append((kw, False))
        else:
            classified.append((kw, False))
    return classified


def escape_like_pattern(keyword, escape_char="\\"):
    """Escape special SQL LIKE pattern characters in a keyword.

    Escapes the escape character itself first, then %, _, and [.

    Args:
        keyword: The raw keyword string.
        escape_char: The LIKE ESCAPE character (default: backslash).

    Returns:
        Escaped keyword safe for use in a LIKE pattern.
    """
    result = keyword.replace(escape_char, escape_char + escape_char)
    result = result.replace("%", escape_char + "%")
    result = result.replace("_", escape_char + "_")
    result = result.replace("[", escape_char + "[")
    return result


def build_connection_string(args):
    """Build a pyodbc connection string from parsed arguments.

    Args:
        args: argparse.Namespace with server, database, port, driver,
              auth, username, and password attributes.

    Returns:
        Connection string for pyodbc.connect().
    """
    driver = args.driver
    if not driver.startswith("{"):
        driver = "{" + driver + "}"

    base = f"DRIVER={driver};SERVER={args.server},{args.port};DATABASE={args.database}"

    if args.auth == "sql":
        return f"{base};UID={args.username};PWD={args.password}"
    elif args.auth == "windows":
        return f"{base};Trusted_Connection=yes"
    elif args.auth == "azure-password":
        return f"{base};UID={args.username};PWD={args.password};Authentication=ActiveDirectoryPassword"
    elif args.auth == "azure-interactive":
        return f"{base};UID={args.username};Authentication=ActiveDirectoryInteractive"
    else:
        raise ValueError(f"Unknown auth type: {args.auth}")


def connect_to_database(connection_string):
    """Open a pyodbc connection to the database.

    Args:
        connection_string: pyodbc connection string.

    Returns:
        pyodbc.Connection object.
    """
    import pyodbc
    return pyodbc.connect(connection_string, timeout=30)


_KNOWN_REGEX_FUNCTIONS = [
    "RegexMatch",
    "RegExIsMatch",
    "fn_RegexMatch",
    "fn_RegExIsMatch",
]


def discover_regex_function(cursor):
    """Check if a usable CLR regex function exists on the server.

    Queries sys.objects for known regex function names, then verifies
    the signature has at least two string parameters and returns BIT.

    Args:
        cursor: pyodbc cursor.

    Returns:
        Schema-qualified function name (e.g. 'dbo.RegexMatch') or None.
    """
    placeholders = ",".join("?" for _ in _KNOWN_REGEX_FUNCTIONS)
    lower_names = [name.lower() for name in _KNOWN_REGEX_FUNCTIONS]

    # Find scalar functions matching known names (case-insensitive)
    cursor.execute(
        "SELECT s.name AS schema_name, o.name AS func_name, o.object_id "
        "FROM sys.objects o "
        "JOIN sys.schemas s ON o.schema_id = s.schema_id "
        "WHERE o.type IN ('FS', 'FN') "
        f"AND LOWER(o.name) IN ({placeholders})",
        lower_names,
    )
    candidates = cursor.fetchall()

    for schema_name, func_name, object_id in candidates:
        # Verify signature: at least 2 string params, returns bit
        cursor.execute(
            "SELECT p.name, t.name AS type_name, p.is_output "
            "FROM sys.parameters p "
            "JOIN sys.types t ON p.user_type_id = t.user_type_id "
            "WHERE p.object_id = ? "
            "ORDER BY p.parameter_id",
            (object_id,),
        )
        params = cursor.fetchall()

        # parameter_id 0 is the return value, rest are inputs
        return_params = [p for p in params if p[0] == "" or p[2] == True]
        input_params = [p for p in params if p[0] != "" and p[2] == False]

        # Check: return type is bit, at least 2 string input params
        string_types = {"nvarchar", "varchar", "nchar", "char", "ntext", "text"}
        has_bit_return = any(
            p[1].lower() == "bit" for p in params if p[0] == ""
        )
        string_inputs = [
            p for p in input_params if p[1].lower() in string_types
        ]

        if has_bit_return and len(string_inputs) >= 2:
            return f"{schema_name}.{func_name}"

    return None


def get_table_columns(cursor, table):
    """Discover column names for a table via INFORMATION_SCHEMA.

    Args:
        cursor: pyodbc cursor.
        table: Table name, optionally schema-qualified (e.g. 'dbo.MyTable').

    Returns:
        List of column name strings.

    Raises:
        ValueError: If the table is not found.
    """
    parts = table.split(".", 1)
    if len(parts) == 2:
        schema, table_name = parts
        cursor.execute(
            "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS "
            "WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? "
            "ORDER BY ORDINAL_POSITION",
            (schema, table_name),
        )
    else:
        table_name = parts[0]
        cursor.execute(
            "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS "
            "WHERE TABLE_NAME = ? "
            "ORDER BY ORDINAL_POSITION",
            (table_name,),
        )

    columns = [row[0] for row in cursor.fetchall()]
    if not columns:
        raise ValueError(f"Table not found or has no columns: {table}")
    return columns


def _quote_identifier(name):
    """Bracket-quote a SQL identifier.

    Handles schema-qualified names like 'dbo.MyTable' by quoting each part.
    Escapes ] as ]] within each part.

    Args:
        name: SQL identifier, optionally schema-qualified.

    Returns:
        Bracket-quoted identifier string.
    """
    parts = name.split(".", 1)
    quoted = ["[" + p.replace("]", "]]") + "]" for p in parts]
    return ".".join(quoted)


def search_database(cursor, table, columns, classified_keywords,
                    regex_fn=None):
    """Search database columns for keyword matches.

    Plain keywords use a temp table + LIKE approach. Regex keywords use
    a CLR function server-side if available, otherwise fall back to
    pulling distinct values and matching client-side with re.search().

    Args:
        cursor: pyodbc cursor.
        table: Table name (optionally schema-qualified).
        columns: List of column names to search.
        classified_keywords: List of (keyword_text, is_regex) tuples.
        regex_fn: Schema-qualified CLR regex function name, or None.

    Returns:
        List of (column_name, keyword) tuples for each match found.
    """
    results = []
    quoted_table = _quote_identifier(table)

    plain_keywords = [kw for kw, is_re in classified_keywords if not is_re]
    regex_keywords = [kw for kw, is_re in classified_keywords if is_re]

    # --- Plain keyword search via temp table + LIKE ---
    if plain_keywords:
        cursor.execute(
            "CREATE TABLE #Keywords ("
            "keyword NVARCHAR(500), "
            "pattern NVARCHAR(510)"
            ")"
        )

        rows = [(kw, escape_like_pattern(kw)) for kw in plain_keywords]
        batch_size = 500
        for i in range(0, len(rows), batch_size):
            batch = rows[i:i + batch_size]
            cursor.executemany(
                "INSERT INTO #Keywords (keyword, pattern) VALUES (?, ?)",
                batch,
            )

    try:
        for idx, col in enumerate(columns, 1):
            quoted_col = _quote_identifier(col)
            print(f"  Searching column {idx}/{len(columns)}: {col}")

            # Plain keywords via LIKE
            if plain_keywords:
                query = (
                    "SELECT DISTINCT k.keyword FROM #Keywords k "
                    "WHERE EXISTS ("
                    f"SELECT 1 FROM {quoted_table} "
                    f"WHERE CAST({quoted_col} AS NVARCHAR(MAX)) "
                    "COLLATE Latin1_General_CI_AS "
                    "LIKE N'%' + k.pattern + N'%' "
                    "COLLATE Latin1_General_CI_AS "
                    "ESCAPE N'\\'"
                    ")"
                )
                cursor.execute(query)
                for row in cursor.fetchall():
                    results.append((col, row[0]))

            # Regex keywords
            if regex_keywords and regex_fn:
                # Server-side CLR path
                quoted_fn = _quote_identifier(regex_fn)
                for pattern in regex_keywords:
                    query = (
                        f"SELECT 1 WHERE EXISTS ("
                        f"SELECT 1 FROM {quoted_table} "
                        f"WHERE {quoted_fn}("
                        f"CAST({quoted_col} AS NVARCHAR(MAX)), ?"
                        ") = 1)"
                    )
                    cursor.execute(query, (pattern,))
                    if cursor.fetchone():
                        results.append((col, pattern))

            elif regex_keywords:
                # Client-side fallback: pull distinct values once per column
                query = (
                    f"SELECT DISTINCT CAST({quoted_col} AS NVARCHAR(MAX)) "
                    f"FROM {quoted_table} "
                    f"WHERE {quoted_col} IS NOT NULL"
                )
                cursor.execute(query)
                col_values = [row[0] for row in cursor.fetchall()]

                for pattern in regex_keywords:
                    compiled = re.compile(pattern, re.IGNORECASE)
                    for val in col_values:
                        if compiled.search(val):
                            results.append((col, pattern))
                            break
    finally:
        if plain_keywords:
            cursor.execute("DROP TABLE IF EXISTS #Keywords")

    return results


def search_csv(csv_path, classified_keywords):
    """Search CSV file columns for keyword matches.

    Plain keywords use case-insensitive substring matching.
    Regex keywords use re.search() with IGNORECASE.
    Short-circuits on first match per (column, keyword) pair.

    Args:
        csv_path: Path to the CSV file.
        classified_keywords: List of (keyword_text, is_regex) tuples.

    Returns:
        List of (column_name, keyword) tuples for each match found.
    """
    results = []

    with open(csv_path, encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            return results

        columns = list(reader.fieldnames)
        rows = list(reader)

    # Pre-process keywords: plain get lowercased, regex get compiled
    prepared = []
    for kw, is_regex in classified_keywords:
        if is_regex:
            try:
                compiled = re.compile(kw, re.IGNORECASE)
                prepared.append((kw, True, compiled))
            except re.error:
                # Defensive: should not happen since classify_keywords validated
                print(f"  Warning: skipping invalid regex pattern: {kw}")
                continue
        else:
            prepared.append((kw, False, kw.lower()))

    total = len(columns)

    for idx, col in enumerate(columns, 1):
        print(f"  Searching column {idx}/{total}: {col}")
        for kw, is_regex, matcher in prepared:
            for row in rows:
                cell = row.get(col, "")
                if cell is None:
                    continue
                if is_regex:
                    if matcher.search(cell):
                        results.append((col, kw))
                        break
                else:
                    if matcher in cell.lower():
                        results.append((col, kw))
                        break

    return results


def write_results(results, output_path):
    """Write search results to a CSV file.

    Args:
        results: List of (column_name, keyword) tuples.
        output_path: Path for the output CSV file.
    """
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["column_name", "keyword"])
        for col, kw in results:
            writer.writerow([col, kw])


def main(argv=None):
    """Main orchestrator for keyword column search.

    Args:
        argv: Argument list to parse. Defaults to sys.argv[1:].

    Returns:
        0 on success, 1 on error.
    """
    try:
        args = parse_args(argv)
    except SystemExit as e:
        return e.code if e.code is not None else 1

    # Load and classify keywords
    keywords = load_keywords(args.keywords)
    if not keywords:
        print("Error: keyword file is empty or contains only blank lines.")
        return 1

    classified = classify_keywords(keywords)
    num_literal = sum(1 for _, is_re in classified if not is_re)
    num_regex = sum(1 for _, is_re in classified if is_re)
    print(f"Loaded {len(classified)} keyword(s): {num_literal} literal, {num_regex} regex")
    for kw, is_re in classified:
        if is_re:
            print(f"  Regex: {kw}")

    try:
        if args.csv_path:
            # CSV mode
            print(f"Searching CSV file: {args.csv_path}")
            results = search_csv(args.csv_path, classified)
        else:
            # Database mode
            conn_str = build_connection_string(args)
            print(f"Connecting to {args.server}/{args.database}...")
            conn = connect_to_database(conn_str)
            print("Connected.")
            try:
                cursor = conn.cursor()

                # Discover CLR regex function if we have regex keywords
                regex_fn = None
                if num_regex > 0:
                    print("Checking for server-side regex function...")
                    regex_fn = discover_regex_function(cursor)
                    if regex_fn:
                        print(f"Found server-side regex function: {regex_fn}")
                    else:
                        print("No server-side regex function found; "
                              "regex patterns will use client-side matching")

                print(f"Discovering columns for table: {args.table}")
                columns = get_table_columns(cursor, args.table)
                print(f"Found {len(columns)} column(s).")

                print("Searching for keywords...")
                results = search_database(
                    cursor, args.table, columns, classified,
                    regex_fn=regex_fn,
                )
            finally:
                conn.close()
                print("Connection closed.")

        # Write results
        write_results(results, args.output)
        print(f"\nResults written to {args.output}")

        # Print summary
        if results:
            matched_columns = {}
            for col, kw in results:
                matched_columns.setdefault(col, []).append(kw)
            print(f"\nSummary: {len(matched_columns)} column(s) with matches:")
            for col, kws in matched_columns.items():
                print(f"  {col}: {len(kws)} keyword(s) - {', '.join(kws)}")
        else:
            print("\nNo matches found.")

        return 0

    except Exception as e:
        print(f"Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
