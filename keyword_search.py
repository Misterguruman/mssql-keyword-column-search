"""Keyword Column Search Tool.

Identifies which columns in SQL Server tables or CSV files contain
specific keywords. Given a list of keywords and a data source, reports
which columns contain which keywords.
"""

import argparse
import csv
import os
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


def search_database(cursor, table, columns, keywords):
    """Search database columns for keyword matches.

    Creates a temp table of keywords, then checks each column for matches
    using LIKE with case-insensitive collation.

    Args:
        cursor: pyodbc cursor.
        table: Table name (optionally schema-qualified).
        columns: List of column names to search.
        keywords: List of keyword strings.

    Returns:
        List of (column_name, keyword) tuples for each match found.
    """
    results = []
    quoted_table = _quote_identifier(table)

    # Step 1: Create temp table
    cursor.execute(
        "CREATE TABLE #Keywords ("
        "keyword NVARCHAR(500), "
        "pattern NVARCHAR(510)"
        ")"
    )

    # Step 2: Batch-insert keywords
    rows = [(kw, escape_like_pattern(kw)) for kw in keywords]
    batch_size = 500
    for i in range(0, len(rows), batch_size):
        batch = rows[i:i + batch_size]
        cursor.executemany(
            "INSERT INTO #Keywords (keyword, pattern) VALUES (?, ?)",
            batch,
        )

    # Step 3: Search each column
    try:
        for idx, col in enumerate(columns, 1):
            quoted_col = _quote_identifier(col)
            print(f"  Searching column {idx}/{len(columns)}: {col}")

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
    finally:
        # Step 4: Cleanup
        cursor.execute("DROP TABLE IF EXISTS #Keywords")

    return results


def search_csv(csv_path, keywords):
    """Search CSV file columns for keyword matches.

    For each (column, keyword) pair, checks if any cell contains
    the keyword as a case-insensitive substring. Short-circuits
    on first match per pair.

    Args:
        csv_path: Path to the CSV file.
        keywords: List of keyword strings.

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

    lower_keywords = [(kw, kw.lower()) for kw in keywords]
    total = len(columns)

    for idx, col in enumerate(columns, 1):
        print(f"  Searching column {idx}/{total}: {col}")
        for kw, kw_lower in lower_keywords:
            for row in rows:
                cell = row.get(col, "")
                if cell is not None and kw_lower in cell.lower():
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

    # Load keywords
    keywords = load_keywords(args.keywords)
    if not keywords:
        print("Error: keyword file is empty or contains only blank lines.")
        return 1
    print(f"Loaded {len(keywords)} keyword(s).")

    try:
        if args.csv_path:
            # CSV mode
            print(f"Searching CSV file: {args.csv_path}")
            results = search_csv(args.csv_path, keywords)
        else:
            # Database mode
            conn_str = build_connection_string(args)
            print(f"Connecting to {args.server}/{args.database}...")
            conn = connect_to_database(conn_str)
            print("Connected.")
            try:
                cursor = conn.cursor()
                print(f"Discovering columns for table: {args.table}")
                columns = get_table_columns(cursor, args.table)
                print(f"Found {len(columns)} column(s).")

                print("Searching for keywords...")
                results = search_database(cursor, args.table, columns, keywords)
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
