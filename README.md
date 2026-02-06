# Keyword Column Search Tool

Identifies which columns in SQL Server tables or CSV files contain specific keywords. Given a list of keywords and a data source (MSSQL table or CSV file), reports which columns contain which keywords.

## Setup

```bash
python -m venv venv
source venv/bin/activate    # Linux/Mac
venv\Scripts\activate       # Windows
pip install -r requirements.txt
```

### Requirements

- Python 3.8+
- `pyodbc` (for database mode) - requires an ODBC driver installed on the system
- `pytest` (for running tests)

## Usage

### CSV Mode

```bash
python keyword_search.py --csv data.csv -k keywords.txt [-o results.csv]
```

### Database Mode

```bash
python keyword_search.py -s SERVER -d DATABASE -t TABLE -a AUTH_TYPE -k keywords.txt [options]
```

#### Required Database Arguments

| Argument | Description |
|---|---|
| `-s`, `--server` | SQL Server hostname |
| `-d`, `--database` | Database name |
| `-t`, `--table` | Table name (supports `schema.table` format) |
| `-a`, `--auth` | Authentication type (see below) |
| `-k`, `--keywords` | Path to keyword file (one keyword per line) |

#### Optional Arguments

| Argument | Default | Description |
|---|---|---|
| `-o`, `--output` | `results.csv` | Output file path |
| `-u`, `--username` | None | Username (required for some auth types) |
| `-p`, `--password` | None | Password (required for some auth types) |
| `--port` | `1433` | SQL Server port |
| `--driver` | `ODBC Driver 17 for SQL Server` | ODBC driver name |

### Authentication Types

| Type | Description | Requires |
|---|---|---|
| `sql` | SQL Server authentication | `--username`, `--password` |
| `windows` | Windows integrated authentication | Nothing |
| `azure-password` | Azure AD with password | `--username`, `--password` |
| `azure-interactive` | Azure AD interactive (browser) | `--username` |

### Keyword File Format

Plain text file with one keyword per line. Blank lines are ignored. Duplicate keywords (case-insensitive) are removed. UTF-8 with or without BOM is supported.

```
Confidential
SSN
Social Security
credit card
```

## Output

Results are written to a CSV file with two columns:

```csv
column_name,keyword
employee_name,Confidential
ssn_field,SSN
notes,Social Security
```

A summary is also printed to stdout showing which columns matched and how many keywords were found per column.

## Examples

```bash
# Search a CSV file
python keyword_search.py --csv employees.csv -k sensitive_terms.txt -o matches.csv

# Search with SQL authentication
python keyword_search.py -s sqlserver01 -d HRDatabase -t dbo.Employees \
    -a sql -u sa -p MyPassword -k keywords.txt

# Search with Windows authentication
python keyword_search.py -s sqlserver01 -d HRDatabase -t Employees \
    -a windows -k keywords.txt

# Search with Azure AD interactive login
python keyword_search.py -s myserver.database.windows.net -d MyDB -t Users \
    -a azure-interactive -u user@domain.com -k keywords.txt
```

## Running Tests

```bash
pytest tests/ -v
```
