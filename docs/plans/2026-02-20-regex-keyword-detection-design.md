# Regex Keyword Auto-Detection

## Overview

Add automatic regex pattern detection to the keyword file parser. When a line in the keyword file contains regex-specific syntax, the tool treats it as a regex pattern and adjusts its search strategy accordingly. For SQL Server, it attempts server-side CLR regex matching first, falling back to client-side Python matching. For CSV mode, it uses Python's `re` module directly.

No new CLI flags. No output schema changes. The feature is transparent to the user.

## 1. Regex Auto-Detection

A new function `classify_keywords(keywords)` splits the loaded keyword list into two groups: plain keywords and regex patterns. It scans each keyword for conservative regex-specific indicators:

- Backslash sequences: `\d`, `\w`, `\s`, `\b`, `\D`, `\W`, `\S`, `\B`
- Character classes: `[` followed by `]` (e.g., `[a-zA-Z]`, `[0-9]`)
- Quantifier braces: `{` followed by digits and `}` (e.g., `{3}`, `{2,4}`)
- Anchors: `^` at start or `$` at end of the pattern

If none of these are found, the keyword is treated as a plain literal. If any are found, the keyword is validated with `re.compile()` to ensure it's actually valid regex. If compilation fails, it's treated as a plain keyword and a warning is printed.

The return value is a list of tuples: `[(keyword_text, is_regex), ...]`. This replaces the current flat list and threads through the rest of the pipeline.

Deduplication in `load_keywords` stays the same and operates on the raw text before classification. Classification happens after loading.

## 2. SQL Server - CLR Auto-Discovery

A new function `discover_regex_function(cursor)` checks whether a usable CLR regex function exists on the server. It queries `sys.objects` and `sys.parameters` for known function names:

- `RegexMatch`
- `RegExIsMatch`
- `fn_RegexMatch`
- `fn_RegExIsMatch`

The search is case-insensitive and checks across all schemas. When a match is found, it verifies the function signature has at least two string parameters (input, pattern) and returns a BIT. The function returns the fully schema-qualified name (e.g., `dbo.RegexMatch`) or `None` if nothing is found.

This discovery runs once at the start of database mode, before column searching begins. The result is cached and passed into `search_database`. A message is printed:

- `"Found server-side regex function: dbo.RegexMatch"`
- `"No server-side regex function found; regex patterns will use client-side matching"`

## 3. SQL Server - Query Execution for Regex Keywords

The `search_database` function gets a new parameter: the discovered CLR function name (or `None`). Behavior depends on keyword type:

**Plain keywords** - no change. Temp table + `LIKE '%pattern%'` approach.

**Regex keywords with CLR available** - the query uses the discovered function:

```sql
SELECT 1 FROM [MyTable]
WHERE dbo.RegexMatch(CAST([col] AS NVARCHAR(MAX)), N'\d{3}-\d{2}-\d{4}') = 1
```

These are queried individually (not via the temp table) since the CLR function takes the pattern directly.

**Regex keywords with no CLR (client-side fallback)** - pull distinct non-null values for the column:

```sql
SELECT DISTINCT CAST([col] AS NVARCHAR(MAX)) FROM [MyTable]
WHERE [col] IS NOT NULL
```

Then run `re.search(pattern, value, re.IGNORECASE)` in Python for each value. A column is a match if any value matches. The distinct values are fetched once per column and reused across all regex keywords for that column to avoid repeated queries.

The temp table approach continues to handle all plain keywords in bulk. Regex keywords are processed in a separate pass per column.

## 4. CSV Mode Changes

The `search_csv` function receives the classified keyword list instead of plain strings:

- **Plain keywords** - same as today: `kw_lower in cell.lower()` substring check.
- **Regex keywords** - use `re.search(pattern, cell, re.IGNORECASE)` instead.

Regex patterns are pre-compiled with `re.compile(pattern, re.IGNORECASE)` once before the search loop starts. If a pattern fails to compile (defensive - should not happen since validated during classification), it's skipped with a warning.

Same output, same short-circuit on first match per (column, keyword) pair.

## 5. CLI and User-Facing Changes

**No new CLI flags.** Detection is automatic.

**Console output changes:**

- After loading: `"Loaded 8 keyword(s): 5 literal, 3 regex"`
- Regex listings: `"  Regex: \d{3}-\d{2}-\d{4}"`
- Compile failure: `"  Warning: '\d{3' looks like regex but failed to compile - treating as literal"`
- CLR discovery message (database mode only)

**Keyword file format** - unchanged. Users write regex patterns directly alongside plain keywords:

```
Confidential
SSN
\d{3}-\d{2}-\d{4}
[A-Z]{2}\d{6}
credit card
```

**Output format** - unchanged. `column_name,keyword` where keyword is the raw line from the file.

## 6. Testing Strategy

New and modified tests:

- **`TestClassifyKeywords`** - each detection trigger (`\d`, `[a-z]`, `{3}`, `^`, `$`), plain text that should not trigger (`SSN`, `100%`, `C++`), invalid regex fallback to literal with warning.
- **`TestDiscoverRegexFunction`** - mock cursor returning known function names from `sys.objects`, schema-qualified return, no match returns `None`, signature validation rejects wrong parameter count.
- **`TestSearchDatabase` updates** - mixed plain+regex with CLR available, CLR `None` (client-side fallback), plain keywords still use temp table, regex keywords use CLR function or distinct-value pull.
- **`TestSearchCsv` updates** - regex keyword matching (`\d{3}` against `"ID: 123"`), mixed plain+regex, pre-compilation behavior.
- **`TestMain` updates** - integration test with keyword file containing both plain and regex keywords in CSV mode.

All existing tests continue to pass since plain-keyword-only paths are unchanged.

## Files Modified

- `keyword_search.py` - new functions (`classify_keywords`, `discover_regex_function`), modified functions (`search_database`, `search_csv`, `main`)
- `tests/test_keyword_search.py` - new test classes and updated existing test classes
- `README.md` - document regex keyword support in keyword file format section
