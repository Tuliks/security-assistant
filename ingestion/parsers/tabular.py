"""Tabular parsers: CSV, Excel, and HTML — the bulk of real scanner exports.

All three are row-and-column, so pandas reads them uniformly. Everything is read
as strings (dtype=str) with blanks as "" — the mapper decides what's a number, a
date, or a CVE id, because that depends on which scanner produced the column.
"""

from __future__ import annotations

import pandas as pd


def _frame_to_rows(df: "pd.DataFrame") -> list[dict]:
    """A DataFrame -> list of {column: str} dicts, blanks as ''. Columns trimmed."""
    df = df.where(pd.notna(df), "")           # NaN -> ""
    df.columns = [str(c).strip() for c in df.columns]
    rows = df.astype(str).to_dict(orient="records")
    # astype(str) turns "" into "" but also real NaN that slipped through into 'nan'
    return [{k: ("" if v == "nan" else v.strip()) for k, v in row.items()} for row in rows]


def parse_csv(path: str) -> list[dict]:
    return _frame_to_rows(pd.read_csv(path, dtype=str, keep_default_na=False))


def parse_excel(path: str) -> list[dict]:
    """First sheet only. Multi-sheet workbooks are a per-scanner concern for later."""
    return _frame_to_rows(pd.read_excel(path, dtype=str, sheet_name=0))


def parse_html(path: str) -> list[dict]:
    """First table in the document. read_html finds every <table>; scanner HTML
    reports lead with the findings table, so [0] is the right one here."""
    tables = pd.read_html(path)
    if not tables:
        return []
    return _frame_to_rows(tables[0])
