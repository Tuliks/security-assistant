"""PDF parser — extract the findings table from a PDF scanner report.

Many tools (Nessus, Qualys, vendor pen-test reports) hand you a PDF. pdfplumber
pulls ruled tables off each page; we take the first row of each table as its
header and turn the rest into row dicts, concatenating across pages. Like the
tabular parsers, values come out as strings — the mapper decides their meaning.

PDFs are the messiest real format (a "table" may be visual, not ruled). This
handles the common ruled-table export; anything more exotic is a per-report
concern, not a reason to block the common case.
"""

from __future__ import annotations

import pdfplumber


def _clean(cell) -> str:
    return "" if cell is None else str(cell).replace("\n", " ").strip()


def parse_pdf(path: str) -> list[dict]:
    rows: list[dict] = []
    with pdfplumber.open(path) as pdf:
        header: list[str] | None = None
        for page in pdf.pages:
            for table in page.extract_tables() or []:
                if not table:
                    continue
                # A table's first row is its header. Tables continuing onto the
                # next page often repeat no header, so we carry the last one.
                start = 0
                if header is None or _looks_like_header(table[0]):
                    header = [_clean(c) for c in table[0]]
                    start = 1
                for raw in table[start:]:
                    cells = [_clean(c) for c in raw]
                    if not any(cells):
                        continue
                    rows.append({header[i] if i < len(header) else f"col{i}": cells[i]
                                 for i in range(len(cells))})
    return rows


def _looks_like_header(row) -> bool:
    """A header row has non-empty, non-numeric labels — used to detect repeats."""
    cells = [_clean(c) for c in row]
    non_empty = [c for c in cells if c]
    if not non_empty:
        return False
    return all(not c.replace(".", "").isdigit() for c in non_empty)
