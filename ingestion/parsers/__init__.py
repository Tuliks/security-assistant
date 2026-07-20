"""Format parsers — read a report file into a list of raw row dicts.

Keyed by file extension. Each parser's ONLY job is bytes -> rows using the
report's native column names; it knows nothing about our schema. Turning those
native columns into a canonical finding is the mapper's job (mappers/), so that
a Trivy CSV and a Trivy Excel share one mapper, and a CSV from any scanner shares
one parser.

Add a format by writing a `parse_<x>(path) -> list[dict]` and registering its
extension(s) in PARSERS.
"""

from __future__ import annotations

import os

from ingestion.parsers.tabular import parse_excel, parse_html, parse_csv
from ingestion.parsers.json_report import parse_json
from ingestion.parsers.pdf_report import parse_pdf

# extension (lowercase, no dot) -> parser callable
PARSERS = {
    "csv": parse_csv,
    "xlsx": parse_excel,
    "xls": parse_excel,
    "html": parse_html,
    "htm": parse_html,
    "json": parse_json,
    "pdf": parse_pdf,
}


class UnsupportedFormat(ValueError):
    """Raised when no parser is registered for a file's extension."""


def parse(path: str) -> list[dict]:
    """Dispatch on extension and return the report's rows as dicts.

    Row values are strings (empty string for blanks) — normalizing types is the
    mapper's job, once it knows which column means what.
    """
    ext = os.path.splitext(path)[1].lower().lstrip(".")
    parser = PARSERS.get(ext)
    if parser is None:
        raise UnsupportedFormat(
            f"No parser for .{ext} ({os.path.basename(path)}). "
            f"Registered: {', '.join(sorted(PARSERS))}."
        )
    return parser(path)
