"""JSON parser — the format the original lab shipped with.

Accepts either the lab's `{"scanner": ..., "findings": [...]}` envelope or a bare
top-level list of finding objects. Returns the raw finding dicts unchanged; the
mapper normalizes their keys.
"""

from __future__ import annotations

import json


def parse_json(path: str) -> list[dict]:
    with open(path) as f:
        doc = json.load(f)
    if isinstance(doc, list):
        return doc
    if isinstance(doc, dict):
        rows = doc.get("findings", [])
        return rows if isinstance(rows, list) else []
    return []
