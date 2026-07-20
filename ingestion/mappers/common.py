"""Shared normalization helpers for scanner mappers.

Every scanner spells severity, CVSS, and CVE ids its own way. These turn the
scanner-native strings into the canonical values RecordMetadata expects, so each
mapper stays a thin column map instead of re-implementing the same cleanups.
"""

from __future__ import annotations

import re

_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Scanner severity/risk wording -> our Severity literal.
_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
    "none": "info",
    "negligible": "low",
    "unknown": "info",
}


def normalize_severity(raw: str) -> str:
    """'High' / 'Risk: High' / 'CRITICAL' -> a canonical Severity value.

    Unrecognized wording falls back to 'info' rather than crashing the row — a
    real corpus is messy and one odd severity string shouldn't drop the finding.
    """
    if not raw:
        return "info"
    token = raw.strip().lower().split(":")[-1].strip()
    return _SEVERITY.get(token, "info")


def parse_cvss(raw: str) -> float | None:
    """First float in the cell, clamped to [0, 10]. Blank/garbage -> None."""
    if not raw:
        return None
    m = re.search(r"\d+(?:\.\d+)?", str(raw))
    if not m:
        return None
    try:
        return max(0.0, min(10.0, float(m.group())))
    except ValueError:
        return None


def extract_cves(*cells: str) -> list[str]:
    """All distinct CVE ids across the given cells, upper-cased, order preserved."""
    seen: list[str] = []
    for cell in cells:
        for m in _CVE.findall(cell or ""):
            cid = m.upper()
            if cid not in seen:
                seen.append(cid)
    return seen


def first(row: dict, *names: str, default: str = "") -> str:
    """First non-empty value among candidate column names (case-insensitive).

    Scanner exports rename columns between versions ('CVSS' vs 'CVSS v3.0 Base
    Score'); listing the aliases here keeps a mapper resilient to that.
    """
    lowered = {k.lower().strip(): v for k, v in row.items()}
    for n in names:
        v = lowered.get(n.lower().strip(), "")
        if v is not None and str(v).strip():
            return str(v).strip()
    return default
