"""Load the ingested scanner reports from data/ into typed Findings.

This is the lightweight stand-in for the spec's ingestion + ChromaDB pipeline.
Both rag_search and the analytics tools read the corpus through here, so there is
one place to swap in a real vector store later without touching the tools.
"""

from __future__ import annotations

import glob
import json
import os

from schemas import Finding

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")


def load_findings() -> list[Finding]:
    """Read every data/*.json report and flatten it to a list of Findings.

    Malformed or partial records are skipped rather than crashing the tool — a
    real corpus is messy, and one bad row shouldn't sink a query.
    """
    findings: list[Finding] = []
    for path in sorted(glob.glob(os.path.join(DATA_DIR, "*.json"))):
        try:
            with open(path) as f:
                report = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        scanner = report.get("scanner", os.path.splitext(os.path.basename(path))[0])
        for raw in report.get("findings", []):
            row = {"scanner": scanner, **raw}
            try:
                findings.append(Finding(**row))
            except Exception:
                # Skip rows that don't fit the Finding schema.
                continue
    return findings
