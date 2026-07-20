"""Load the ingested corpus as typed Findings — the single source of truth.

Everything Finding-based (rag_search's eval index, the analytics tools, the asset
graph) reads the corpus through here, so there's one seam. That corpus is now the
ONE produced by the ingestion pipeline: `manifest.csv` -> parse each report (CSV /
Excel / HTML / PDF / the lab's JSON) -> map to RecordMetadata -> project to Finding.

The original `data/*.json` reports are just rows in the manifest (mapper=lab_json)
now, so the legacy findings and the real scanner exports live in one corpus — no
separate legacy island. `search_reports` retrieves over the same corpus (via the
persistent store), so retrieval, counting, and correlation all agree.
"""

from __future__ import annotations

from schemas import Finding
from ingestion.manifest import load_manifest
from ingestion.mappers import map_report
from ingestion.parsers import parse


def load_records():
    """Every ingested record (RecordMetadata) across all manifest reports.

    Malformed reports/rows are skipped rather than crashing a query — a real
    corpus is messy and one bad file shouldn't sink retrieval.
    """
    records = []
    for env in load_manifest():
        try:
            rows = parse(env.abs_path)
            records.extend(map_report(rows, env))
        except Exception:
            continue
    return records


def load_findings(products: set[str] | None = None) -> list[Finding]:
    """The corpus as Findings. Optionally restrict to certain products.

    `products` is a scoping hook for evals that want a controlled subset (e.g. the
    original lab corpus under product 'Acme') without pulling in every product.
    """
    records = load_records()
    if products is not None:
        records = [m for m in records if m.product_name in products]
    return [m.to_finding() for m in records]
