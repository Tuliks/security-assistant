"""search_reports — the agent's one retrieval tool, over the unified corpus.

Every finding — real scanner exports (CSV/Excel/HTML/PDF) and the lab's own JSON —
is ingested into one persistent store (ingest.py). search_reports runs HYBRID
retrieval over it (BM25 + embeddings, fused with RRF — good at both exact CVE/asset
ids and fuzzy topics) and adds the record template's metadata filters: product /
scanner / severity / scan_category / status. So the agent can scope a question to
"Twistlock findings for mcp-cce in ProductB" instead of searching everything at once,
and the corpus it searches is the same one count_critical and correlate_asset see.

Returns typed RecordMetadata, so the model can cite product/component/finding_id
but can't invent them — same grounding rule as every other tool here.
"""

from __future__ import annotations

from pydantic_ai import ModelRetry

from ingestion.store import ReportStore
from schemas import RecordMetadata

_VALID_SEVERITIES = ("critical", "high", "medium", "low", "info")

# Open the persistent store eagerly, at import (main thread). Pydantic AI runs
# sync tools in a worker thread, and Chroma's native bindings can fail if the
# PersistentClient is first created OFF the main thread — so create it here, while
# agent.py is importing this module on the main thread. Failure is deferred to
# call time (a clear ModelRetry) rather than crashing import in a no-corpus setup.
try:
    _STORE: ReportStore | None = ReportStore()
except Exception:
    _STORE = None


def _store() -> ReportStore:
    global _STORE
    if _STORE is None:
        _STORE = ReportStore()
    return _STORE


def _to_record(metadata: dict) -> RecordMetadata:
    """Rebuild a RecordMetadata from a stored (scalar) metadata dict.

    Reverses record_builder.build_metadata: split the flattened cve_ids back to a
    list and drop the derived cve_ids_count.
    """
    md = dict(metadata)
    cve_ids = md.get("cve_ids", "")
    md["cve_ids"] = [c.strip() for c in cve_ids.split(",") if c.strip()] if cve_ids else []
    md.pop("cve_ids_count", None)
    return RecordMetadata(**md)


def search_reports(
    query: str,
    product: str | None = None,
    scanner: str | None = None,
    severity: str | None = None,
    scan_category: str | None = None,
    status: str | None = None,
    limit: int = 5,
) -> list[RecordMetadata]:
    """Search ingested scanner reports, optionally scoped by metadata filters.

    Use this when the question names a product, scanner, release, or scan type —
    the filters keep retrieval on-target instead of ranking across every product's
    findings. Every filter is optional; omit the ones the user didn't specify.

    Args:
        query: What to look for — a topic, component, CVE, or description.
        product: Restrict to one product, e.g. 'ProductB' (exact match).
        scanner: Restrict to one scanner, e.g. 'Trivy', 'Nessus', 'Twistlock'.
        severity: One of critical/high/medium/low/info.
        scan_category: e.g. 'CONTAINER', 'SCA', 'HOST', 'SAST', 'SECRET'.
        status: 'new' | 'recurring' | 'resolved'.
        limit: Max records to return (1-20, default 5).
    """
    if not query or not query.strip():
        raise ModelRetry("Empty query. Pass a topic, component, or CVE to search for.")
    if limit <= 0 or limit > 20:
        raise ModelRetry(f"Invalid limit: {limit}. Must be between 1 and 20.")
    if severity is not None and severity.lower() not in _VALID_SEVERITIES:
        raise ModelRetry(
            f"Invalid severity {severity!r}. Use one of: {', '.join(_VALID_SEVERITIES)}, or omit it."
        )

    store = _store()
    if store.count == 0:
        raise ModelRetry(
            "The report corpus is empty — nothing has been ingested. Run `python ingest.py` first."
        )

    filters = {
        "product_name": product,
        "scanner": scanner,
        "severity": severity.lower() if severity else None,
        "scan_category": scan_category,
        "status": status,
    }
    filters = {k: v for k, v in filters.items() if v is not None}

    hits = store.hybrid_search(query, filters=filters or None, k=limit)
    return [_to_record(h["metadata"]) for h in hits]
