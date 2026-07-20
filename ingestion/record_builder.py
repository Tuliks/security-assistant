"""Record builder — RecordMetadata -> the {id, text, metadata} vector record.

This is the shape a security finding takes inside the vector DB (the record
template): a stable `id`, a `text` blob that gets embedded, and a scalar
`metadata` dict used for filtering. One finding = one record.

Two production details handled here:
- `id` is a deterministic hash of the finding's identity, so re-ingesting the
  same report UPSERTS instead of duplicating (idempotent ingestion).
- Chroma metadata must be scalar, so `cve_ids` (a list on RecordMetadata, the
  source of truth) is flattened to a comma-joined string on the way in.
"""

from __future__ import annotations

import hashlib

from schemas import RecordMetadata

# The metadata fields written to the store, in record order. `cve_ids` is
# intentionally excluded here and re-added as a flattened string below;
# `description` lives only in the embedding text, never in metadata.
_META_FIELDS = (
    "product_name", "release_version", "scanner", "scan_category",
    "scan_date", "scan_label", "report_file",
    "component_name", "component_version", "component_type",
    "finding_id", "severity", "cvss_score", "status",
    "title", "category", "location",
)


def record_id(m: RecordMetadata) -> str:
    """Stable id from the finding's identity — same finding -> same id (idempotent).

    Keyed on the things that make a finding unique within the corpus: product,
    scanner, source file, the finding id, and the exact component version it was
    seen on. A re-scan on a NEW date reuses the id (it's the same finding, its
    status/scan_date just update); a different version is a different record.
    """
    key = "|".join([
        m.product_name, m.scanner, m.report_file,
        m.finding_id, m.component_name, m.component_version,
    ])
    return hashlib.sha1(key.encode("utf-8")).hexdigest()[:24]


def build_text(m: RecordMetadata) -> str:
    """The embedding text — the human-readable rendering of the finding.

    Mirrors the record template: a labeled block the embedder turns into a
    vector, so semantic search hits on product, component, and description alike.
    """
    lines = [
        f"Product: {m.product_name}",
        f"Release: {m.release_version}",
        f"Scanner: {m.scanner} ({m.scan_category})",
        f"Component: {m.component_name}",
        f"Version: {m.component_version}",
        f"Finding: {m.finding_id}",
        f"Severity: {m.severity}",
        f"CVSS: {'' if m.cvss_score is None else m.cvss_score}",
        f"CVEs: {', '.join(m.cve_ids)}",
        f"Status: {m.status}",
    ]
    if m.description:
        lines.append(f"Description: {m.description}")
    return "\n".join(lines)


def build_metadata(m: RecordMetadata) -> dict:
    """Scalar metadata dict for the store (Chroma `where` filters operate on this).

    All values are str / float / None. `cve_ids` is flattened to a comma-joined
    string; `cve_ids_count` is added so 'has any CVE' is a cheap numeric filter.
    """
    meta = {f: getattr(m, f) for f in _META_FIELDS}
    meta["cve_ids"] = ", ".join(m.cve_ids)
    meta["cve_ids_count"] = len(m.cve_ids)
    return {k: v for k, v in meta.items() if v is not None}


def build_record(m: RecordMetadata) -> dict:
    """RecordMetadata -> {id, text, metadata} — one vector-DB record."""
    return {"id": record_id(m), "text": build_text(m), "metadata": build_metadata(m)}
