"""Ingestion + filtered-retrieval eval — proves the production pipeline works.

Runs the whole thing against the sample corpus (3 products/scanners, 3 file
formats — CSV, Excel, HTML) and checks the two things that matter:

  1. Records have the right SHAPE — every metadata field from the record
     template is present and correctly typed, across all three formats.
  2. Metadata FILTERS scope retrieval — product / scanner / severity($in) /
     compound($and) filters return exactly the records they should.

Run:  python eval/ingest_eval.py     (exits non-zero if any check fails)
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ingest import ingest
from ingestion.store import ReportStore

_REQUIRED_META = [
    "product_name", "release_version", "scanner", "scan_category", "scan_date",
    "scan_label", "report_file", "component_name", "component_version",
    "component_type", "finding_id", "severity", "status", "cve_ids",
]

_passed = 0
_failed = 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global _passed, _failed
    mark = "✓" if ok else "✗"
    print(f"  {mark} {name}" + (f" — {detail}" if detail and not ok else ""))
    if ok:
        _passed += 1
    else:
        _failed += 1


def _all(store, filters):
    """Every record matching a filter (enumerated, not ranked)."""
    return [{"metadata": m} for m in store.records(filters)]


def main() -> int:
    print("Ingesting sample corpus (reset)…")
    total = ingest(reset=True)
    store = ReportStore()

    print("\nRecord count")
    # New reports: CSV 5 + Excel 5 + HTML 4 + PDF 3 = 17 (info rows dropped).
    # Legacy lab JSON (mapper=lab_json): Gitleaks 3 + Trivy 4 + Nessus 3 = 10.
    # Unified corpus = 27.
    check("27 records ingested (17 new + 10 legacy lab_json)", total == 27, f"got {total}")
    check("store holds 27", store.count == 27, f"got {store.count}")

    print("\nRecord shape (all metadata fields present, across CSV/Excel/HTML/PDF)")
    everything = _all(store, None)
    missing = {
        f for hit in everything for f in _REQUIRED_META if f not in hit["metadata"]
    }
    check("every record has all template metadata fields", not missing, f"missing: {missing}")
    types_ok = all(
        isinstance(h["metadata"].get("cvss_score", 0.0), (int, float))
        for h in everything if "cvss_score" in h["metadata"]
    )
    check("cvss_score is numeric where present", types_ok)

    print("\nMetadata filters scope retrieval")
    ivan = _all(store, {"product_name": "Ivan"})
    check("filter product=Ivan -> only Ivan (13: Twistlock 5 + Trivy 5 + Nessus PDF 3)",
          len(ivan) == 13 and all(h["metadata"]["product_name"] == "Ivan" for h in ivan),
          f"got {len(ivan)}")

    nessus = _all(store, {"scanner": "Nessus"})
    check("filter scanner=Nessus -> all Nessus (10: HTML 4 + PDF 3 + legacy 3)",
          len(nessus) == 10 and all(h["metadata"]["scanner"] == "Nessus" for h in nessus),
          f"got {len(nessus)}")

    crit_high = _all(store, {"severity": ["critical", "high"]})
    check("filter severity $in [critical, high]",
          all(h["metadata"]["severity"] in ("critical", "high") for h in crit_high) and crit_high,
          f"got {len(crit_high)}")

    compound = _all(store, {"product_name": "Ivan", "scanner": "Trivy"})
    check("compound $and product=Ivan AND scanner=Trivy (5 records)",
          len(compound) == 5 and all(
              h["metadata"]["product_name"] == "Ivan" and h["metadata"]["scanner"] == "Trivy"
              for h in compound),
          f"got {len(compound)}")

    print("\nHybrid query + filter (scoped retrieval)")
    hits = store.hybrid_search(
        "remote code execution in logging library",
        filters={"product_name": "Ivan", "scanner": "Trivy"}, k=1,
    )
    top = hits[0]["metadata"] if hits else {}
    check("'RCE in logging library' + Ivan/Trivy -> Log4Shell (CVE-2021-44228)",
          top.get("finding_id") == "CVE-2021-44228", f"got {top.get('finding_id')}")

    print("\nUnified corpus: legacy findings reachable via the same store")
    secrets = store.hybrid_search("exposed AWS secret key committed to source", k=1)
    check("secret query surfaces a Gitleaks finding (was legacy-only)",
          bool(secrets) and secrets[0]["metadata"]["scanner"] == "Gitleaks",
          f"got {secrets[0]['metadata'] if secrets else None}")

    print(f"\n{_passed} passed, {_failed} failed")
    return 1 if _failed else 0


if __name__ == "__main__":
    sys.exit(main())
