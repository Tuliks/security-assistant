"""Evaluate cross-report correlation — graph vs hybrid retrieval.

retrieval_eval.py showed hybrid beats keyword at finding *individual* findings.
This one shows the different job graph correlation does: recovering EVERY finding
on an asset, across scanners that spell the asset three different ways.

For each golden case we compare, on the same asset question:
  • hybrid  — rag_search(query, limit=5) -> ids   (per-finding search, top-k)
  • graph   — correlate_asset(asset)     -> ids   (all findings on the node)

We report BOTH recall (did we get the full set?) and precision (was the result
free of other-asset noise?). On a corpus this small, hybrid's top-k recalls the
set fine — the honest difference shows up in precision: a per-finding search pulls
in wrong-asset lookalikes (e.g. NS-002 on edge-lb bleeding into a payments-api
query), whereas the graph returns exactly the asset's node. Two more graph-only
wins a flat id-list can't show at all: it never truncates at `limit`, and it emits
the correlated *structure* (scanners, max_cvss, compound_risk) — the compound
secret+vuln pattern that motivates the whole milestone.

Run:  python eval/graph_eval.py
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.asset_graph import correlate_asset  # noqa: E402
from tools.rag_search import rag_search  # noqa: E402

CASES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "graph_cases.json")
K = 5


def recall(retrieved_ids: list[str], expected: list[str]) -> float:
    got = set(retrieved_ids)
    return sum(1 for e in expected if e in got) / len(expected)


def precision(retrieved_ids: list[str], expected: list[str]) -> float:
    if not retrieved_ids:
        return 0.0
    exp = set(expected)
    return sum(1 for r in retrieved_ids if r in exp) / len(retrieved_ids)


def main() -> None:
    with open(CASES) as f:
        cases = json.load(f)

    agg = {"hybrid": {"recall": [], "prec": []}, "graph": {"recall": [], "prec": []}}

    print("\n=== Per-case: recall / precision of the full correlated set ===")
    for c in cases:
        runs = {
            "hybrid": [f.id for f in rag_search(c["query"], limit=K)],
            "graph": [f.id for f in correlate_asset(c["asset"]).findings],
        }
        print(f"\n  {c['id']}  (expected {c['expected_ids']})")
        for name, ids in runs.items():
            r = recall(ids, c["expected_ids"])
            p = precision(ids, c["expected_ids"])
            agg[name]["recall"].append(r)
            agg[name]["prec"].append(p)
            print(f"    {name:<7} recall={r:.2f} precision={p:.2f}  got={ids}")

    print("\n=== Aggregate (mean over %d cases) ===" % len(cases))
    print(f"  {'':<8} recall   precision")
    for name in ("hybrid", "graph"):
        rec = sum(agg[name]["recall"]) / len(cases)
        prc = sum(agg[name]["prec"]) / len(cases)
        print(f"  {name:<8} {rec:.3f}    {prc:.3f}")


if __name__ == "__main__":
    main()
