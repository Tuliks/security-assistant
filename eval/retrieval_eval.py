"""Evaluate retrieval quality — hybrid vs the old keyword scorer.

The run_eval.py harness scores the *agent* (did it pick the right tools?). This
one scores *retrieval* directly, bypassing the LLM: it runs both the keyword
baseline (`_keyword_rank`) and the hybrid `rag_search` over a golden set of
query -> expected finding ids, and prints recall@k / MRR side by side. That makes
"hybrid beats keyword" a measured result, not a claim.

Metrics (keyed on finding ids, mirroring rag-chunking-lab/eval/metrics.py):
  • recall@k — fraction of the expected ids that appear in the top-k results.
  • MRR      — 1 / rank of the first expected id (1.0 = ranked first, 0.0 = miss).

Run:  python eval/retrieval_eval.py
"""

from __future__ import annotations

import json
import os
import sys

# Allow "python eval/retrieval_eval.py" from the repo root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.rag_search import _get_index, _hybrid_search, _keyword_rank, expand_query, rag_search  # noqa: E402

CASES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "retrieval_cases.json")
K = 5


def recall_at_k(retrieved_ids: list[str], expected: list[str], k: int = K) -> float:
    top = set(retrieved_ids[:k])
    return sum(1 for e in expected if e in top) / len(expected)


def reciprocal_rank(retrieved_ids: list[str], expected: list[str], k: int = K) -> float:
    expected_set = set(expected)
    for i, fid in enumerate(retrieved_ids[:k]):
        if fid in expected_set:
            return 1.0 / (i + 1)
    return 0.0


def _ids(findings) -> list[str]:
    return [f.id for f in findings]


def main() -> None:
    with open(CASES) as f:
        cases = json.load(f)

    # keyword baseline -> hybrid (no query expansion) -> hybrid + rewrite.
    # _hybrid_search is the fusion core over the query as-given; rag_search runs
    # the same core over the acronym-expanded query, so the two columns isolate
    # exactly what query rewriting adds.
    runners = {
        "keyword": lambda q: _ids(_keyword_rank(q, limit=K)),
        "hybrid": lambda q: _ids(_hybrid_search(q, None, K)),
        "hybrid+rw": lambda q: _ids(rag_search(q, limit=K)),
    }

    agg = {name: {"recall": [], "mrr": []} for name in runners}

    print("\n=== Per-case (recall@%d / MRR) ===" % K)
    for c in cases:
        line = f"  {c['id']:<22}"
        for name, run in runners.items():
            got = run(c["query"])
            r = recall_at_k(got, c["expected_ids"])
            rr = reciprocal_rank(got, c["expected_ids"])
            agg[name]["recall"].append(r)
            agg[name]["mrr"].append(rr)
            line += f"  {name}: {r:.2f}/{rr:.2f}"
        print(line)

    print("\n=== Aggregate (mean over %d cases) ===" % len(cases))
    print(f"  {'':<10} recall@{K}   MRR")
    for name in runners:
        rec = sum(agg[name]["recall"]) / len(cases)
        mrr = sum(agg[name]["mrr"]) / len(cases)
        print(f"  {name:<10} {rec:.3f}      {mrr:.3f}")

    # Why hybrid == hybrid+rw above: on this corpus the semantic arm already maps
    # 'sqli'->SQL injection, 'creds'->credentials, so the FUSED result doesn't move.
    # Query expansion is a *lexical* fix — its effect is only visible on the BM25
    # arm in isolation. Measure it there so the mechanism is a number, not a claim.
    index = _get_index()
    raw_rec = exp_rec = 0.0
    print("\n=== Lexical-only (BM25): query expansion's effect on recall ===")
    for c in cases:
        raw = index.bm25_ranking(c["query"])[:K]
        exp = index.bm25_ranking(expand_query(c["query"]))[:K]
        r = recall_at_k(raw, c["expected_ids"], K)
        e = recall_at_k(exp, c["expected_ids"], K)
        raw_rec += r
        exp_rec += e
        if e != r:
            recovered = set(exp) & set(c["expected_ids"]) - set(raw)
            print(f"  {c['id']:<22} recall {r:.2f} -> {e:.2f}   (expansion recovered {sorted(recovered)})")
    n = len(cases)
    print(f"  BM25 mean recall@{K}:  raw {raw_rec / n:.3f}  ->  expanded {exp_rec / n:.3f}")


if __name__ == "__main__":
    main()
