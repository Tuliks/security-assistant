"""Evaluate the agent.

A workflow's tool order is fixed in code, so it's trivially "correct." An agent
*chooses* its tools at runtime — so whether it took the right path is a real,
measurable thing. Each case runs as an INDEPENDENT single turn (no history), so
the eval scores the agent, not the conversation.

Ships:
  • output_type_correct — did it return SecurityAnswer vs NeedMoreInfo as expected?
  • tool_recall          — fraction of expected tools the agent actually called.

Run:  python eval/run_eval.py
"""

from __future__ import annotations

import json
import os
import sys

# Allow "python eval/run_eval.py" from the repo root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from trace import run  # noqa: E402

CASES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cases.json")


def tool_recall(actual: list[str], expected: list[str]) -> float | None:
    """Fraction of expected tools that were called. None when nothing is expected.

    For abstention cases (expected == []) recall is undefined — we instead expect
    zero tool calls, which is checked via `no_tools_ok` below.
    """
    if not expected:
        return None
    called = set(actual)
    return sum(1 for t in expected if t in called) / len(expected)


def main() -> None:
    with open(CASES) as f:
        cases = json.load(f)

    rows = []
    for c in cases:
        try:
            _, output, seq, _, _ = run(c["query"])  # single turn, no history
            got_type = type(output).__name__
        except Exception as e:
            rows.append({"id": c["id"], "error": f"{type(e).__name__}: {e}"})
            continue

        expected_tools = c.get("expected_tools", [])
        rows.append(
            {
                "id": c["id"],
                "type_ok": got_type == c["expected_output"],
                "recall": tool_recall(seq, expected_tools),
                "no_tools_ok": (len(seq) == 0) if not expected_tools else None,
                "got_type": got_type,
                "seq": " -> ".join(seq) or "(none)",
            }
        )

    print("\n=== Per-case ===")
    for r in rows:
        if "error" in r:
            print(f"  {r['id']:<22} ERROR: {r['error']}")
            continue
        recall = "-" if r["recall"] is None else f"{r['recall']:.2f}"
        extra = "" if r["no_tools_ok"] is None else f" no_tools={'yes' if r['no_tools_ok'] else 'NO'}"
        print(
            f"  {r['id']:<22} type={'ok' if r['type_ok'] else 'MISS'} "
            f"({r['got_type']:<14}) tool_recall={recall}{extra}\n"
            f"                         calls: {r['seq']}"
        )

    scored = [r for r in rows if "error" not in r]
    if scored:
        type_acc = sum(r["type_ok"] for r in scored) / len(scored)
        recalls = [r["recall"] for r in scored if r["recall"] is not None]
        recall_acc = (sum(recalls) / len(recalls)) if recalls else float("nan")
        print("\n=== Aggregate ===")
        print(f"  output_type_accuracy   {type_acc:.2f}")
        print(f"  mean_tool_recall       {recall_acc:.2f}")


if __name__ == "__main__":
    main()
