"""Run the agent and turn its message history into a ReAct trace.

Same idea as single-agent-lab/trace.py — walk `result.all_messages()` and label
the parts to make the loop visible:
  • Thought      — the model's reasoning about what to do next
  • Action       — the tool call it decided on (name + arguments)
  • Observation  — the real result that feeds the next Thought
  • Final        — the validated, typed output

The one addition for this lab is MULTI-TURN: `run()` accepts a `message_history`
and returns the full message list so the caller can thread it into the next turn.
Pass message_history=None for an independent single turn (eval / single-query).
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from agent import LIMITS, agent
from schemas import NeedMoreInfo

# Guardrail / loop-limit exceptions we degrade gracefully instead of crashing on.
try:
    from pydantic_ai import UsageLimitExceeded
except Exception:  # pragma: no cover - import path varies by version
    from pydantic_ai.usage import UsageLimitExceeded  # type: ignore
try:
    from pydantic_ai.exceptions import UnexpectedModelBehavior
except Exception:  # pragma: no cover
    UnexpectedModelBehavior = ()  # type: ignore

GUARDRAIL_ERRORS = tuple(e for e in (UsageLimitExceeded, UnexpectedModelBehavior) if isinstance(e, type))


@dataclass
class Step:
    kind: str  # thought | action | observation | retry | final | error
    title: str
    body: str


def _args_str(part) -> str:
    """ToolCallPart.args may be a dict or a JSON string across versions."""
    if hasattr(part, "args_as_json_str"):
        try:
            return part.args_as_json_str()
        except Exception:
            pass
    args = getattr(part, "args", None)
    if isinstance(args, (dict, list)):
        return json.dumps(args)
    return str(args)


def run(query: str, message_history: list | None = None) -> tuple[list[Step], object, list[str], list, list]:
    """Execute one agent turn.

    Args:
        query: The user's message for this turn.
        message_history: Prior turns' messages (from a previous run's last element)
            to give the agent memory; None for an independent single turn.

    Returns (trace steps, final output object, ordered tool names called this turn,
    raw messages as JSON-able Python, full message history to feed the next turn).
    """
    try:
        result = agent.run_sync(query, message_history=message_history, usage_limits=LIMITS)
    except GUARDRAIL_ERRORS as e:
        # A guardrail (UsageLimits) or an exhausted retry budget fired — the
        # guardrail working. Degrade to an abstention instead of crashing.
        out = NeedMoreInfo(
            question="Could you narrow the question — a specific asset, severity, or CVE?",
            reason=f"I stopped to avoid looping ({type(e).__name__}).",
        )
        return (
            [Step("retry", "Guardrail stopped the run", str(e)), Step("final", "Final answer", repr(out))],
            out,
            [],
            [],
            message_history or [],
        )

    steps: list[Step] = []
    tool_sequence: list[str] = []

    # Only walk THIS turn's new messages for the trace, so prior turns aren't
    # re-printed; the full history is returned separately for threading.
    new_messages = result.new_messages() if message_history else result.all_messages()
    for message in new_messages:
        for part in getattr(message, "parts", []):
            name = type(part).__name__
            if name in ("TextPart", "ThinkingPart"):
                body = (getattr(part, "content", "") or "").strip()
                if body:
                    steps.append(Step("thought", "Thought", body))
            elif name == "ToolCallPart":
                # Pydantic AI emits the structured output as a synthetic
                # `final_result_<Type>` tool call — that's the answer, not a
                # real tool. Skip it here; the Final row below already shows it.
                if part.tool_name.startswith("final_result"):
                    continue
                steps.append(Step("action", "Action", f"{part.tool_name}({_args_str(part)})"))
                tool_sequence.append(part.tool_name)
            elif name == "ToolReturnPart":
                if part.tool_name.startswith("final_result"):
                    continue
                content = str(part.content)
                if len(content) > 500:
                    content = content[:500] + "…"
                steps.append(Step("observation", "Observation", f"{part.tool_name} → {content}"))
            elif name == "RetryPromptPart":
                body = getattr(part, "content", part)
                steps.append(Step("retry", "Retry (validation failed)", str(body)))

    output = getattr(result, "output", None)
    if output is None:
        output = getattr(result, "data", None)
    steps.append(Step("final", "Final answer", repr(output)))

    try:
        raw_messages = json.loads(result.all_messages_json())
    except Exception:
        raw_messages = []

    return steps, output, tool_sequence, raw_messages, result.all_messages()


if __name__ == "__main__":
    import sys

    q = " ".join(sys.argv[1:]) or "How many critical findings are there, and which repos have exposed secrets?"
    trace, output, seq, _, _ = run(q)
    for s in trace:
        print(f"\n[{s.title}]\n{s.body}")
    print("\nTOOL SEQUENCE:", " -> ".join(seq) or "(none)")
