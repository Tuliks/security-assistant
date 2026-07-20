"""CLI for the security assistant.

Two modes (like chat-assistant/app.py):
  • Interactive  (no args)  — a MULTI-TURN chat. Message history is threaded
    across turns, so follow-ups work ("...now just the ones in payments-api").
    Type /clear to reset memory, exit/quit to leave.
  • Single query (with args) — one independent turn, no memory (for scripting).

Each turn renders the ReAct loop (Thought / Action / Observation) then the typed
answer, via trace.run().
"""

from __future__ import annotations

import sys

from dotenv import load_dotenv

load_dotenv()

from schemas import NeedMoreInfo, SecurityAnswer
from trace import run

COLORS = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "blue": "\033[34m", "green": "\033[32m", "yellow": "\033[33m",
    "red": "\033[31m", "cyan": "\033[36m", "magenta": "\033[35m",
}

ICONS = {
    "thought": "💭", "action": "🔧", "observation": "📡",
    "retry": "↻", "final": "✅", "error": "❌",
}


def format_trace_step(step) -> str:
    icon = ICONS.get(step.kind, "•")
    color_map = {
        "thought": "yellow", "action": "blue", "observation": "green",
        "retry": "yellow", "final": "cyan", "error": "red",
    }
    color = COLORS.get(color_map.get(step.kind, "reset"), "")
    title = f"{color}{COLORS['bold']}{icon} {step.title}{COLORS['reset']}"
    body = f"{COLORS['dim']}{step.body}{COLORS['reset']}"
    return f"{title}\n{body}\n"


def format_output(output) -> str:
    if isinstance(output, SecurityAnswer):
        result = f"{COLORS['green']}{COLORS['bold']}✅ Analyst:{COLORS['reset']}\n{output.message}\n"
        if output.findings_cited:
            result += f"\n{COLORS['dim']}Findings cited:{COLORS['reset']}\n"
            for f in output.findings_cited:
                result += f"  • [{f.severity.upper()}] {f.id} {f.title} ({f.asset})\n"
        if output.cves:
            result += f"\n{COLORS['dim']}CVEs: {', '.join(output.cves)}{COLORS['reset']}\n"
        if output.summary_data:
            result += f"{COLORS['dim']}Summary: {output.summary_data}{COLORS['reset']}\n"
        if output.tools_used:
            result += f"{COLORS['dim']}🔧 Tools used: {', '.join(output.tools_used)}{COLORS['reset']}\n"
        return result
    if isinstance(output, NeedMoreInfo):
        result = f"{COLORS['yellow']}{COLORS['bold']}❓ Need more info:{COLORS['reset']}\n{output.reason}\n"
        result += f"\n{COLORS['dim']}Question: {output.question}{COLORS['reset']}\n"
        return result
    return str(output)


def print_banner():
    banner = f"""
{COLORS['cyan']}{COLORS['bold']}╔══════════════════════════════════════════════════════════════╗
║         Security AI Assistant — investigate scanner reports    ║
╚══════════════════════════════════════════════════════════════╝{COLORS['reset']}

{COLORS['dim']}An agent that decides which tools to use:
  🔎  search_reports    — hybrid + filtered search over the ingested corpus
  🕸️  correlate_asset   — every finding on one asset / riskiest_assets
  📊  analytics         — count_critical / average_cvss / extract_cves / calculate_risk
  🌐  cve_lookup        — enrich a CVE from NIST NVD (live)
  🛠️  suggest_remediation — playbook fixes by finding category

Multi-turn: follow-ups remember the conversation. /clear resets, exit to quit.{COLORS['reset']}
"""
    print(banner)


def _render(steps, output, tool_sequence):
    for step in steps[:-1]:  # all except final
        print(format_trace_step(step))
    print(f"{COLORS['dim']}{'─' * 60}{COLORS['reset']}\n")
    print(format_output(output))
    if tool_sequence:
        print(f"{COLORS['dim']}Tool sequence: {' → '.join(tool_sequence)}{COLORS['reset']}")


def run_chat():
    """Interactive, multi-turn: history is threaded across turns."""
    print_banner()
    history: list | None = None

    while True:
        try:
            query = input(f"\n{COLORS['bold']}You:{COLORS['reset']} ").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n\n{COLORS['dim']}Goodbye!{COLORS['reset']}\n")
            sys.exit(0)

        if query.lower() in ("exit", "quit", "q", "bye"):
            print(f"\n{COLORS['dim']}Goodbye!{COLORS['reset']}\n")
            break
        if query.lower() in ("/clear", "/reset"):
            history = None
            print(f"{COLORS['dim']}Conversation memory cleared.{COLORS['reset']}")
            continue
        if not query:
            continue

        print(f"\n{COLORS['dim']}{'─' * 60}{COLORS['reset']}")
        print(f"{COLORS['magenta']}{COLORS['bold']}🤖 Agent Trace (ReAct Loop):{COLORS['reset']}\n")
        try:
            steps, output, tool_sequence, _, history = run(query, message_history=history)
            _render(steps, output, tool_sequence)
        except Exception as e:
            print(f"{COLORS['red']}{COLORS['bold']}❌ Error:{COLORS['reset']} {COLORS['red']}{e}{COLORS['reset']}")


def run_single_query(query: str):
    """One independent turn, no memory (for scripting/testing)."""
    print(f"\n{COLORS['bold']}Query:{COLORS['reset']} {query}\n")
    print(f"{COLORS['dim']}{'─' * 60}{COLORS['reset']}\n")
    try:
        steps, output, tool_sequence, _, _ = run(query)
        _render(steps, output, tool_sequence)
    except Exception as e:
        print(f"{COLORS['red']}{COLORS['bold']}❌ Error:{COLORS['reset']} {COLORS['red']}{e}{COLORS['reset']}\n")
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        run_single_query(" ".join(sys.argv[1:]))
    else:
        run_chat()
