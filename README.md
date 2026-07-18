# Security AI Assistant — Pydantic AI + ReAct (vertical slice)

The first vertical slice of `Security_AI_Assistant_Product_Spec.md`: one Pydantic AI
agent that investigates security scanner reports. Same lab shape as
`single-agent-lab/` and `chat-assistant/`, plus the one thing both of those skip —
**multi-turn conversation memory** (spec capability #10).

## What it does

Ask questions about a corpus of ingested scanner findings (Gitleaks / Trivy /
Nessus, in `data/`). The agent decides which tools to use, chains them, and
returns a typed, grounded answer — or abstains when nothing supports one.

### The ReAct pattern here

Pydantic AI's `Agent` runs the ReAct loop internally: Thought → tool call →
Observation → repeat → typed final output. We don't hand-roll a loop; `trace.py`
reconstructs it from `result.all_messages()` so you can *see* it.

### Tools

| Tool | Kind | Purpose |
|------|------|---------|
| `rag_search` | internal retrieval | find findings across `data/` (lightweight keyword scoring; swap for ChromaDB later) |
| `count_critical`, `average_cvss`, `extract_cves` | deterministic compute | exact counts/averages/CVE extraction over the corpus |
| `calculate_risk` | deterministic compute | CVSS + KEV + exposure → prioritization score |
| `cve_lookup` | external HTTP | enrich a CVE from **NIST NVD** (live, keyless), incl. CISA KEV status |
| `suggest_remediation` | local knowledge | vetted fix playbook by finding category |

The grounding rule (the transferable lesson): the model may choose *which*
findings/CVEs to investigate, but must never fabricate CVSS scores, KEV status,
counts, or remediation — those only come from tool results. Enforced by typed
tool returns + an `@agent.output_validator`.

Output is a union `[SecurityAnswer, NeedMoreInfo]` — succeed-or-abstain.

## Setup

```bash
cd security-assistant
pip install -r requirements.txt
cp .env.example .env         # then set OPENAI_API_KEY (or switch AGENT_MODEL)
```

## Run

Single query (one independent turn):

```bash
python app.py "Which repos have exposed secrets, and how risky is the worst CVE?"
```

Interactive, **multi-turn** (follow-ups remember context; `/clear` resets):

```bash
python app.py
You: Show critical vulnerabilities
You: Now just the ones in payments-api
```

Eval (each case = one independent single turn):

```bash
python eval/run_eval.py
```

## Layout

```
agent.py       Agent + tools + guardrails (the whole agent, one file)
schemas.py     typed contracts (Finding, CVEIntel, RiskScore, SecurityAnswer, ...)
trace.py       run() → ReAct steps; multi-turn (threads message_history)
app.py         multi-turn CLI + single-query mode
tools/         rag_search, analytics, cve_lookup, remediation, corpus loader
data/          sample scanner reports (the "ingested" corpus)
eval/          cases.json + run_eval.py (output-type + tool-recall metrics)
```

## Out of scope (later milestones)

FastAPI endpoints, real ChromaDB + embeddings, PDF/XML/CSV parsing, PDF report
generation, and a web UI. The agent core here is a drop-in for those wrappers —
e.g. `rag_search`/`corpus.py` is the seam where ChromaDB replaces the keyword scorer.
```
