# LLM Learnings

A running log of explanations and insights about how the LLM interacts with this project's tools and design. Appended to over time.

---

## How `data/*.json` is fed to the agent in `agent.py`

**The `data/*.json` files are never passed into `agent.py` directly** — the agent reaches them only by calling tools. The flow:

```
agent.py                    tools/rag_search.py      tools/analytics.py
  agent = LLM + tools   ──►   rag_search()      ──┐
  (registers tools)          (token-overlap      │
                              scoring)            ├──►  tools/corpus.py
                            count_critical()     │      load_findings()
                            average_cvss()   ────┘        │
                                                          ▼
                                                    data/*.json
                                             (trivy, gitleaks, nessus)
```

**Step by step:**

1. **`agent.py`** wires tools onto the agent but has zero knowledge of `data/`. At `agent.py:78-84` it registers `rag_search`, `count_critical`, `average_cvss`, etc. via `agent.tool_plain(...)`. The data only enters when the LLM *decides* to call one of these during the ReAct loop.

2. **`tools/corpus.py`** is the single loader. `load_findings()` globs `data/*.json`, reads each report, and for every entry in its `findings` array builds a typed `Finding` (tagging it with `scanner`). Malformed rows/files are skipped, not fatal. `DATA_DIR` is resolved relative to the file, pointing at the `data/` folder.

3. **`tools/rag_search.py`** calls `load_findings()`, optionally filters by severity, then scores each finding by simple token overlap with the query and returns the top matches as `Finding` objects. This is the "what findings exist" path.

4. **Analytics tools** (`count_critical`, `average_cvss`, `extract_cves`, `calculate_risk`) also read through `load_findings()` — same corpus, one source of truth.

**Key design point:** the JSON is deliberately *not* dumped into the system prompt or context. The model can't see findings until it retrieves them, which enforces the grounding rule at `agent.py:36-40` — it must cite tool results, so it can't fabricate findings from its weights. `corpus.py` is the seam where you'd later swap the flat JSON for a real ChromaDB vector store without touching the tools or the agent.

---

## rag_search.py — the retrieval tool and its interaction with the LLM

### What the tool actually is

It's the **"R" in RAG** (Retrieval-Augmented Generation) — the retrieval step. It's a plain Python function, but because it's registered as a tool on the agent, the LLM can *choose* to call it, read the results, and reason over them.

Mechanically it does three things:
1. **Validates the query** (`tools/rag_search.py:40-47`) — bad input raises `ModelRetry`, which sends a correction *back to the model* so it can fix its own call rather than the program crashing.
2. **Loads + filters the corpus** (`tools/rag_search.py:49-52`) — reads every `data/*.json` scanner report via `load_findings()` (`tools/corpus.py:19`), optionally filtered by severity.
3. **Scores by token overlap** (`tools/rag_search.py:54-69`) — a cheap stand-in for semantic search: count shared words between the query and each finding's `title/description/asset/category/cve`, normalize, sort, return the top `limit`.

### Why the LLM needs it — the load-bearing idea

The docstring says it directly: *"it must retrieve before it can cite, so it can't fabricate findings from its weights."* (`tools/rag_search.py:8-9`)

The model has no idea what's in *your* scanner reports — that data isn't in its training weights. So there are two guardrails working together:

- **Grounding:** To put a `Finding` into its `SecurityAnswer.findings_cited`, the model has to have gotten that `Finding` object from a tool. `rag_search` is the only way to obtain them. It can't hallucinate `GL-001` — it has to retrieve it.
- **Graceful abstention:** When nothing matches, the tool returns `[]` — *not* an error (`tools/rag_search.py:63-66`). That empty list is a signal the model reads and, per the schema, responds to by returning `NeedMoreInfo` instead of inventing an answer.

So `rag_search` is what turns "confidently make something up" into "look it up, then answer or admit you can't."

### Use case 1 — Topic discovery

**User:** *"Do we have any exposed secrets?"*

- **Thinking:** I have no findings in hand. "Exposed secrets" is a topic in the reports, not general knowledge — I must retrieve first.
- **Action:** `rag_search(query="exposed secrets", severity=None, limit=5)`
- **Result:** returns e.g. `[Finding(id="GL-001", scanner="gitleaks", severity="critical", title="AWS key in commit history", asset="payments-api", category="exposed_secret", ...)]`
- **How it helps:** the model now has *real, typed* findings. It can cite `GL-001` in `findings_cited`, name the affected asset (`payments-api`), and — because the finding has a `category` — chain into `suggest_remediation("exposed_secret")`. The retrieval seeds every downstream step.

### Use case 2 — Scoped triage + abstention

**User:** *"What are the critical issues in the billing-service?"*

- **Thinking:** Two constraints — severity `critical` and asset `billing-service`. Let me filter hard.
- **Action:** `rag_search(query="billing-service", severity="critical", limit=10)`
- **Result:** `[]` — nothing critical for that asset.
- **How it helps:** the empty list isn't a dead end, it's information. Instead of fabricating a critical bug to look useful, the model returns `NeedMoreInfo(reason="No critical findings for billing-service in the ingested reports", question="Want me to broaden to high/medium, or check a different asset?")`. The tool's design is what *permits* honesty here.

### Mini demo — full thinking → action → answer trace

**User:** *"Are we exposed to Log4Shell?"*

```
THINK   Log4Shell = CVE-2021-44228. Is it in OUR corpus? I don't know — retrieve.
ACT     rag_search(query="log4j log4shell CVE-2021-44228")
OBS     [Finding(id="TR-042", scanner="trivy", severity="critical",
                 asset="auth-service", cve="CVE-2021-44228",
                 category="vulnerable_dependency")]
THINK   Found it. But CVSS/KEV status aren't mine to invent — enrich via the un-fakeable tool.
ACT     cve_lookup("CVE-2021-44228")           → CVEIntel(cvss_v3=10.0, kev_listed=True, ...)
ACT     calculate_risk(cvss=10.0, kev=True, ...) → RiskScore(score=9.8, band="critical")
ACT     suggest_remediation("vulnerable_dependency") → RemediationPlaybook(steps=[...])
ANSWER  SecurityAnswer(
          message="Yes — auth-service is exposed via TR-042 (Log4Shell). KEV-listed,
                   risk 9.8/critical. Upgrade log4j-core to >=2.17.1 ...",
          findings_cited=[TR-042], cves=["CVE-2021-44228"],
          tools_used=["rag_search","cve_lookup","calculate_risk","suggest_remediation"])
```

The pattern: **`rag_search` is always the first hop.** It converts a vague natural-language question into concrete, typed findings — and everything after it (CVE enrichment, risk scoring, remediation) is chained off the assets, categories, and CVE ids that retrieval surfaced. Without it, the model has nothing real to stand on; with it, every claim traces back to a tool result.
