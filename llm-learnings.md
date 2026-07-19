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

---

## Hybrid retrieval — how `rag_search` finds findings now (BM25 + semantic + RRF)

`rag_search` used to score findings by **token overlap** — how many words the query
literally shared with a finding. That misses paraphrases: *"any leaked credentials?"*
shares no words with *"AWS secret access key committed to source"*, so it returned
nothing. It replaced that with **hybrid retrieval**: two searches run in parallel and
their results are fused.

### The two searches (they're good at opposite things)

- **BM25 (lexical)** — a proper keyword ranker. Great at *exact identifiers*: a
  `CVE-2021-44228`, a `GL-001`, an asset name like `payments-api`. Bad at synonyms —
  it only knows words, not meaning. (`tools/rag_search.py`, `BM25Okapi`.)
- **Semantic (embeddings + ChromaDB)** — each finding is turned into a vector by a
  local model (`tools/embedder.py`, `all-mpnet-base-v2`); the query is turned into a
  vector too, and we find the nearest ones (`tools/vector_store.py`). Great at
  *meaning* ("leaked credentials" ≈ "exposed secret"). Fuzzier on exact ids.

Security findings need **both** — they mix exact ids (BM25's strength) with
natural-language topics (semantic's strength). That's why hybrid, not either alone.

### Fusing the two lists — Reciprocal Rank Fusion (RRF)

Each search returns findings *ranked* best-first. We can't just compare their raw
scores — BM25 scores and cosine distances live on different scales (and Chroma
reports *distance*, where lower = closer). RRF sidesteps that by using only the
**rank position**: a finding's fused score is `Σ 1/(60 + rank)` across both lists.
Appear high in either list → score well; appear high in both → win. (`_rrf` in
`tools/rag_search.py`.)

### Two things that keep it honest (and cost me a debugging round)

1. **Semantic search always returns *something*.** Ask for "weather in Paris" and it
   still hands back its 10 closest findings — all irrelevant. That would flood the
   grounding/abstention path. Fix: a **distance gate** (`_SEMANTIC_MAX_DISTANCE`) —
   only keep semantic hits closer than a measured cutoff. Off-topic query → no
   semantic candidates.
2. **BM25 matching stopwords.** "weather **in** Paris" shares "in" with many findings,
   so BM25 gave them nonzero scores. Fix: strip stopwords from the *lexical* side only
   (`_content_tokens`). This also sharpened exact-id search — `CVE-2021-44228` went
   back to ranking the right finding first.

Together: a truly off-topic query now returns `[]`, so the model abstains
(`NeedMoreInfo`) instead of being handed junk.

### Did it actually help? (measured, not asserted)

`eval/retrieval_eval.py` runs the old keyword scorer (kept as `_keyword_rank`) and the
new hybrid over a golden `query → finding ids` set:

```
             recall@5   MRR
  keyword    0.833      0.750
  hybrid     1.000      0.917
```

Hybrid ties or beats keyword on every case; the clearest win is a paraphrased SQL-injection
query the keyword scorer missed entirely (recall 0.00 → 1.00).

**The seam held:** the tool signature `rag_search(query, severity, limit) -> list[Finding]`
never changed, so `agent.py` and `schemas.py` were untouched — exactly the swap point the
README promised. `python eval/run_eval.py` still scores 1.00/1.00.

---

## Milestone 3 — Graph RAG (cross-report correlation)

Hybrid retrieval finds findings *individually*. But the risk that matters is often
**relational**: several findings, from different scanners, on the *same asset*. A
leaked credential (Gitleaks) plus a SQL-injection vuln (Nessus) on one service is a
compound breach path — worse than either alone, and invisible to any single-finding
search. That's what a graph over the corpus buys you.

### The real work was normalization, not the graph

The data bit back: scanners name the same asset differently.

```
payments-api            (gitleaks)
payments-api:latest     (trivy   — image tag)
payments-api (10.0.4.21)(nessus  — host/ip annotation)
```

Nothing correlates until those collapse to one canonical node. `normalize_asset`
strips the `:tag` and the ` (...)` annotation and lowercases — three strings → one
graph node. The graph itself (`asset -> [findings]`, `category -> [findings]`) is
trivial once the nodes are clean. **Lesson: in correlation problems, entity
resolution is the hard part; the graph is the easy part.**

### Honest eval: on a small corpus, recall doesn't show the win

`eval/graph_eval.py` compares hybrid `rag_search` vs graph `correlate_asset` on
"everything on <asset>" questions:

```
           recall   precision
  hybrid   1.000    0.900
  graph    1.000    1.000
```

Both *recall* the full set (only 10 findings, `limit=5` catches them). The honest
difference is **precision**: hybrid pulls in a wrong-asset lookalike (NS-002 on
`edge-lb` bleeding into a payments-api query); graph returns exactly the asset's
node. Two more graph-only wins a flat id-list can't express at all: it never
truncates at `limit`, and it emits correlated *structure* — `scanners`,
`max_cvss`, and the `compound_risk` flag (secret AND vuln co-located) that is the
whole point. **Lesson: pick the metric that exposes the mechanism; recall@k was
the right metric for hybrid-vs-keyword and the wrong one here.**

### Kept honest about what doesn't fire

A `same_cve` edge is part of the Graph-RAG idea, but every CVE in this corpus is
unique — so it's documented as a no-op that would light up on a larger corpus,
not dressed up as a working feature.

**The seam held again:** added a new tool file + one schema (`AssetExposure`) +
two tool registrations + three prompt lines. `rag_search`, `corpus.py`,
`schemas.py`'s existing types, `trace.py`, `app.py` untouched. `run_eval.py` stays
1.00/1.00 — and the agent picked up `correlate_asset`/`riskiest_assets` on its own
in the chained-risk case without being told to.
