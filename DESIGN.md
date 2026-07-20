# Design Doc — Security AI Assistant

**Status:** Living design (written before/during development)
**Scope:** First vertical slice of `Security_AI_Assistant_Product_Spec.md`
**Audience:** Engineers building or extending the assistant

---

## 1. Problem

Security teams run many scanners (Gitleaks, Trivy, Nessus, Twistlock, Blackduck,
Checkmarx) across many products, releases, and weekly cadences. The findings land
as a pile of heterogeneous files — CSV, Excel, HTML, PDF, JSON — each with its own
column names for the same concepts. Analysts then have to answer questions that
cut *across* those files: "Which repos leak secrets?", "How bad is the worst CVE
on payments-api?", "Which asset carries both an exposed secret and an exploitable
vuln?"

Doing this by hand is slow and error-prone. Doing it with a naive LLM is worse —
the model will happily invent CVSS scores, KEV status, and counts.

**Goal:** an agent that answers grounded security questions over an ingested
corpus of real scanner reports — and *abstains* when the data doesn't support an
answer, never fabricating facts.

## 2. Non-goals (this slice)

- FastAPI / web UI — CLI only for now.
- Auth, multi-tenant, or persistence beyond a local vector DB.
- PDF *report generation* (we parse PDFs, we don't emit them).
- Fine-tuning or hosting our own LLM.

## 3. Design principles

1. **Grounding by typing.** The model may choose *which* findings/CVEs to
   investigate, but every fact (CVSS, KEV, counts, remediation) must originate
   from a typed tool return — never the model's memory. Enforced structurally, not
   by prompt-wishing.
2. **Succeed or abstain.** The agent's output is a union
   `[SecurityAnswer, NeedMoreInfo]`. No half-answers.
3. **Separation of concerns in ingestion.** Real reports vary along two axes at
   once — *format* (CSV/Excel/…) and *scanner* (Trivy/Nessus/…). Parsing and
   mapping are therefore independent registries, not one function per (format ×
   scanner) pair.
4. **One corpus.** Retrieval, counting, and graph correlation all read the same
   ingested store, so they can never disagree about what exists.
5. **Local-first AI.** Only the reasoning LLM and the live NVD lookup make
   network calls. Embeddings, vector search, and lexical ranking run on-device —
   retrieval needs zero API keys.

## 4. High-level architecture

```
                      ┌───────────────────────── Ingestion (offline) ─────────────────────────┐
  data/reports/       │  manifest / scan → parse(by ext) → map(by scanner) → build → upsert    │
  <product>/<release>/│   envelope         rows            RecordMetadata     {id,text,meta}    │
  <scanner>/<date>/…  └───────────────────────────────────────────────┬───────────────────────┘
                                                                       ▼
                                                          ChromaDB (data/.chroma)
                                                          + local embeddings + BM25 index
                                                                       ▲
                      ┌──────────────────────────── Agent (online) ────┴──────────────────────┐
  user query ───────▶ │  Pydantic AI ReAct loop: Thought → tool → Observation → typed output   │
                      │  tools: search_reports · correlate_asset · analytics · cve_lookup · …   │
                      │  output_validator enforces grounding → [SecurityAnswer | NeedMoreInfo]  │
                      └───────────────────────────────────────────────────────────────────────┘
```

Two independent halves that meet at the vector store:

- **Ingestion** turns messy files into uniform `RecordMetadata` records. The
  envelope a file can't self-describe (product, release, scanner, date) comes from
  either a hand-written `manifest.csv` **or** is derived from the folder
  convention by `ingestion/scan.py`.
- **Agent** answers questions by planning tool calls over that store.

## 5. Key design decisions & trade-offs

| Decision | Why | Trade-off accepted |
|---|---|---|
| **Pydantic AI** for the agent | Runs the ReAct loop internally; native typed outputs + output validators give us grounding for free | Framework lock-in; less control than a hand-rolled loop |
| **Provider-agnostic LLM** (`AGENT_MODEL`) | Swap OpenAI ↔ Anthropic without code change | Behavior varies by model; must eval per model |
| **Hybrid retrieval** (BM25 + embeddings, RRF-fused) | Exact ids (CVE, asset) need lexical; fuzzy topics need semantic. Neither alone suffices | Two indexes to maintain; more moving parts than pure-vector |
| **Local embeddings** (`all-mpnet-base-v2`) | No API key, no per-query cost, private | ~400 MB model download; CPU-bound first run |
| **Parser/mapper split** | Same scanner exports many formats; same format used by many scanners | Two registries instead of one; slight indirection |
| **Manifest as the envelope** | A Trivy Excel can't say "I'm product ProductB, release ReleaseB.1, scanned 2026-02-24" | Someone/something must supply it → solved by `--scan` |
| **`--scan` derives manifest from folders** | Hand-writing a manifest doesn't scale to many product×release×scanner×week drops | Requires a strict folder convention; a few fields (category, date) need inference |
| **Graph correlation** hand-rolled | Cross-scanner asset risk is *relational*; flat retrieval bleeds in wrong-asset lookalikes | Custom code to maintain vs. a library |
| **Deterministic analytics tools** | Counts/averages/CVE extraction must be exact, never an LLM guess | Model can't "reason" over them — must call the tool |

## 6. The grounding mechanism (the load-bearing decision)

```
output_type = [SecurityAnswer, NeedMoreInfo]      # union: succeed or abstain
@agent.output_validator answer_is_grounded(...)   # rejects ungrounded answers
tools return typed models (CVEIntel, RiskScore…)  # facts enter only through tools
```

The LLM is the *planner*; the tools are the *source of truth*. This is what makes
the assistant safe to trust in a security context.

## 7. Ingestion contract (the folder convention)

```
data/reports/<product>/<release>/<scanner>/[<date>/]<report.ext>
              ProductB      ReleaseB.1(…)     Twistlock  2026-02-24 mcp-cce-2.4.0.csv
```

- `product`, `release`, `scanner` → path segments.
- `scan_category`, `component_type` → `scanner → profile` table (`scan.py`).
- `scan_date` → a date folder, else a date in the filename, else file mtime (flagged).

`--scan` reconstructs the manifest from this tree; the hand-written `manifest.csv`
remains the fallback for anything outside the convention (e.g. lab JSON fixtures).

## 8. Milestones

- ✅ Multi-turn agent + typed grounding (spec capability #10)
- ✅ Hybrid retrieval → graph correlation → query rewriting (retrieval track)
- ✅ Production ingestion (parse CSV/Excel/HTML/PDF/JSON, per-scanner mappers)
- ✅ Folder-derived manifest (`--scan`)
- ⏭ Mappers for Blackduck / Checkmarx / real Gitleaks
- ⏭ FastAPI wrapper + web UI + PDF report generation

## 9. Risks

- **LLM drift across providers** — mitigated by the eval suite (`eval/`).
- **Scanner schema changes** — isolated to a single mapper each.
- **Retrieval quality** — measured, not assumed (`retrieval_eval`, `graph_eval`).
