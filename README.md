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
| `search_reports` | internal retrieval | **hybrid + filtered search** — BM25 (lexical) + embeddings/ChromaDB (semantic), fused with Reciprocal Rank Fusion over an acronym-expanded query, plus metadata filters (product / scanner / severity / scan_category / status) over the ingested corpus |
| `correlate_asset`, `riskiest_assets` | graph correlation | **cross-report correlation** — every finding on one asset (across scanners), and asset risk ranking, with compound-risk detection |
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
schemas.py     typed contracts (Finding, RecordMetadata, CVEIntel, RiskScore, ...)
trace.py       run() → ReAct steps; multi-turn (threads message_history)
app.py         multi-turn CLI + single-query mode
tools/         search_reports (agent retrieval), analytics, cve_lookup, remediation,
               corpus loader, rag_search + retrieval_common (eval-only mechanics)
ingest.py      production ingestion CLI (manifest → parse → map → upsert)
ingestion/     parsers/ (by format) + mappers/ (by scanner) + record_builder + store
data/          manifest.csv + reports/ (CSV/Excel/HTML/PDF) + lab *.json (mapper=lab_json)
eval/          cases.json + run_eval.py (agent) · ingest/retrieval/graph evals
```

## Production ingestion — real files, many products/scanners/dates

Real reports are Excel, CSV, PDF, and HTML, organized by **product → release →
scanner → dated report**, and each finding becomes one vector-DB record with rich metadata.
`ingest.py` + `ingestion/` do that, keeping three concerns independent:

```
manifest.csv row → parse(file) → map_report(rows) → build_record → ReportStore.upsert
                   (by extension)  (by scanner)      {id,text,metadata}   (persistent Chroma)
```

- **parsers/** — bytes → rows, keyed by file *extension* (`csv`, `xlsx`, `html`, `json`, `pdf`).
- **mappers/** — rows → canonical `RecordMetadata`, keyed by *scanner* (or an explicit
  `mapper` column). Trivy's `VulnerabilityID`, Nessus's `Plugin ID`, and Twistlock's
  `CVE` all mean "finding id" but are named differently — the mapper reconciles that.
  Parser and mapper are separate registries because the same scanner exports in several
  formats and the same format is used by every scanner. The lab's own `data/*.json`
  reports are ingested too, via the `lab_json` mapper — so there is **one corpus**, not
  a legacy island beside it.
- **manifest.csv** — the envelope a file can't self-describe (product, release,
  scan_date, category), one row per report. It's either **hand-written or
  auto-derived from the folder tree**: `ingest.py --scan` walks
  `reports/<product>/<release>/<scanner>/[<date>/]<file>` and reconstructs the
  manifest (product/release/scanner from the path, category from a
  `scanner → profile` table, date from a date folder or the filename), so
  onboarding a product's reports is just dropping files in the right folders.
- **record_builder** — `RecordMetadata` → `{id, text, metadata}`. `id` is a stable
  hash of the finding's identity, so re-ingesting **upserts** (idempotent); the
  `cve_ids` list is flattened to a string because Chroma metadata must be scalar.
- **ReportStore** — a *persistent* Chroma collection (`data/.chroma`, gitignored)
  with **metadata-filtered** search: `product` / `scanner` / `severity` (`$in`) /
  compound (`$and`) filters, so retrieval can be scoped to "Twistlock findings for
  mcp-cce in ProductB".

```bash
python ingest.py            # incremental upsert of everything in the manifest
python ingest.py --reset    # clear the collection, then full re-ingest
python ingest.py --dry-run  # parse+map+build without writing (fast pipeline check)
python ingest.py --scan     # derive the manifest from the folder tree, then ingest
python ingest.py --scan --write-manifest data/manifest.csv   # ...and save it for review
python eval/ingest_eval.py  # 27 records (17 real + 10 lab) + filter/hybrid checks
```

Add a format → drop a `parse_<x>` in `ingestion/parsers/` and register the
extension. Add a scanner → write `map_<scanner>` in `ingestion/mappers/scanners.py`
and register the name (and add it to `SCANNER_PROFILE` in `ingestion/scan.py` so
`--scan` can categorize it). Mappers for Twistlock/Trivy/Nessus are verified;
Blackduck/Checkmarx/Gitleaks are scaffolded (`TODO` — column names need
confirming against a real export).

### One corpus, one retrieval tool

The agent retrieves through a single tool, **`search_reports`**
(`tools/report_search.py`): **hybrid** (BM25 + embeddings, RRF-fused — strong on
both exact CVE/asset ids and fuzzy topics) **and filtered** (product / scanner /
severity / scan_category / status), over the one ingested corpus. Embeddings are
computed once at ingest and reused; the cheap BM25 index is rebuilt from the stored
documents at query time.

Because `corpus.load_findings()` now derives its `Finding`s from that same
manifest-driven corpus, the analytics tools (`count_critical`, …) and the asset
graph (`correlate_asset`, …) count and correlate over exactly what `search_reports`
retrieves — retrieval, counting, and correlation all agree. There is no separate
legacy corpus and no `rag_search` agent tool anymore.

`tools/rag_search.py` remains, but only as the **retrieval-mechanics baseline** for
`eval/retrieval_eval.py` and `eval/graph_eval.py` — those run over a fixed 10-finding
fixture (the lab findings, ingested under product `Acme`) so their hand-verified
goldens stay controlled while the agent uses the full corpus. Shared retrieval
primitives (query expansion, tokenizer, RRF) live in `tools/retrieval_common.py`,
used by both the eval index and the store's hybrid search.

## Retrieval eval

The hybrid retrieval (BM25 lexical + semantic embeddings/ChromaDB, RRF-fused) is
the same mechanism `search_reports` uses. `eval/retrieval_eval.py` measures it
against the keyword scorer it replaced, over a golden `query -> finding ids` set
(the fixed `Acme` fixture), printing recall@k / MRR side by side:

```bash
python eval/retrieval_eval.py
```

Embeddings are local (`sentence-transformers`, `all-mpnet-base-v2`) — no API key;
first run downloads the model (~400MB). The old scorer stays in `rag_search.py` as
`_keyword_rank`, used only as the eval baseline.

**Query rewriting.** Before ranking, `expand_query` appends spelled-out forms of
security shorthand (`sqli`→`sql injection`, `creds`→`credentials`, ...) so the
lexical arm doesn't miss on jargon. It's deterministic (no LLM). The eval prints a
third column (`hybrid+rw`) — on this corpus it *ties* plain hybrid, because the
semantic arm already covers the shorthand, so the fused result doesn't move. The
value is only visible on the **BM25-only** arm the eval isolates at the end
(`creds`→`credentials` recovers GL-001, lexical recall 0.815→0.852): rewriting is a
cheap safety net for when the embedder is weak, unavailable, or hasn't seen the term.

## Graph correlation (cross-report)

`search_reports` finds findings one at a time; the risk that matters is often
*relational* — several findings, from different scanners, on the **same asset**.
The obstacle: scanners spell assets differently (`payments-api`,
`payments-api:latest`, `payments-api (10.0.4.21)`). `tools/asset_graph.py`
normalizes those to one canonical node, then `correlate_asset` returns the full
per-asset picture and `riskiest_assets` ranks by combined exposure — flagging
**compound risk** (a leaked secret *and* an exploitable vuln on one asset).

```bash
python eval/graph_eval.py    # graph vs hybrid: recall + precision on asset questions
```

On this 10-finding corpus both recall the set, but graph is asset-*exact*
(precision 1.00 vs hybrid 0.90 — hybrid bleeds in wrong-asset lookalikes) and
emits correlated structure a flat id-list can't.

## Out of scope (later milestones)

FastAPI endpoints, PDF/XML/CSV parsing, PDF report generation, and a web UI.
The retrieval track is complete (hybrid search → graph correlation → query
rewriting). The agent core here is a drop-in for those wrappers.
```
