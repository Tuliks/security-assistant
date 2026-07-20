# Documentation — Security AI Assistant

Complete reference for what was built, how it works, and how to run it. For the
*why* behind the design, see [DESIGN.md](DESIGN.md).

---

## Table of contents

1. [Overview](#1-overview)
2. [Setup](#2-setup)
3. [Usage](#3-usage)
4. [Architecture & data flow](#4-architecture--data-flow)
5. [Ingestion pipeline](#5-ingestion-pipeline)
6. [Retrieval](#6-retrieval)
7. [The agent & its tools](#7-the-agent--its-tools)
8. [Data schemas](#8-data-schemas)
9. [Evaluation](#9-evaluation)
10. [Project layout](#10-project-layout)
11. [Tech stack](#11-tech-stack)
12. [Extending the system](#12-extending-the-system)
13. [Troubleshooting](#13-troubleshooting)

---

## 1. Overview

The Security AI Assistant is a **Pydantic AI agent** that answers questions about
a corpus of ingested security-scanner findings (Gitleaks, Trivy, Nessus,
Twistlock, and others). You ask in natural language; the agent decides which tools
to call, chains them, and returns a **typed, grounded answer** — or abstains when
nothing in the data supports one.

It has two halves:

- **Ingestion (offline):** turns real scanner reports (CSV / Excel / HTML / PDF /
  JSON) into uniform records in a local vector database.
- **Agent (online):** a ReAct loop over that database, with multi-turn
  conversation memory.

**What makes it trustworthy:** the model chooses *what* to investigate, but every
fact it reports — CVSS scores, CISA KEV status, counts, remediation steps — comes
only from a typed tool result. Fabrication is blocked structurally.

---

## 2. Setup

```bash
cd security-assistant
pip install -r requirements.txt
cp .env.example .env          # then edit .env
```

Set your model and key in `.env`:

```bash
AGENT_MODEL=openai:gpt-4.1        # or anthropic:claude-opus-4-8, etc.
OPENAI_API_KEY=sk-...             # the key matching your AGENT_MODEL provider
```

**First run note:** the local embedding model (`all-mpnet-base-v2`, ~400 MB)
downloads on first use. No API key is needed for embeddings, retrieval, BM25, or
graph correlation — only the LLM and the live NVD CVE lookup make network calls.

Then ingest the corpus so the store is populated:

```bash
python ingest.py            # populates data/.chroma (gitignored)
```

---

## 3. Usage

### Single query (one independent turn)

```bash
python app.py "Which repos have exposed secrets, and how risky is the worst CVE?"
```

### Interactive, multi-turn (follow-ups remember context)

```bash
python app.py
You: Show critical vulnerabilities
You: Now just the ones in payments-api      # remembers "critical" from before
You: /clear                                 # reset conversation memory
You: exit                                   # or quit
```

The CLI prints the **ReAct trace** (each Thought → tool call → Observation) and
then the typed final answer, so you can see exactly how the agent reasoned.

### Ingestion commands

```bash
python ingest.py                       # incremental upsert of everything in the manifest
python ingest.py --reset               # clear the collection, then full re-ingest
python ingest.py --dry-run             # parse + map + build, but don't write (fast pipeline check)
python ingest.py --scan                # derive the manifest FROM the folder tree, then ingest
python ingest.py --scan --write-manifest data/manifest.csv   # ... and save the derived manifest
```

### Evaluation

```bash
python eval/run_eval.py            # agent end-to-end (each case = one independent turn)
python eval/ingest_eval.py         # ingestion: record counts, shape, filters, hybrid
python eval/retrieval_eval.py      # hybrid vs keyword: recall@k / MRR
python eval/graph_eval.py          # graph vs hybrid: recall + precision on asset questions
```

---

## 4. Architecture & data flow

```
 OFFLINE ─ Ingestion
   data/reports/<product>/<release>/<scanner>/[<date>/]<file.ext>
        │
        │  manifest.csv  OR  scan_reports()          → ReportEnvelope (the "envelope")
        ▼
     parse(file)         (dispatch by file extension)  → list[dict] raw rows
        ▼
     map_report(rows,env)(dispatch by scanner)         → RecordMetadata (canonical)
        ▼
     build_record()                                    → {id, text, metadata}
        ▼
     ReportStore.upsert()   → ChromaDB @ data/.chroma  (idempotent, keyed by stable id)

 ONLINE ─ Agent
   user query
        ▼
   Pydantic AI Agent (ReAct loop)
        │  Thought → choose tool → Observation → repeat
        ├─ search_reports   → hybrid + filtered retrieval over the store
        ├─ correlate_asset  → cross-scanner asset picture
        ├─ analytics/cve/…  → deterministic compute + live NVD
        ▼
   output_validator (grounding check)
        ▼
   [ SecurityAnswer | NeedMoreInfo ]   (typed, succeed-or-abstain)
```

The two halves meet at **one vector store**. Because analytics and the asset graph
read the same store `search_reports` retrieves from, retrieval, counting, and
correlation always agree about what exists.

---

## 5. Ingestion pipeline

Located in `ingestion/`. Three concerns are kept independent because real scanner
exports vary along two axes at once — *format* and *scanner*.

```
raw file --[parser]--> rows --[mapper]--> RecordMetadata --[builder]--> {id,text,metadata}
          (by extension)       (by scanner)                (record shape)
```

### 5.1 The manifest (the envelope)

A Trivy Excel lists CVEs but nothing inside it says "product Ivan, release Dana,
scanned 2026-02-24 by Trivy." That **envelope** is declared, not parsed. Two ways
to provide it:

**(a) Hand-written `data/manifest.csv`** — one row per report:

| column | meaning |
|---|---|
| `report_file` | path relative to `data/` |
| `product_name` | e.g. `Ivan` |
| `release_version` | e.g. `Dana(01.01.00.00)` (may be blank) |
| `scanner` | e.g. `Trivy` → selects the mapper |
| `scan_category` | `SCA` / `CONTAINER` / `HOST` / `SAST` / `SECRET` |
| `scan_date` | `YYYY-MM-DD` |
| `component_name` / `component_version` / `component_type` | default component (may be blank) |
| `mapper` | optional mapper override (e.g. `lab_json`); defaults to `scanner` |

**(b) Auto-derived from the folder tree** (`ingestion/scan.py`, via `--scan`) —
the folder convention encodes most of the envelope:

```
data/reports/<product>/<release>/<scanner>/[<date>/]<report.ext>
```

`scan_reports()` walks this tree and derives one `ReportEnvelope` per file:

- `product`, `release`, `scanner` → path segments.
- `scan_category` + `component_type` → the `SCANNER_PROFILE` table:

  | scanner | scan_category | component_type |
  |---|---|---|
  | blackduck | SCA | repository |
  | nessus | HOST | host |
  | twistlock | CONTAINER | container_image |
  | gitleaks | SECRET | repository |
  | checkmarx | SAST | repository |
  | trivy | SCA | repository |

- `scan_date` → a date **folder** under the scanner (`2026-02-24` or ISO week
  `2026-W08`), else a date **in the filename** (`webapp_20260305.html`), else the
  file's **mtime** (with a warning — the path told us nothing).
- `component_name` / `component_version` → parsed from the filename
  (`mcp-cce-2.4.0.csv` → `mcp-cce`, `2.4.0`); blank for host scans.

Everything the path *can't* express is logged as a warning — unknown scanner,
too-shallow path, missing date — so nothing is silently guessed.

### 5.2 Parsers (`ingestion/parsers/`) — keyed by file extension

| extension | parser | backend |
|---|---|---|
| `csv` | `parse_csv` | pandas |
| `xlsx` / `xls` | `parse_excel` | pandas + openpyxl |
| `html` / `htm` | `parse_html` | pandas.read_html + BeautifulSoup/lxml |
| `json` | `parse_json` | stdlib |
| `pdf` | `parse_pdf` | pdfplumber |

Each parser's only job is *bytes → rows* using the report's native column names.
Register a new format with `parse_<x>(path) -> list[dict]` in `PARSERS`.

### 5.3 Mappers (`ingestion/mappers/scanners.py`) — keyed by scanner

This is where production messiness lives. Trivy calls the finding id
`VulnerabilityID`, Nessus calls it `Plugin ID`, Twistlock calls it `CVE`; each
mapper knows its own columns and produces the one canonical `RecordMetadata`.
Register with `map_<scanner>(row, env) -> RecordMetadata | None` (return `None` to
drop a row) in `MAPPERS`.

> **Currently implemented mappers:** `twistlock`, `trivy`, `nessus`, and `lab_json`
> (for the JSON fixtures). `blackduck`, `checkmarx`, and real (non-lab) `gitleaks`
> are profiled in `--scan` but need mappers before those reports can ingest.

### 5.4 Record builder & store

- `build_record()` turns `RecordMetadata` into `{id, text, metadata}`. `id` is a
  **stable hash** of the finding's identity, so re-ingesting **upserts** (idempotent).
  `cve_ids` (a list) is flattened to a string because Chroma metadata must be scalar.
- `ReportStore` is a **persistent** Chroma collection at `data/.chroma`
  (gitignored) with metadata-filtered search (`product` / `scanner` / `severity`
  `$in` / compound `$and`).

---

## 6. Retrieval

The agent retrieves through a single tool, **`search_reports`**
(`tools/report_search.py`): **hybrid + filtered** over the one ingested corpus.

**Hybrid = BM25 (lexical) + embeddings (semantic), fused with Reciprocal Rank
Fusion (RRF).** Lexical is strong on exact CVE/asset ids; semantic is strong on
fuzzy topics; RRF combines their rankings. Embeddings are computed once at ingest
and reused; the cheap BM25 index is rebuilt from stored documents at query time.
Shared primitives (query expansion, tokenizer, RRF) live in
`tools/retrieval_common.py`.

**Query rewriting.** Before ranking, `expand_query` appends spelled-out forms of
security shorthand (`sqli`→`sql injection`, `creds`→`credentials`, …) so the
lexical arm doesn't miss on jargon. Deterministic — no LLM.

**Filters.** Retrieval can be scoped by product / scanner / severity /
scan_category / status — e.g. "Twistlock findings for mcp-cce in Ivan."

**Graph correlation.** The risk that matters is often *relational* — several
findings, from different scanners, on the **same asset**. Scanners spell assets
differently (`payments-api`, `payments-api:latest`, `payments-api (10.0.4.21)`);
`tools/asset_graph.py` normalizes them to one canonical node, then
`correlate_asset` returns the full per-asset picture and `riskiest_assets` ranks by
combined exposure — flagging **compound risk** (a leaked secret *and* an
exploitable vuln on one asset).

---

## 7. The agent & its tools

Defined in `agent.py` (~120 lines — the whole agent in one file). Built on
Pydantic AI's `Agent`, which runs the ReAct loop internally. `trace.py`
reconstructs the loop from `result.all_messages()` so it's visible; it also threads
`message_history` for multi-turn memory.

**Registered tools** (`agent.tool_plain(...)`):

| Tool | Kind | Purpose |
|---|---|---|
| `search_reports` | internal retrieval | hybrid + filtered search over the corpus |
| `correlate_asset` | graph correlation | every finding on one asset, across scanners |
| `riskiest_assets` | graph correlation | rank assets by combined exposure; compound-risk flag |
| `count_critical` | deterministic compute | exact count of critical findings |
| `average_cvss` | deterministic compute | exact mean CVSS |
| `extract_cves` | deterministic compute | pull CVE ids from the corpus |
| `calculate_risk` | deterministic compute | CVSS + KEV + exposure → prioritization score |
| `cve_lookup` | external HTTP | enrich a CVE from **NIST NVD** (live, keyless), incl. CISA KEV |
| `suggest_remediation` | local knowledge | vetted fix playbook by finding category |

**Output & grounding.** `output_type = [SecurityAnswer, NeedMoreInfo]` — a union
that forces succeed-or-abstain. An `@agent.output_validator`
(`answer_is_grounded`) rejects answers not backed by tool results. Because tools
return typed models, facts can only enter through them.

---

## 8. Data schemas

Defined in `schemas.py` (Pydantic v2). The contract shared across ingestion,
retrieval, and the agent.

| Model | Role |
|---|---|
| `Finding` | An in-memory finding (id, scanner, severity, asset, cve, cvss, …) used by analytics & the graph |
| `RecordMetadata` | The **ingested vector-DB record's** metadata — envelope + finding fields; the target of the ingest pipeline |
| `CVEIntel` | NVD lookup result — description, severity band, `kev_listed`, affected, references |
| `RiskScore` | `score` (0–10) + `band` + `rationale` from CVSS/KEV/exposure |
| `RemediationPlaybook` | Category → ordered fix `steps` + references |
| `AssetExposure` | Correlated per-asset view — all findings, distinct scanners, `max_cvss`, `has_exposed_secret`, `has_vulnerability`, `compound_risk` |
| `SecurityAnswer` | The success output — `message`, `findings_cited`, `cves`, `tools_used`, optional `summary_data` |
| `NeedMoreInfo` | The abstain output — the one `question` to ask + `reason` it couldn't answer |

`Severity` is a constrained type; `cvss`/`cvss_score` are validated `0 ≤ x ≤ 10`.

---

## 9. Evaluation

Each eval isolates one part of the system so regressions are attributable.

| Eval | Measures | Fixture |
|---|---|---|
| `eval/run_eval.py` (+ `cases.json`) | Agent end-to-end; each case = one independent turn | full corpus |
| `eval/ingest_eval.py` | Record counts, metadata shape across formats, filter scoping, hybrid+filter | full corpus (27 = 17 real + 10 lab) |
| `eval/retrieval_eval.py` (+ `retrieval_cases.json`) | Hybrid vs keyword baseline: recall@k / MRR, incl. a `hybrid+rw` column | fixed 10-finding `Acme` fixture |
| `eval/graph_eval.py` (+ `graph_cases.json`) | Graph vs hybrid: recall + precision on asset questions | fixed 10-finding fixture |

**Why a fixed fixture for retrieval/graph:** those hand-verified goldens stay
controlled (the lab findings, ingested under product `Acme`) while the agent runs
over the full corpus. `tools/rag_search.py` remains as the retrieval-mechanics
baseline for these two evals (its `_keyword_rank` is the baseline scorer); it is
**not** an agent tool.

Representative results:
- Ingestion: **27 records ingested** (17 real reports + 10 lab JSON), 10/10 checks pass.
- Retrieval: hybrid beats the keyword baseline on recall@k / MRR; query rewriting
  is a safety net visible on the BM25-only arm (lexical recall 0.815 → 0.852).
- Graph: same recall as hybrid but asset-*exact* (precision 1.00 vs 0.90) and emits
  correlated structure a flat id-list can't.

---

## 10. Project layout

```
agent.py            Agent + tool registration + grounding validator (whole agent, one file)
schemas.py          Typed contracts (Finding, RecordMetadata, CVEIntel, RiskScore, …)
trace.py            run() → ReAct steps; multi-turn (threads message_history)
app.py              Multi-turn CLI + single-query mode
ingest.py           Ingestion CLI (manifest OR --scan; --reset / --dry-run / --write-manifest)

tools/
  report_search.py    search_reports — the agent's hybrid+filtered retrieval tool
  retrieval_common.py shared primitives: query expansion, tokenizer, RRF
  embedder.py         local sentence-transformers embedding layer
  asset_graph.py      asset normalization + correlate_asset / riskiest_assets
  analytics.py        count_critical / average_cvss / extract_cves / calculate_risk
  cve_lookup.py       live NVD lookup (httpx)
  remediation.py      suggest_remediation playbooks
  rag_search.py       retrieval-mechanics baseline (eval-only; _keyword_rank)
  vector_store.py     Chroma helper (persistent/ephemeral)
  corpus.py           load_findings() over the ingested corpus

ingestion/
  manifest.py         ReportEnvelope + load_manifest (reads manifest.csv)
  scan.py             scan_reports() — derive the manifest from the folder tree (+ write_manifest)
  parsers/            bytes → rows, by file extension (tabular, json_report, pdf_report)
  mappers/            rows → RecordMetadata, by scanner (scanners.py, common.py)
  record_builder.py   RecordMetadata → {id, text, metadata}
  store.py            ReportStore — persistent Chroma collection + filtered search

data/
  manifest.csv        the envelope, one row per report
  reports/            real reports: <product>/<release>/<scanner>/[<date>/]<file>
  *.json              lab JSON fixtures (mapper=lab_json)
  .chroma/            persistent vector store (gitignored)

eval/                 run_eval · ingest_eval · retrieval_eval · graph_eval (+ *_cases.json)
```

---

## 11. Tech stack

**AI / agent**
- **Pydantic AI** — agent framework; runs the ReAct loop; typed outputs + output validators.
- **LLM (provider-agnostic)** — `AGENT_MODEL` env var (default `openai:gpt-4.1`; e.g. `anthropic:claude-opus-4-8`). The only paid/hosted AI dependency.

**Retrieval / RAG**
- **sentence-transformers** (`all-mpnet-base-v2`) — local embeddings, no API key.
- **ChromaDB** — persistent vector store + metadata filters.
- **rank-bm25** — lexical arm.
- **Reciprocal Rank Fusion** + **query rewriting** — custom (in `retrieval_common.py`).
- **NumPy** — vector math.

**Ingestion / parsing**
- **pandas** (CSV/Excel/HTML), **openpyxl** (`.xlsx`), **beautifulsoup4** + **lxml** (HTML), **pdfplumber** (PDF).

**External data**
- **NIST NVD REST API** (live, keyless) via **httpx** — CVE enrichment + CISA KEV.

**Core**
- **Python 3.9+**, **Pydantic v2** (schemas), **python-dotenv** (config), **argparse** (CLIs).

---

## 12. Extending the system

**Add a report format** → write `parse_<x>(path) -> list[dict]` in
`ingestion/parsers/` and register the extension in `PARSERS`.

**Add a scanner** → write `map_<scanner>(row, env) -> RecordMetadata | None` in
`ingestion/mappers/scanners.py`, register it in `MAPPERS`, and add a row to
`SCANNER_PROFILE` in `ingestion/scan.py` (category + component_type) so `--scan`
knows it.

**Add an agent capability** → write the tool (typed return!), then register it in
`agent.py` with `agent.tool_plain(...)`. Keep facts flowing through typed returns
so the grounding guarantee holds.

**Onboard a new product's reports** → drop files under
`data/reports/<product>/<release>/<scanner>/[<date>/]` and run
`python ingest.py --scan` — no manual manifest editing.

---

## 13. Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| First run is slow / downloads ~400 MB | The `all-mpnet-base-v2` embedding model downloads once; cached after. |
| `--scan` skips a file ("too shallow") | Path isn't `product/release/scanner/file`; check the folder depth. |
| `--scan` warns "unknown scanner" | Scanner missing from `SCANNER_PROFILE` — add it in `scan.py`. |
| `--scan` uses file mtime for the date | No date folder and no date in the filename — add one to get the real scan date. |
| A report parses but fails at map | No mapper registered for that scanner (e.g. blackduck/checkmarx yet). |
| Agent returns `NeedMoreInfo` | By design — the data/tools didn't support a grounded answer. |
| Empty / stale results | Re-run `python ingest.py --reset` to rebuild `data/.chroma`. |
| Auth errors from the LLM | Check `AGENT_MODEL` and the matching `*_API_KEY` in `.env`. |
