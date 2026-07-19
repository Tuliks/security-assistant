"""rag_search — the internal-retrieval tool (the "R" in RAG).

Hybrid retrieval over the ingested findings: a lexical rank (BM25) and a semantic
rank (embeddings + ChromaDB) are computed in parallel and fused with Reciprocal
Rank Fusion (RRF). Security findings mix exact identifiers (CVE ids, asset names —
BM25's strength) with fuzzy natural-language topics ("leaked credentials" —
semantic's strength); hybrid gets both.

Signature and typed return are unchanged from the keyword-only stand-in this
replaces, so agent.py and schemas.py don't move — corpus.py + this file are the
seam the README promised. The old keyword scorer is kept as `_keyword_rank` so
`eval/retrieval_eval.py` can measure that hybrid actually beats it.

The model uses this to answer "what findings exist" questions; it must retrieve
before it can cite, so it can't fabricate findings from its weights.
"""

from __future__ import annotations

import re

from pydantic_ai import ModelRetry
from rank_bm25 import BM25Okapi

from schemas import Finding
from tools.corpus import load_findings
from tools.embedder import embed_query, embed_texts
from tools.vector_store import ChromaStore

_WORD = re.compile(r"[a-z0-9]+")
_VALID_SEVERITIES = ("critical", "high", "medium", "low", "info")
_RRF_K = 60  # standard RRF constant; damps the weight of very high ranks

# Semantic search always returns its top-k, however irrelevant — so an out-of-scope
# query ("weather in Paris") would otherwise pull in random findings and defeat the
# abstention path. Gate semantic hits by cosine distance (Chroma: 0 = identical).
# Measured separation on this corpus: true matches sit ~0.47-0.80, unrelated queries
# start ~0.86. 0.82 keeps real hits and drops noise, so an off-topic query yields no
# semantic candidates (and, with no BM25 overlap either, rag_search returns []).
_SEMANTIC_MAX_DISTANCE = 0.82


# Common English connectors carry no signal but appear in many finding texts, so
# BM25 would otherwise "match" an off-topic query on a shared "in"/"the". Dropped
# from the *lexical* side only (the semantic side embeds full sentences, and the
# keyword baseline is left untouched for a fair comparison).
_STOPWORDS = frozenset(
    "a an and are as at be but by for from how i if in into is it its of on or "
    "that the their this to via was were what when where which who with your our "
    "do does can could would should you we they he she them us".split()
)


def _tokens(text: str) -> list[str]:
    return _WORD.findall(text.lower())


def _content_tokens(text: str) -> list[str]:
    """Tokens with stopwords removed — the lexical (BM25) view of a text."""
    return [t for t in _WORD.findall(text.lower()) if t not in _STOPWORDS]


def _finding_text(f: Finding) -> str:
    """The searchable text for a finding — same fields the keyword scorer used."""
    return " ".join(filter(None, [f.title, f.description, f.asset, f.category, f.cve]))


# --- Hybrid index -----------------------------------------------------------
# Built once per process and cached: loading the embedding model and embedding
# the corpus is slow, and the corpus is static within a run. First rag_search
# call pays the cost; the rest reuse it.


class _HybridIndex:
    def __init__(self, findings: list[Finding]) -> None:
        self.findings = findings
        self.ids = [f.id for f in findings]
        self.by_id = {f.id: f for f in findings}
        texts = [_finding_text(f) for f in findings]

        # Lexical: BM25 over stopword-filtered finding texts.
        self._bm25 = BM25Okapi([_content_tokens(t) for t in texts])

        # Semantic: embed once, store in ChromaDB (in-memory).
        self._store = ChromaStore(collection_name="findings")
        chunks = [
            {"text": t, "metadata": {"id": fid, "severity": f.severity}}
            for t, fid, f in zip(texts, self.ids, findings)
        ]
        self._store.add(chunks, embed_texts(texts))

    def bm25_ranking(self, query: str) -> list[str]:
        """Finding ids ranked by BM25, best first. Drops zero-score (no-overlap) ids."""
        scores = self._bm25.get_scores(_content_tokens(query))
        order = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)
        return [self.ids[i] for i in order if scores[i] > 0]

    def semantic_ranking(self, query: str) -> list[str]:
        """Finding ids ranked by embedding similarity, best first.

        Only hits within `_SEMANTIC_MAX_DISTANCE` are kept, so an off-topic query
        contributes no semantic candidates instead of its (irrelevant) top-k.
        """
        hits = self._store.search(embed_query(query), k=len(self.findings))
        return [h["metadata"]["id"] for h in hits if h["score"] <= _SEMANTIC_MAX_DISTANCE]


_INDEX: _HybridIndex | None = None


def _get_index() -> _HybridIndex:
    global _INDEX
    if _INDEX is None:
        _INDEX = _HybridIndex(load_findings())
    return _INDEX


def _rrf(rankings: list[list[str]], k: int = _RRF_K) -> list[str]:
    """Fuse ranked id-lists with Reciprocal Rank Fusion, best first.

    score(id) = Σ 1 / (k + rank), rank starting at 1. Rank-based, so it doesn't
    matter that BM25 and Chroma report scores on different scales (or that Chroma
    reports distance, not similarity). An id present in either list is kept.
    """
    scores: dict[str, float] = {}
    for ranking in rankings:
        for rank, fid in enumerate(ranking, start=1):
            scores[fid] = scores.get(fid, 0.0) + 1.0 / (k + rank)
    return sorted(scores, key=lambda fid: scores[fid], reverse=True)


def rag_search(query: str, severity: str | None = None, limit: int = 5) -> list[Finding]:
    """Search the ingested scanner reports for findings relevant to a query.

    Use this to discover what findings exist before citing or analyzing them,
    e.g. "exposed secrets", "SQL injection", "issues in payments-api".

    Args:
        query: What to look for — keywords, an asset/repo name, or a topic.
        severity: Optional filter, one of critical/high/medium/low/info.
        limit: Max findings to return (1-20, default 5).
    """
    if not query or not query.strip():
        raise ModelRetry("Empty query. Pass keywords, an asset name, or a topic to search for.")
    if limit <= 0 or limit > 20:
        raise ModelRetry(f"Invalid limit: {limit}. Must be between 1 and 20.")
    if severity is not None and severity.lower() not in _VALID_SEVERITIES:
        raise ModelRetry(
            f"Invalid severity {severity!r}. Use one of: {', '.join(_VALID_SEVERITIES)}, or omit it."
        )

    index = _get_index()

    # Severity is a pre-filter on the candidate set (same behavior as before):
    # restrict both rankings to the allowed ids before fusing.
    allowed: set[str] | None = None
    if severity is not None:
        sev = severity.lower()
        allowed = {f.id for f in index.findings if f.severity == sev}
        if not allowed:
            return []

    bm25 = index.bm25_ranking(query)
    semantic = index.semantic_ranking(query)
    if allowed is not None:
        bm25 = [i for i in bm25 if i in allowed]
        semantic = [i for i in semantic if i in allowed]

    fused = _rrf([bm25, semantic])
    if not fused:
        # Business-empty is not an error — an empty list lets the model decide to
        # abstain (NeedMoreInfo) rather than being forced to retry a valid query.
        return []

    return [index.by_id[fid] for fid in fused[:limit]]


# --- Baseline: the old keyword-overlap scorer -------------------------------
# Kept so eval/retrieval_eval.py can compare hybrid against what it replaced.
# Not used by the agent.


def _keyword_rank(query: str, severity: str | None = None, limit: int = 5) -> list[Finding]:
    """The original token-overlap retrieval — retained only as an eval baseline."""
    findings = load_findings()
    if severity is not None:
        sev = severity.lower()
        findings = [f for f in findings if f.severity == sev]

    q_tokens = set(_tokens(query))
    scored: list[tuple[float, Finding]] = []
    for f in findings:
        haystack = set(_tokens(_finding_text(f)))
        overlap = len(q_tokens & haystack)
        if overlap:
            scored.append((overlap / max(len(q_tokens), 1), f))

    if not scored:
        return []

    scored.sort(key=lambda pair: pair[0], reverse=True)
    return [f for _, f in scored[:limit]]
