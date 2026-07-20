"""ReportStore — the persistent vector index for ingested reports.

Unlike the legacy in-memory index in tools/rag_search.py (rebuilt from data/*.json
every run), the production corpus grows over time — many products, scanners, and
dated reports — so it persists to disk and is updated incrementally.

- PersistentClient at data/.chroma (gitignored); survives across runs.
- upsert() keys on the record's stable id, so re-ingesting a report replaces its
  records instead of duplicating them.
- hybrid_search() fuses BM25 (lexical, great on exact CVE/asset ids) with the
  stored embeddings (semantic), and applies the record template's metadata filters
  (product / scanner / severity / category / status) as a Chroma `where` — so
  retrieval is both high-quality AND scopable to "Twistlock findings for mcp-cce
  in Ivan". Embeddings are computed once at ingest and reused; only the (cheap)
  BM25 index is rebuilt from the stored documents at query time.
"""

from __future__ import annotations

import os

import chromadb
from rank_bm25 import BM25Okapi

from tools.embedder import embed_query, embed_texts
from tools.retrieval_common import content_tokens, expand_query, rrf

# Semantic hits beyond this cosine distance are dropped, so an off-topic query
# contributes no semantic candidates (preserving the agent's abstention path).
# Same model + threshold as tools/rag_search.py.
_SEMANTIC_MAX_DISTANCE = 0.82

_CHROMA_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", ".chroma"
)
_COLLECTION = "reports"


def build_where(filters: dict | None) -> dict | None:
    """Translate a flat filter dict into a Chroma `where` clause.

    Scalar value -> equality ({"product_name": "Ivan"}); list value -> membership
    ({"severity": {"$in": ["critical", "high"]}}). Multiple conditions are
    combined with $and (Chroma requires the operator for >1 condition). Mirrors
    the record template's metadata-filter examples.
    """
    if not filters:
        return None
    conditions = []
    for key, value in filters.items():
        if value is None:
            continue
        if isinstance(value, (list, tuple, set)):
            values = [v for v in value if v is not None]
            if values:
                conditions.append({key: {"$in": list(values)}})
        else:
            conditions.append({key: value})
    if not conditions:
        return None
    if len(conditions) == 1:
        return conditions[0]
    return {"$and": conditions}


def _passes(meta: dict, filters: dict | None) -> bool:
    """Python-side twin of build_where — does a record's metadata satisfy filters?

    Used to constrain the BM25 arm (which Chroma's `where` can't reach) to the
    same candidate set the semantic arm sees.
    """
    if not filters:
        return True
    for key, value in filters.items():
        mv = meta.get(key)
        if isinstance(value, (list, tuple, set)):
            if mv not in value:
                return False
        elif mv != value:
            return False
    return True


class ReportStore:
    def __init__(self, persist_dir: str = _CHROMA_DIR, collection: str = _COLLECTION):
        os.makedirs(persist_dir, exist_ok=True)
        self.client = chromadb.PersistentClient(path=persist_dir)
        self.collection = self.client.get_or_create_collection(
            name=collection, metadata={"hnsw:space": "cosine"}
        )
        self._cache = None  # (ids, docs, metas, bm25), lazily built at query time

    def upsert(self, records: list[dict]) -> int:
        """Insert-or-replace records ({id, text, metadata}). Idempotent by id."""
        if not records:
            return 0
        ids = [r["id"] for r in records]
        docs = [r["text"] for r in records]
        metas = [r["metadata"] for r in records]
        embs = [e.tolist() for e in embed_texts(docs)]
        self.collection.upsert(ids=ids, documents=docs, embeddings=embs, metadatas=metas)
        self._cache = None  # corpus changed; drop the BM25 cache
        return len(records)

    # --- retrieval ----------------------------------------------------------

    def _lexical(self):
        """(ids, docs, metas, BM25) over the whole collection, built once per run.

        Embeddings live in Chroma; BM25 is cheap to rebuild from the stored
        documents, so we don't persist it. `collection.get` returns every record.
        """
        if self._cache is None:
            got = self.collection.get(include=["documents", "metadatas"])
            ids, docs, metas = got["ids"], got["documents"], got["metadatas"]
            bm25 = BM25Okapi([content_tokens(d) for d in docs]) if docs else None
            self._cache = (ids, docs, metas, bm25)
        return self._cache

    def _semantic_ranking(self, query: str, filters: dict | None) -> list[str]:
        """Ids ranked by embedding similarity, filtered server-side, noise-gated."""
        res = self.collection.query(
            query_embeddings=[embed_query(query).tolist()],
            n_results=max(self.count, 1),
            where=build_where(filters) or None,
        )
        return [
            res["ids"][0][i]
            for i in range(len(res["ids"][0]))
            if res["distances"][0][i] <= _SEMANTIC_MAX_DISTANCE
        ]

    def _bm25_ranking(self, query: str, filters: dict | None) -> list[str]:
        """Ids ranked by BM25, dropping zero-overlap ids and filter non-matches."""
        ids, _docs, metas, bm25 = self._lexical()
        if bm25 is None:
            return []
        scores = bm25.get_scores(content_tokens(query))
        order = sorted(range(len(ids)), key=lambda i: scores[i], reverse=True)
        return [
            ids[i] for i in order
            if scores[i] > 0 and _passes(metas[i], filters)
        ]

    def hybrid_search(self, query: str, filters: dict | None = None, k: int = 5) -> list[dict]:
        """BM25 + semantic, fused with RRF, under optional metadata filters.

        Returns hits (id + metadata), best first. An empty list means nothing
        matched — the caller (search_reports) turns that into an abstention rather
        than a forced, ungrounded answer.
        """
        if self.count == 0:
            return []
        q = expand_query(query)
        fused = rrf([self._bm25_ranking(q, filters), self._semantic_ranking(q, filters)])
        if not fused:
            return []
        ids, _docs, metas, _bm25 = self._lexical()
        by_id = {i: metas[n] for n, i in enumerate(ids)}
        return [{"id": fid, "metadata": by_id[fid]} for fid in fused[:k] if fid in by_id]

    def records(self, filters: dict | None = None) -> list[dict]:
        """Every record's metadata matching `filters` (no ranking) — for counting.

        Unlike hybrid_search (relevance-ranked, query-driven), this enumerates the
        full filtered set, e.g. "all records where product_name == 'Ivan'".
        """
        got = self.collection.get(where=build_where(filters) or None, include=["metadatas"])
        return got["metadatas"]

    def reset(self) -> None:
        """Drop and recreate the collection — a clean full re-ingest."""
        name = self.collection.name
        self.client.delete_collection(name)
        self.collection = self.client.get_or_create_collection(
            name=name, metadata={"hnsw:space": "cosine"}
        )

    @property
    def count(self) -> int:
        return self.collection.count()
