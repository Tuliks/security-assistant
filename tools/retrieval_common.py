"""Shared retrieval primitives — used by both retrieval paths.

Extracted from rag_search so the in-memory hybrid index (rag_search, the eval
mechanics demo) and the persistent-store hybrid (ingestion/store, what the agent
queries) share ONE definition of the security-shorthand expansions, the lexical
tokenizer, and Reciprocal Rank Fusion. One corpus, one retrieval vocabulary.
"""

from __future__ import annotations

import re

_WORD = re.compile(r"[a-z0-9]+")
RRF_K = 60  # standard RRF constant; damps the weight of very high ranks

# Connectors carry no lexical signal but appear in many finding texts, so BM25
# would otherwise "match" an off-topic query on a shared "in"/"the". Dropped from
# the lexical side only (the semantic side embeds full sentences).
STOPWORDS = frozenset(
    "a an and are as at be but by for from how i if in into is it its of on or "
    "that the their this to via was were what when where which who with your our "
    "do does can could would should you we they he she them us".split()
)

# Analysts type acronyms/shorthand ("sqli", "creds", "rce") that finding text
# spells out. BM25 tokenizes "sqli" and "sql"/"injection" differently, so the
# lexical side misses; expanding the query bridges the gap. Deterministic (no LLM).
EXPANSIONS = {
    "rce": "remote code execution",
    "sqli": "sql injection",
    "xss": "cross site scripting",
    "ssrf": "server side request forgery",
    "csrf": "cross site request forgery",
    "xxe": "xml external entity",
    "cred": "credentials",
    "creds": "credentials",
    "mfa": "multi factor authentication",
    "2fa": "two factor authentication",
    "privesc": "privilege escalation",
    "log4shell": "log4j remote code execution",
    "heartbleed": "openssl memory disclosure",
    "exfil": "exfiltration",
    "misconfig": "misconfiguration",
    "dep": "dependency",
    "deps": "dependencies",
    "vuln": "vulnerability",
    "vulns": "vulnerabilities",
}


def tokens(text: str) -> list[str]:
    return _WORD.findall(text.lower())


def content_tokens(text: str) -> list[str]:
    """Tokens with stopwords removed — the lexical (BM25) view of a text."""
    return [t for t in _WORD.findall(text.lower()) if t not in STOPWORDS]


def expand_query(query: str) -> str:
    """Append spelled-out forms of any security acronyms/shorthand in the query.

    Original terms are kept (exact matches still fire) and expansions are added. A
    query with no known shorthand is returned unchanged — so out-of-scope queries
    don't gain spurious terms and the abstention path is preserved.
    """
    lower = query.lower()
    extra = [
        exp for term, exp in EXPANSIONS.items() if re.search(rf"\b{re.escape(term)}\b", lower)
    ]
    return f"{query} {' '.join(extra)}" if extra else query


def rrf(rankings: list[list[str]], k: int = RRF_K) -> list[str]:
    """Fuse ranked id-lists with Reciprocal Rank Fusion, best first.

    score(id) = Σ 1 / (k + rank), rank starting at 1. Rank-based, so it doesn't
    matter that the arms report scores on different scales. An id in either list
    is kept.
    """
    scores: dict[str, float] = {}
    for ranking in rankings:
        for rank, fid in enumerate(ranking, start=1):
            scores[fid] = scores.get(fid, 0.0) + 1.0 / (k + rank)
    return sorted(scores, key=lambda fid: scores[fid], reverse=True)
