"""rag_search — the internal-retrieval tool (the "R" in RAG).

Lightweight stand-in for the spec's semantic search: load the ingested findings,
score each by simple token overlap against the query, and return the best matches.
Deliberately swappable for a ChromaDB semantic query later — same signature,
same typed return.

The model uses this to answer "what findings exist" questions; it must retrieve
before it can cite, so it can't fabricate findings from its weights.
"""

from __future__ import annotations

import re

from pydantic_ai import ModelRetry

from schemas import Finding, Severity
from tools.corpus import load_findings

_WORD = re.compile(r"[a-z0-9]+")
_VALID_SEVERITIES = ("critical", "high", "medium", "low", "info")


def _tokens(text: str) -> set[str]:
    return set(_WORD.findall(text.lower()))


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

    findings = load_findings()
    if severity is not None:
        sev = severity.lower()
        findings = [f for f in findings if f.severity == sev]

    q_tokens = _tokens(query)
    scored: list[tuple[float, Finding]] = []
    for f in findings:
        haystack = _tokens(" ".join(filter(None, [f.title, f.description, f.asset, f.category, f.cve])))
        overlap = len(q_tokens & haystack)
        if overlap:
            # Normalize by query size so short queries aren't penalized.
            scored.append((overlap / max(len(q_tokens), 1), f))

    if not scored:
        # Business-empty is not an error — an empty list lets the model decide to
        # abstain (NeedMoreInfo) rather than being forced to retry a valid query.
        return []

    scored.sort(key=lambda pair: pair[0], reverse=True)
    return [f for _, f in scored[:limit]]
