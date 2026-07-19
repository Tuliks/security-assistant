"""asset_graph — cross-report correlation (Graph RAG over the findings).

rag_search retrieves findings one at a time. But the real risk in this corpus is
*relational*: several findings, from different scanners, landing on the SAME
asset. A leaked credential (Gitleaks) plus a SQL-injection vuln (Nessus) on the
same service is a compound breach path — worse than either finding read alone,
and invisible to any single-finding search.

The obstacle the data hands us: scanners name the same asset differently —
`payments-api` (Gitleaks), `payments-api:latest` (Trivy),
`payments-api (10.0.4.21)` (Nessus). Nothing correlates until those collapse to
one canonical node. So `normalize_asset` is the load-bearing piece here, not a
detail: it's what turns three strings into one graph node.

Same seam discipline as rag_search: this ADDS tools, it doesn't change existing
ones. The graph is built once from load_findings() and cached (module-level lazy
singleton), like _HybridIndex.
"""

from __future__ import annotations

import re

from pydantic_ai import ModelRetry

from schemas import AssetExposure, Finding
from tools.corpus import load_findings

# Categories that represent an exploitable weakness (vs. a leaked secret or a
# passive misconfiguration). Used to detect the compound-risk pattern.
_VULN_CATEGORIES = frozenset({"vulnerable_dependency", "sql_injection"})

_PARENS = re.compile(r"\s*\(.*?\)")  # " (10.0.4.21)" host/ip annotation Nessus appends


def normalize_asset(asset: str) -> str:
    """Collapse a scanner's asset string to one canonical node.

    Strips the ` (ip/host)` annotation Nessus adds and the `:tag` Trivy adds to
    image names, then lowercases. All three of `payments-api`,
    `payments-api:latest`, `payments-api (10.0.4.21)` -> `payments-api`.
    """
    s = _PARENS.sub("", asset)  # drop " (10.0.4.21)"
    s = s.split(":", 1)[0]  # drop ":latest" / ":5.6.1"
    return s.strip().lower()


# --- The graph --------------------------------------------------------------
# Nodes: assets and categories. Edges: a finding's membership in each. Small and
# in-memory (the corpus is ~10 findings); the value is the correlation, not scale.


class _AssetGraph:
    def __init__(self, findings: list[Finding]) -> None:
        self.assets: dict[str, list[Finding]] = {}
        self.by_category: dict[str, list[Finding]] = {}
        for f in findings:
            self.assets.setdefault(normalize_asset(f.asset), []).append(f)
            if f.category:
                self.by_category.setdefault(f.category, []).append(f)
        # NOTE: a `same_cve` edge is part of the Graph-RAG idea but does NOT fire
        # on this corpus — every CVE here is unique. Kept as a documented gap
        # rather than a pretend feature; it would light up on a larger corpus.

    def canonical_assets(self) -> list[str]:
        return sorted(self.assets)

    def resolve(self, asset: str) -> str | None:
        """Map a user/model-supplied asset to a canonical node.

        Exact normalized match first; otherwise substring either direction, so
        "payments" or "payments-api:latest" both find "payments-api". Ambiguous
        or unknown -> None (the caller turns that into a guided ModelRetry).
        """
        target = normalize_asset(asset)
        if not target:
            return None
        if target in self.assets:
            return target
        matches = [a for a in self.assets if target in a or a in target]
        return matches[0] if len(matches) == 1 else None

    def exposure(self, canonical: str) -> AssetExposure:
        """Build the correlated exposure view for one canonical asset."""
        findings = self.assets[canonical]
        scanners = sorted({f.scanner for f in findings})
        cvss_vals = [f.cvss for f in findings if f.cvss is not None]
        max_cvss = max(cvss_vals) if cvss_vals else None

        has_secret = any(f.category == "exposed_secret" for f in findings)
        has_vuln = any(
            (f.category in _VULN_CATEGORIES) or (f.cve is not None) for f in findings
        )
        compound = has_secret and has_vuln

        parts = [
            f"{len(findings)} finding(s) on '{canonical}' across {', '.join(scanners)}"
        ]
        if max_cvss is not None:
            parts.append(f"max CVSS {max_cvss}")
        if compound:
            parts.append("COMPOUND: an exposed secret and an exploitable vulnerability share this asset")
        elif has_secret:
            parts.append("exposed secret present")
        elif has_vuln:
            parts.append("exploitable vulnerability present")

        return AssetExposure(
            asset=canonical,
            findings=findings,
            scanners=scanners,
            finding_count=len(findings),
            max_cvss=max_cvss,
            has_exposed_secret=has_secret,
            has_vulnerability=has_vuln,
            compound_risk=compound,
            rationale="; ".join(parts),
        )

    def exposure_score(self, canonical: str) -> float:
        """An explainable ranking key for riskiest_assets (not a CVSS itself).

        max_cvss carries the weight; +1 per extra co-located finding (blast
        radius); +2 if the compound secret+vuln pattern is present.
        """
        exp = self.exposure(canonical)
        score = exp.max_cvss or 0.0
        score += max(0, exp.finding_count - 1)
        if exp.compound_risk:
            score += 2.0
        return score


_GRAPH: _AssetGraph | None = None


def _get_graph() -> _AssetGraph:
    global _GRAPH
    if _GRAPH is None:
        _GRAPH = _AssetGraph(load_findings())
    return _GRAPH


# --- Tools ------------------------------------------------------------------


def correlate_asset(asset: str) -> AssetExposure:
    """Show EVERY finding on one asset, correlated across all scanner reports.

    Use this for "what's the full exposure on <asset>?" or to check whether one
    asset carries several problems at once. Scanners name assets inconsistently
    (`payments-api`, `payments-api:latest`, `payments-api (10.0.4.21)`); this
    normalizes them, so you get the complete picture a per-finding search misses.

    Args:
        asset: An asset/repo/image/host name (any scanner's spelling, or a prefix).
    """
    if not asset or not asset.strip():
        raise ModelRetry("Empty asset. Pass a repo/image/host name to correlate findings for.")
    graph = _get_graph()
    canonical = graph.resolve(asset)
    if canonical is None:
        known = ", ".join(graph.canonical_assets())
        raise ModelRetry(f"No asset matches {asset!r}. Known assets: {known}.")
    return graph.exposure(canonical)


def riskiest_assets(limit: int = 5) -> list[AssetExposure]:
    """Rank assets by combined exposure across all reports, riskiest first.

    Use for "which asset is riskiest?" or "where should we focus?". Ranking
    accounts for the worst CVSS on the asset, how many findings pile onto it, and
    whether a leaked secret and an exploitable vuln co-locate (compound risk).

    Args:
        limit: Max assets to return (1-20, default 5).
    """
    if limit <= 0 or limit > 20:
        raise ModelRetry(f"Invalid limit: {limit}. Must be between 1 and 20.")
    graph = _get_graph()
    ranked = sorted(graph.canonical_assets(), key=graph.exposure_score, reverse=True)
    return [graph.exposure(a) for a in ranked[:limit]]
