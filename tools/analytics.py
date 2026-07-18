"""Analytics — deterministic Python tools over the ingested findings.

The point of these (vs. RAG) is to show the agent choosing COMPUTE over
retrieval: counts, averages, extraction, and scoring are things you want a
function to do exactly, not an LLM to estimate. Matches the spec's example tools:
count_critical(), average_cvss(), extract_cves(), calculate_risk().
"""

from __future__ import annotations

import re

from pydantic_ai import ModelRetry

from schemas import RiskScore
from tools.corpus import load_findings

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_VALID_SEVERITIES = ("critical", "high", "medium", "low", "info")


def count_critical(severity: str = "critical") -> int:
    """Count findings across all reports at a given severity.

    Args:
        severity: One of critical/high/medium/low/info (default 'critical').
    """
    sev = severity.lower()
    if sev not in _VALID_SEVERITIES:
        raise ModelRetry(f"Invalid severity {severity!r}. Use one of: {', '.join(_VALID_SEVERITIES)}.")
    return sum(1 for f in load_findings() if f.severity == sev)


def average_cvss() -> float:
    """Average CVSS base score across all findings that have one, rounded to 1 dp."""
    scores = [f.cvss for f in load_findings() if f.cvss is not None]
    if not scores:
        raise ModelRetry("No findings carry a CVSS score, so an average can't be computed.")
    return round(sum(scores) / len(scores), 1)


def extract_cves(text: str) -> list[str]:
    """Extract unique CVE identifiers (CVE-YYYY-NNNN...) from arbitrary text.

    Use on a report snippet or a user's pasted text to pull out CVE ids before
    enriching them with cve_lookup.

    Args:
        text: Free text that may contain CVE identifiers.
    """
    if not text or not text.strip():
        raise ModelRetry("Empty text. Pass the text you want to scan for CVE identifiers.")
    seen: list[str] = []
    for match in _CVE_RE.findall(text):
        cve = match.upper()
        if cve not in seen:
            seen.append(cve)
    return seen


def calculate_risk(cvss: float, kev_listed: bool = False, internet_facing: bool = False) -> RiskScore:
    """Compute a prioritization risk score from a CVSS base score plus context.

    Pure computation — deterministic, not the model's guess. Known exploitation
    (KEV) and internet exposure escalate the raw CVSS.

    Args:
        cvss: Base CVSS score (0-10).
        kev_listed: True if the CVE is in CISA's Known Exploited Vulnerabilities catalog.
        internet_facing: True if the affected asset is exposed to the internet.
    """
    if cvss < 0 or cvss > 10:
        raise ModelRetry(f"Invalid cvss {cvss}. Must be between 0 and 10.")

    score = cvss
    reasons = [f"base CVSS {cvss}"]
    if kev_listed:
        score = min(10.0, score + 1.5)
        reasons.append("+1.5 known-exploited (CISA KEV)")
    if internet_facing:
        score = min(10.0, score + 0.5)
        reasons.append("+0.5 internet-facing")
    score = round(score, 1)

    band = "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"
    return RiskScore(score=score, band=band, rationale="; ".join(reasons) + f" → {score} ({band})")
