"""Typed contracts for the security assistant.

Same two-layer validation as the travel lab (single-agent-lab/schemas.py):

  1. Schema validation (automatic) — every type hint becomes JSON Schema the
     model must satisfy for tool arguments AND the final answer.
  2. Business-logic validation (manual) — things a type can't express are caught
     by raising `ModelRetry(...)` inside a tool or an @agent.output_validator.

The load-bearing idea here: the model may DECIDE which findings and CVEs to
investigate, but it may NOT invent a CVSS score, KEV status, or remediation from
its weights. Those come back as typed tool results (`CVEIntel`, `RiskScore`,
`RemediationPlaybook`) that only a tool call can produce — "step N's input
depends on step N-1's output," enforced by types.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info"]


class Finding(BaseModel):
    """One security finding, as ingested from a scanner report in data/."""

    id: str = Field(description="Stable finding id, e.g. 'GL-001'")
    scanner: str = Field(description="Which tool produced it, e.g. 'gitleaks', 'trivy', 'nessus'")
    severity: Severity
    title: str
    description: str
    asset: str = Field(description="The affected repo, image, or host")
    category: str | None = Field(
        default=None,
        description="Finding class for remediation lookup, e.g. 'exposed_secret', 'vulnerable_dependency'",
    )
    cve: str | None = Field(default=None, description="Associated CVE id if any, e.g. 'CVE-2021-44228'")
    cvss: float | None = Field(default=None, ge=0, le=10, description="Base CVSS score if the scanner reported one")
    location: str | None = Field(default=None, description="File/line, package version, or port")


class CVEIntel(BaseModel):
    """External enrichment for one CVE. Output of cve_lookup() — the un-fakeable tool.

    The model cannot produce CVSS/KEV status from its weights; it must call the
    tool, observe this, and feed it forward (e.g. into calculate_risk).
    """

    cve_id: str
    description: str
    cvss_v3: float | None = Field(default=None, ge=0, le=10)
    severity: str | None = Field(default=None, description="NVD severity band, e.g. 'CRITICAL'")
    kev_listed: bool = Field(description="True if the CVE is in CISA's Known Exploited Vulnerabilities catalog")
    affected: list[str] = Field(default_factory=list, description="Affected products/versions if listed")
    patch_guidance: str | None = Field(default=None)
    references: list[str] = Field(default_factory=list)


class RiskScore(BaseModel):
    """A computed risk score. Output of calculate_risk() — deterministic, not the model's guess."""

    score: float = Field(ge=0, le=10)
    band: str = Field(description="'critical' | 'high' | 'medium' | 'low'")
    rationale: str = Field(description="How the inputs (CVSS, KEV, exposure) produced the score")


class RemediationPlaybook(BaseModel):
    """Actionable fix steps for a finding category. Output of suggest_remediation()."""

    category: str
    steps: list[str] = Field(description="Ordered, concrete remediation steps")
    references: list[str] = Field(default_factory=list)


class AssetExposure(BaseModel):
    """All findings correlated onto ONE asset, across every scanner report.

    Output of correlate_asset() / riskiest_assets() — the graph tools. Scanners
    name the same asset differently (`payments-api`, `payments-api:latest`,
    `payments-api (10.0.4.21)`); this is the view AFTER normalizing them to one
    canonical node, so a single-finding search can't produce it — only a
    correlation over the graph can. The model may cite it but not invent it.
    """

    asset: str = Field(description="Canonical (normalized) asset name")
    findings: list[Finding] = Field(description="Every finding on this asset, across scanners")
    scanners: list[str] = Field(default_factory=list, description="Distinct scanners that flagged this asset")
    finding_count: int
    max_cvss: float | None = Field(default=None, ge=0, le=10, description="Highest CVSS among the asset's findings")
    has_exposed_secret: bool = Field(description="An exposed_secret finding is present")
    has_vulnerability: bool = Field(description="An exploitable vuln (CVE-bearing dep or injection) is present")
    compound_risk: bool = Field(
        description="Secret AND exploitable vuln co-located on this asset — worse than either alone"
    )
    rationale: str = Field(description="How the correlated findings produced this exposure view")


# The final output is a UNION: succeed with an answer, or abstain and ask.
# output_type=[SecurityAnswer, NeedMoreInfo] lets the model return NeedMoreInfo
# when no ingested report data supports a grounded answer — enforced by the type
# system, not by hope.


class SecurityAnswer(BaseModel):
    """A grounded answer to a security question. Every claim should trace to a tool result."""

    message: str = Field(description="The analyst-style answer, grounded in the tool results")
    findings_cited: list[Finding] = Field(
        default_factory=list, description="Findings from the reports that support the answer"
    )
    cves: list[str] = Field(default_factory=list, description="CVE ids referenced in the answer")
    tools_used: list[str] = Field(description="Names of the tools called to produce this answer")
    summary_data: dict | None = Field(
        default=None, description="Optional structured numbers, e.g. {'critical': 3, 'avg_cvss': 8.1}"
    )


class NeedMoreInfo(BaseModel):
    """Return this INSTEAD of an answer when the request can't be grounded in the reports.

    No matching findings, an out-of-scope question, or a tool that kept failing —
    say so and ask, rather than fabricating a plausible-looking answer.
    """

    question: str = Field(description="The one thing you need from the user to proceed")
    reason: str = Field(description="Why you could not answer from the report data and tools alone")
