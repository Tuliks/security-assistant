"""cve_lookup — the external threat-intelligence tool (the un-fakeable link).

Mirrors single-agent-lab/tools/geocode.py exactly in shape: an httpx call to a
free, keyless public API (NIST NVD), with ModelRetry on transient failure or a
business-invalid input. The model CANNOT produce a real CVSS score or KEV status
from its weights — it has to call this, observe the result, and feed it forward
(e.g. into calculate_risk).

NVD API: https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-YYYY-NNNN
KEV status is cross-referenced against a small embedded slice of CISA's catalog
(the full feed would be another fetch; kept local to keep the lab offline-friendly).
"""

from __future__ import annotations

import re

import httpx

from pydantic_ai import ModelRetry
from schemas import CVEIntel

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

# A small local slice of CISA's Known Exploited Vulnerabilities catalog. In the
# full spec this would be a live fetch of the KEV feed.
_KEV_IDS = {
    "CVE-2021-44228",  # Log4Shell
    "CVE-2024-3094",   # xz-utils backdoor
    "CVE-2014-0160",   # Heartbleed
}


async def cve_lookup(cve_id: str) -> CVEIntel:
    """Enrich a CVE with authoritative details from the NIST NVD.

    Returns the official description, CVSS v3 score/severity, affected products,
    references, and whether it is a known-exploited vulnerability (CISA KEV).

    Args:
        cve_id: A CVE identifier, e.g. "CVE-2021-44228".
    """
    cve_id = cve_id.strip().upper()
    if not _CVE_RE.match(cve_id):
        raise ModelRetry(f"{cve_id!r} is not a valid CVE id. Expected form 'CVE-2021-44228'.")

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(NVD_URL, params={"cveId": cve_id})
            resp.raise_for_status()
            vulns = resp.json().get("vulnerabilities") or []
    except httpx.HTTPError as e:
        # Transient (rate limit, 5xx, timeout). Let the model retry, don't crash.
        raise ModelRetry(f"NVD is temporarily unavailable ({type(e).__name__}). Try again.")

    if not vulns:
        raise ModelRetry(f"No NVD record found for {cve_id}. Double-check the id.")

    cve = vulns[0].get("cve", {})

    # Description (prefer English).
    description = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            description = d.get("value", "")
            break

    # CVSS v3.x — NVD nests metrics under cvssMetricV31 / V30.
    cvss_v3: float | None = None
    severity: str | None = None
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0].get("cvssData", {})
            cvss_v3 = data.get("baseScore")
            severity = data.get("baseSeverity") or entries[0].get("baseSeverity")
            break

    affected: list[str] = []
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                crit = match.get("criteria")
                if crit and crit not in affected:
                    affected.append(crit)
    affected = affected[:8]  # keep the observation compact

    references = [r.get("url") for r in cve.get("references", []) if r.get("url")][:8]

    return CVEIntel(
        cve_id=cve_id,
        description=description or "(no description provided by NVD)",
        cvss_v3=cvss_v3,
        severity=severity,
        kev_listed=cve_id in _KEV_IDS,
        affected=affected,
        patch_guidance="Upgrade the affected component to a fixed version; see references." if cvss_v3 else None,
        references=references,
    )
