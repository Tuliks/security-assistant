"""Per-scanner mappers: raw rows (+ envelope) -> RecordMetadata.

This is where the messy production reality lives. Trivy calls the finding id
`VulnerabilityID`, Nessus calls it `Plugin ID`, Twistlock calls it `CVE`; the CVSS
column is `Score` / `CVSS v3.0 Base Score` / `CVSS`. Each mapper knows its own
scanner's columns and maps them onto the one canonical shape. Envelope fields
(product, release, scan_date, ...) are stamped on every record from the manifest.

Register a new scanner by writing `map_<scanner>(row, env) -> RecordMetadata | None`
(return None to drop a row) and adding it to MAPPERS. Lookup is case-insensitive
on the manifest's `scanner` value.
"""

from __future__ import annotations

from ingestion.manifest import ReportEnvelope
from ingestion.mappers.common import extract_cves, first, normalize_severity, parse_cvss
from schemas import RecordMetadata


def _base(env: ReportEnvelope, **finding) -> RecordMetadata:
    """Stamp the manifest envelope onto a record; caller supplies finding fields."""
    return RecordMetadata(
        product_name=env.product_name,
        release_version=env.release_version,
        scanner=env.scanner,
        scan_category=env.scan_category,
        scan_date=env.scan_date,
        scan_label=env.scan_label,
        report_file=env.basename,
        component_type=env.component_type,
        **finding,
    )


def map_twistlock(row: dict, env: ReportEnvelope) -> RecordMetadata | None:
    """Twistlock CONTAINER scan: one image (from the manifest), many CVE rows.

    Columns: CVE, Severity, CVSS, Package, Installed Version, Status, Description.
    """
    cve = first(row, "CVE", "cve id")
    cves = extract_cves(cve)
    finding_id = cves[0] if cves else cve
    if not finding_id:
        return None
    return _base(
        env,
        component_name=env.component_name or first(row, "Package"),
        component_version=env.component_version or first(row, "Installed Version", "version"),
        finding_id=finding_id,
        severity=normalize_severity(first(row, "Severity")),
        cvss_score=parse_cvss(first(row, "CVSS")),
        cve_ids=cves,
        status=first(row, "Status", default="new").lower() or "new",
        description=first(row, "Description"),
    )


def map_trivy(row: dict, env: ReportEnvelope) -> RecordMetadata | None:
    """Trivy SCA scan: many packages, each a row.

    Columns: VulnerabilityID, Severity, Score, PkgName, InstalledVersion, Title, CVE.
    """
    vuln_id = first(row, "VulnerabilityID", "Vulnerability ID")
    cves = extract_cves(vuln_id, first(row, "CVE"))
    finding_id = vuln_id or (cves[0] if cves else "")
    if not finding_id:
        return None
    return _base(
        env,
        component_name=first(row, "PkgName", "Package") or env.component_name,
        component_version=first(row, "InstalledVersion", "Installed Version"),
        finding_id=finding_id,
        severity=normalize_severity(first(row, "Severity")),
        cvss_score=parse_cvss(first(row, "Score", "CVSS")),
        cve_ids=cves,
        status="new",
        description=first(row, "Title", "Description"),
    )


def map_nessus(row: dict, env: ReportEnvelope) -> RecordMetadata | None:
    """Nessus HOST scan: findings per host, keyed by plugin.

    Columns: Plugin ID, Risk, CVSS v3.0 Base Score, Host, Name, CVE.
    Nessus rows with Risk 'None' are informational — dropped, not stored.
    """
    # Nessus populates Risk for every real finding; a blank/None Risk is an
    # informational plugin (host discovery, SYN scan) — noise, so drop it.
    # (pandas.read_html maps the literal cell "None" to NaN, hence the blank check.)
    risk = first(row, "Risk")
    if not risk or risk.strip().lower() == "none":
        return None
    plugin = first(row, "Plugin ID", "PluginID")
    cves = extract_cves(first(row, "CVE"))
    finding_id = plugin or (cves[0] if cves else "")
    if not finding_id:
        return None
    return _base(
        env,
        component_name=first(row, "Host", "Host IP") or env.component_name,
        component_version=env.component_version,
        finding_id=finding_id,
        severity=normalize_severity(risk),
        cvss_score=parse_cvss(first(row, "CVSS v3.0 Base Score", "CVSS", "CVSS3 Base Score")),
        cve_ids=cves,
        status="new",
        description=first(row, "Name", "Synopsis", "Description"),
    )


def map_lab_json(row: dict, env: ReportEnvelope) -> RecordMetadata | None:
    """The lab's own JSON finding shape (data/*.json) — a near-passthrough.

    These rows are already close to canonical (id, scanner, severity, title,
    description, asset, category, cve, cvss, location). Mapping them through the
    same pipeline is what folds the original corpus into the unified store, so
    there's one corpus and one retrieval path — not a legacy island beside it.
    """
    fid = first(row, "id")
    if not fid:
        return None
    cve = first(row, "cve")
    return _base(
        env,
        component_name=first(row, "asset") or env.component_name,
        component_version=env.component_version,
        finding_id=fid,
        severity=normalize_severity(first(row, "severity")),
        cvss_score=parse_cvss(first(row, "cvss")),
        cve_ids=extract_cves(cve) if cve else [],
        status="new",
        title=first(row, "title"),
        category=first(row, "category") or None,
        location=first(row, "location") or None,
        description=first(row, "description"),
    )


# --------------------------------------------------------------------------- #
# TODO(scaffold): the three mappers below are SCAFFOLDS. The `first(...)` column
# aliases are informed guesses at each scanner's real headers, NOT verified against
# a live export. Before trusting their output: get one real Blackduck / Checkmarx /
# Gitleaks report, run `python ingest.py --scan --dry-run`, and correct the aliases
# (and add an ingest_eval row-count assertion) so no row is silently dropped or
# mismapped. `--scan` already recognizes these scanners via SCANNER_PROFILE; these
# mappers are the missing piece that turns their rows into records.
# --------------------------------------------------------------------------- #


def map_blackduck(row: dict, env: ReportEnvelope) -> RecordMetadata | None:
    """Blackduck SCA scan: one vulnerable open-source component per row.

    TODO(sample): UNVERIFIED columns — confirm against a real Black Duck
    vulnerability-report export. Common headers: "Vulnerability id" / "CVE",
    "Component name", "Component version", "Security risk" / "Severity",
    "Base score" / "CVSS v3 score", "Description", "Remediation status".
    """
    cve_cell = first(row, "Vulnerability id", "Vulnerability Id", "CVE")
    cves = extract_cves(cve_cell)
    finding_id = cves[0] if cves else cve_cell
    if not finding_id:
        return None
    return _base(
        env,
        component_name=first(row, "Component name", "Component") or env.component_name,
        component_version=first(row, "Component version", "Version"),
        finding_id=finding_id,
        severity=normalize_severity(first(row, "Security risk", "Severity")),
        cvss_score=parse_cvss(first(row, "Base score", "CVSS v3 score", "CVSS")),
        cve_ids=cves,
        status=first(row, "Remediation status", "Status", default="new").lower() or "new",
        description=first(row, "Description"),
    )


def map_checkmarx(row: dict, env: ReportEnvelope) -> RecordMetadata | None:
    """Checkmarx SAST scan: one code-flaw result per row (usually no CVE/CVSS).

    TODO(sample): UNVERIFIED columns — confirm against a real CxSAST export.
    Common headers: "Query" / "Vulnerability" (the rule, e.g. 'SQL_Injection'),
    "Severity", "SrcFileName" / "Source file", "Line", "Result State" / "Status",
    "Category". SAST findings have no CVE and rarely a CVSS, so both stay empty.
    A CxSAST row has no single stable id, so we synthesize one from rule+location.
    """
    query = first(row, "Query", "Vulnerability", "Name")
    if not query:
        return None
    src_file = first(row, "SrcFileName", "Source file", "File", "FileName")
    line = first(row, "Line", "SrcLine", "Node")
    finding_id = " @ ".join(p for p in (query, src_file, line) if p) or query
    location = " : ".join(p for p in (src_file, line) if p) or None
    return _base(
        env,
        component_name=src_file or env.component_name,
        component_version=env.component_version,
        finding_id=finding_id,
        severity=normalize_severity(first(row, "Severity", "Result Severity")),
        cvss_score=None,
        cve_ids=[],
        status=first(row, "Result State", "State", "Status", default="new").lower() or "new",
        title=query,
        category=first(row, "Category", "Query Group") or None,
        location=location,
        description=first(row, "Description", "Query Description"),
    )


def map_gitleaks(row: dict, env: ReportEnvelope) -> RecordMetadata | None:
    """Gitleaks SECRET scan: one leaked-secret hit per row (native gitleaks JSON).

    TODO(sample): UNVERIFIED against a real gitleaks export. Native gitleaks JSON
    keys are typically: "RuleID", "Description", "File", "StartLine", "Commit",
    "Author", "Match". Secrets carry no CVE/CVSS and gitleaks emits no severity,
    so an exposed secret defaults to 'high' by policy. NOTE: the lab's own JSON
    fixture uses `map_lab_json` (via the manifest's `mapper` column) — this mapper
    is for a *real* gitleaks report dropped under `reports/.../Gitleaks/`.
    """
    rule = first(row, "RuleID", "rule", "Rule")
    file = first(row, "File", "file")
    line = first(row, "StartLine", "line", "Line")
    if not rule and not file:
        return None
    finding_id = " @ ".join(p for p in (rule, file, line) if p) or rule or file
    location = " : ".join(p for p in (file, line) if p) or None
    return _base(
        env,
        component_name=file or env.component_name,
        component_version=env.component_version,
        finding_id=finding_id,
        severity=normalize_severity(first(row, "Severity", default="high")),
        cvss_score=None,
        cve_ids=[],
        status="new",
        title=rule or "Exposed secret",
        category="exposed_secret",
        location=location,
        description=first(row, "Description", "Match", "Secret"),
    )


# mapper key -> mapper. Keyed by the manifest's `mapper` column when present,
# otherwise by the lowercased `scanner` value. A `mapper` column lets one scanner
# name have format-specific mappers (e.g. a real Trivy export vs the lab's JSON).
MAPPERS = {
    "twistlock": map_twistlock,
    "trivy": map_trivy,
    "nessus": map_nessus,
    "lab_json": map_lab_json,
    # TODO(scaffold): verify against real exports before relying on these.
    "blackduck": map_blackduck,
    "checkmarx": map_checkmarx,
    "gitleaks": map_gitleaks,
}


class UnknownScanner(ValueError):
    """Raised when the manifest names a scanner/mapper with no registered mapper."""


def map_report(rows: list[dict], env: ReportEnvelope) -> list[RecordMetadata]:
    """Map every row of one report to a record, dropping rows the mapper rejects."""
    key = (env.mapper or env.scanner).lower()
    mapper = MAPPERS.get(key)
    if mapper is None:
        raise UnknownScanner(
            f"No mapper {key!r} for {env.basename}. "
            f"Registered: {', '.join(sorted(MAPPERS))}."
        )
    records: list[RecordMetadata] = []
    for row in rows:
        try:
            rec = mapper(row, env)
        except Exception:
            # One malformed row shouldn't sink the whole report.
            continue
        if rec is not None:
            records.append(rec)
    return records
