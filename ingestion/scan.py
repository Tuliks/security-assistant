"""scan.py — generate the manifest FROM the folder tree instead of by hand.

The manifest is the envelope a report file can't self-describe (product, release,
scanner, date, ...). Writing it by hand doesn't scale to many products x releases
x scanners x weekly drops. But the drop *convention* already encodes most of it:

    data/reports/<product>/<release>/<scanner>/[<date>/]<report.ext>
                  A          Re1        Nessus     2026-W08  hosts.pdf

So a filesystem walk can reconstruct the manifest. `scan_reports()` does exactly
that, returning the same `ReportEnvelope` rows `load_manifest()` produces — so
`ingest.py --scan` is a drop-in alternative to `ingest.py` (which reads the CSV).

Only two fields aren't literally in the path:
  - scan_category / component_type : ~1:1 with the scanner, via SCANNER_PROFILE.
  - scan_date                      : a date *folder* under the scanner, or a date
                                     *in the filename*, or (last resort) file mtime.

Everything else (product, release, scanner, report_file) is a path segment.
"""

from __future__ import annotations

import os
import re
import time
from datetime import datetime

from ingestion.manifest import DATA_DIR, ReportEnvelope

REPORTS_DIR = os.path.join(DATA_DIR, "reports")

# scanner (lowercase) -> (scan_category, component_type). The one domain lookup:
# a scanner produces one kind of finding, so its category/component_type are fixed.
# Add or remove a scanner by editing this table — nothing else changes.
SCANNER_PROFILE: dict[str, tuple[str, str]] = {
    "blackduck": ("SCA", "repository"),
    "nessus": ("HOST", "host"),
    "twistlock": ("CONTAINER", "container_image"),
    "gitleaks": ("SECRET", "repository"),
    "checkmarx": ("SAST", "repository"),
    # kept because the existing sample corpus uses it:
    "trivy": ("SCA", "repository"),
}

# A YYYY-MM-DD (separators optional) or an ISO week YYYY-Www, anywhere in a segment.
_DATE_RE = re.compile(r"(?<!\d)(20\d{2})[-_.]?(0[1-9]|1[0-2])[-_.]?(0[1-9]|[12]\d|3[01])(?!\d)")
_WEEK_RE = re.compile(r"(?<!\d)(20\d{2})[-_]?[Ww](0[1-9]|[1-4]\d|5[0-3])(?!\d)")
# a trailing version token to peel off a component name, e.g. "-2.4.0" or "_v1.2"
_VERSION_RE = re.compile(r"[-_]v?(\d+(?:\.\d+)+)$")


def extract_date(segment: str) -> str | None:
    """Pull an ISO date out of a path segment (folder name or filename). None if absent.

    A plain date wins over a week number if both appear. Week 'YYYY-Www' resolves to
    that ISO week's Monday, so scan_date is always a concrete 'YYYY-MM-DD'.
    """
    m = _DATE_RE.search(segment)
    if m:
        return f"{m.group(1)}-{m.group(2)}-{m.group(3)}"
    w = _WEEK_RE.search(segment)
    if w:
        # %G-%V-%u : ISO year / week / weekday(1=Mon) -> the Monday of that week.
        return datetime.strptime(f"{w.group(1)}-W{w.group(2)}-1", "%G-W%V-%u").date().isoformat()
    return None


def _mtime_date(path: str) -> str:
    return time.strftime("%Y-%m-%d", time.localtime(os.path.getmtime(path)))


def parse_component(filename: str) -> tuple[str, str]:
    """Best-effort (name, version) from a report filename, minus date + extension.

    'payments-api-2.4.0.csv'      -> ('payments-api', '2.4.0')
    'mcp-cce-2026-02-24.csv'      -> ('mcp-cce', '')       (date stripped, no version)
    'edna-hosts.html'             -> ('edna-hosts', '')
    """
    stem = os.path.splitext(filename)[0]
    # strip any date/week token so it isn't mistaken for a version
    stem = _DATE_RE.sub("", stem)
    stem = _WEEK_RE.sub("", stem)
    stem = stem.strip("-_. ")
    version = ""
    vm = _VERSION_RE.search(stem)
    if vm:
        version = vm.group(1)
        stem = stem[: vm.start()].strip("-_. ")
    return stem, version


def scan_reports(
    reports_root: str = REPORTS_DIR, data_dir: str = DATA_DIR
) -> tuple[list[ReportEnvelope], list[str]]:
    """Walk <reports_root> and derive one ReportEnvelope per report file.

    Convention: <product>/<release>/<scanner>/[<date>/...]/<file.ext>. Anything
    shallower than product/release/scanner is skipped with a warning. Returns
    (envelopes, warnings) so the caller can surface what couldn't be inferred.
    """
    envelopes: list[ReportEnvelope] = []
    warnings: list[str] = []

    for dirpath, _dirs, filenames in os.walk(reports_root):
        for fn in sorted(filenames):
            if fn.startswith("."):
                continue
            abs_path = os.path.join(dirpath, fn)
            parts = os.path.relpath(abs_path, reports_root).split(os.sep)
            if len(parts) < 4:  # product / release / scanner / file  = 4 segments
                warnings.append(
                    f"skip (need product/release/scanner/file, got {len(parts)} levels): "
                    + os.path.relpath(abs_path, data_dir)
                )
                continue

            product, release, scanner = parts[0], parts[1], parts[2]
            middle, filename = parts[3:-1], parts[-1]  # middle = optional date folder(s)

            profile = SCANNER_PROFILE.get(scanner.lower())
            if profile is None:
                category, ctype = "", ""
                warnings.append(
                    f"unknown scanner '{scanner}' (category/component_type left blank; "
                    f"add it to SCANNER_PROFILE): {os.path.relpath(abs_path, data_dir)}"
                )
            else:
                category, ctype = profile

            # date: a date-like folder under the scanner wins, else a date in the
            # filename, else the file's mtime (flagged — the path told us nothing).
            scan_date = next((d for d in (extract_date(s) for s in middle) if d), None)
            scan_date = scan_date or extract_date(filename)
            if not scan_date:
                scan_date = _mtime_date(abs_path)
                warnings.append(
                    f"no date in path; using file mtime {scan_date}: "
                    + os.path.relpath(abs_path, data_dir)
                )

            # host scans aren't about one component; per-row component comes from the mapper.
            cname, cver = ("", "") if ctype == "host" else parse_component(filename)

            envelopes.append(
                ReportEnvelope(
                    report_file=os.path.relpath(abs_path, data_dir),
                    product_name=product,
                    release_version=release,
                    scanner=scanner,
                    scan_category=category,
                    scan_date=scan_date,
                    component_name=cname,
                    component_version=cver,
                    component_type=ctype,
                    mapper="",  # defaults to scanner; override only for oddballs (lab_json)
                )
            )

    envelopes.sort(key=lambda e: e.report_file)
    return envelopes, warnings


# manifest.csv column order, kept in one place so write_manifest and the reader agree.
MANIFEST_COLUMNS = [
    "report_file", "product_name", "release_version", "scanner", "scan_category",
    "scan_date", "component_name", "component_version", "component_type", "mapper",
]


def write_manifest(envelopes: list[ReportEnvelope], path: str) -> None:
    """Write envelopes out as a manifest.csv (for review/editing before ingest)."""
    import csv

    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=MANIFEST_COLUMNS)
        w.writeheader()
        for e in envelopes:
            w.writerow({c: getattr(e, c) for c in MANIFEST_COLUMNS})
