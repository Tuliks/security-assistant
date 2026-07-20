"""The manifest — envelope metadata a report file can't self-describe.

A Trivy Excel export lists CVEs and packages, but nothing inside it says "this is
product Ivan, release Edna, scanned 2026-02-24 by Trivy." That envelope has to
come from somewhere; data/manifest.csv is the source of truth, one row per report
file. This decouples "what's in the file" (parsed) from "which product/scan it
belongs to" (declared).

manifest.csv columns:
    report_file        path relative to data/ (e.g. reports/Ivan/Trivy/payments-api.xlsx)
    product_name       e.g. Ivan
    release_version    e.g. Edna(01.02.00.00)   (may be blank)
    scanner            e.g. Trivy               -> selects the mapper
    scan_category      e.g. SCA | CONTAINER | HOST | SAST | SECRET
    scan_date          YYYY-MM-DD
    component_name     default component if the report is about one thing (may be blank)
    component_version  default version                                    (may be blank)
    component_type     e.g. container_image | repository | host
    mapper             OPTIONAL — mapper override; defaults to `scanner`. Lets one
                       scanner name have format-specific mappers (e.g. 'lab_json').
"""

from __future__ import annotations

import csv
import os
from dataclasses import dataclass

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
MANIFEST_PATH = os.path.join(DATA_DIR, "manifest.csv")


@dataclass
class ReportEnvelope:
    """One manifest row: everything about a report except its findings."""

    report_file: str            # path relative to data/
    product_name: str
    release_version: str
    scanner: str
    scan_category: str
    scan_date: str              # YYYY-MM-DD
    component_name: str
    component_version: str
    component_type: str
    mapper: str = ""            # optional mapper override; "" -> use scanner

    @property
    def abs_path(self) -> str:
        return os.path.join(DATA_DIR, self.report_file)

    @property
    def basename(self) -> str:
        return os.path.basename(self.report_file)

    @property
    def scan_label(self) -> str:
        """Display label: scan_date reformatted DD-MM-YYYY (matches the record shape)."""
        try:
            y, m, d = self.scan_date.split("-")
            return f"{d}-{m}-{y}"
        except ValueError:
            return self.scan_date


def load_manifest(path: str = MANIFEST_PATH) -> list[ReportEnvelope]:
    """Read manifest.csv into ReportEnvelope rows. Blank/comment lines skipped."""
    envelopes: list[ReportEnvelope] = []
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            if not row.get("report_file", "").strip() or row["report_file"].lstrip().startswith("#"):
                continue
            envelopes.append(
                ReportEnvelope(
                    report_file=row["report_file"].strip(),
                    product_name=row.get("product_name", "").strip(),
                    release_version=row.get("release_version", "").strip(),
                    scanner=row.get("scanner", "").strip(),
                    scan_category=row.get("scan_category", "").strip(),
                    scan_date=row.get("scan_date", "").strip(),
                    component_name=row.get("component_name", "").strip(),
                    component_version=row.get("component_version", "").strip(),
                    component_type=row.get("component_type", "").strip(),
                    mapper=row.get("mapper", "").strip(),
                )
            )
    return envelopes
