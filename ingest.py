"""ingest.py — walk the manifest, parse every report, upsert the vector records.

    manifest.csv row --> parse(file) --> map_report(rows) --> build_record --> ReportStore.upsert
                         (by extension)   (by scanner)        ({id,text,metadata})

This is the production replacement for the legacy "load data/*.json in-memory"
path. It handles many products / scanners / dated reports and many file formats
(CSV, Excel, HTML, JSON), and it's idempotent: re-running upserts by stable id
instead of duplicating.

Usage:
    python ingest.py                # incremental upsert of everything in the manifest
    python ingest.py --reset        # drop the collection first, then full re-ingest
    python ingest.py --dry-run      # parse + map + build, but don't write to the store
    python ingest.py --scan         # derive the manifest from the folder tree, then ingest
    python ingest.py --scan --write-manifest data/manifest.csv   # ... and save it for review
"""

from __future__ import annotations

import argparse
import sys

from ingestion.manifest import ReportEnvelope, load_manifest
from ingestion.mappers import map_report
from ingestion.parsers import parse
from ingestion.record_builder import build_record
from ingestion.scan import scan_reports, write_manifest
from ingestion.store import ReportStore


def ingest(
    reset: bool = False,
    dry_run: bool = False,
    envelopes: list[ReportEnvelope] | None = None,
) -> int:
    if envelopes is None:
        envelopes = load_manifest()
    print(f"Manifest: {len(envelopes)} report(s)\n")

    store = None
    if not dry_run:
        store = ReportStore()
        if reset:
            store.reset()
            print("Reset: collection cleared.\n")

    total = 0
    for env in envelopes:
        label = f"{env.product_name} / {env.scanner} / {env.basename}"
        try:
            rows = parse(env.abs_path)
            records = [build_record(r) for r in map_report(rows, env)]
        except Exception as exc:  # a bad report shouldn't abort the whole ingest
            print(f"  ✗ {label}: {type(exc).__name__}: {exc}")
            continue

        if not dry_run:
            store.upsert(records)
        total += len(records)
        print(f"  ✓ {label}: {len(rows)} row(s) -> {len(records)} record(s)")

    tail = "" if dry_run else f"  (store now holds {store.count} record(s))"
    print(f"\nIngested {total} record(s).{tail}")
    return total


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Ingest scanner reports into the vector store.")
    ap.add_argument("--reset", action="store_true", help="clear the collection before ingesting")
    ap.add_argument("--dry-run", action="store_true", help="parse/map/build but don't write")
    ap.add_argument("--scan", action="store_true",
                    help="derive the manifest from data/reports/<product>/<release>/<scanner>/ "
                         "instead of reading manifest.csv")
    ap.add_argument("--write-manifest", metavar="PATH",
                    help="with --scan: write the derived manifest to PATH for review")
    args = ap.parse_args(argv)

    envelopes = None
    if args.scan:
        envelopes, warnings = scan_reports()
        for w in warnings:
            print(f"  ! {w}")
        print(f"Scanned folder tree: {len(envelopes)} report(s) derived.\n")
        if args.write_manifest:
            write_manifest(envelopes, args.write_manifest)
            print(f"Wrote manifest -> {args.write_manifest}\n")
    elif args.write_manifest:
        ap.error("--write-manifest requires --scan")

    ingest(reset=args.reset, dry_run=args.dry_run, envelopes=envelopes)
    return 0


if __name__ == "__main__":
    sys.exit(main())
