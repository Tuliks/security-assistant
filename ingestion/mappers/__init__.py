"""Scanner mappers — raw report rows -> canonical RecordMetadata."""

from ingestion.mappers.scanners import MAPPERS, UnknownScanner, map_report

__all__ = ["MAPPERS", "UnknownScanner", "map_report"]
