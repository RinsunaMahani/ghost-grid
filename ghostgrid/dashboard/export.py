"""Evidence export for the SOC console: full-detail records as CSV for an incident report.

The console's tables are trimmed for reading (short session IDs, local clock times, the latest
rows only). An export keeps everything: full session IDs, every column the database holds, and
times in UTC ISO 8601 so they line up with the same alerts in the SIEM.
"""
import csv
import io
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List

TIME_FIELDS = ("timestamp", "started_at", "last_seen")


def utc_iso(ts: Any) -> str:
    if not isinstance(ts, (int, float)) or not ts:
        return ""
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def evidence_csv(rows: Iterable[Dict[str, Any]]) -> bytes:
    """Rows as CSV bytes, every column kept, epoch times turned into UTC ISO 8601."""
    rows: List[Dict[str, Any]] = [
        {k: (utc_iso(v) if k in TIME_FIELDS else v) for k, v in dict(r).items()} for r in rows
    ]
    columns: List[str] = []
    for r in rows:                           # union of columns, in first-seen order
        columns.extend(k for k in r if k not in columns)
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=columns, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    # A BOM so Excel opens accented site and description text correctly.
    return ("﻿" + out.getvalue()).encode("utf-8")
