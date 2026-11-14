from __future__ import annotations

import csv
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from .models import Event


def _event(record: dict[str, Any], source_record: int) -> Event:
    try:
        timestamp = datetime.fromisoformat(str(record["timestamp"]).replace("Z", "+00:00"))
        event_id = int(record["event_id"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"Invalid record {source_record}: timestamp and event_id are required") from exc

    return Event(
        timestamp=timestamp,
        event_id=event_id,
        computer=str(record.get("computer", "")).strip(),
        user=str(record.get("user", "")).strip(),
        source_ip=str(record.get("source_ip", "")).strip(),
        outcome=str(record.get("outcome", "")).strip().lower(),
        action=str(record.get("action", "")).strip(),
        details=str(record.get("details", "")).strip(),
        source_record=source_record,
    )


def parse_events(path: str | Path) -> list[Event]:
    source = Path(path)
    suffix = source.suffix.lower()

    if suffix == ".csv":
        with source.open("r", encoding="utf-8-sig", newline="") as handle:
            records = list(csv.DictReader(handle))
    elif suffix == ".json":
        with source.open("r", encoding="utf-8") as handle:
            records = json.load(handle)
        if not isinstance(records, list) or not all(isinstance(item, dict) for item in records):
            raise ValueError("JSON evidence must be an array of event objects")
    else:
        raise ValueError("Supported evidence formats are .csv and .json")

    events = [_event(record, index) for index, record in enumerate(records, start=2 if suffix == ".csv" else 1)]
    return sorted(events, key=lambda item: item.timestamp)

