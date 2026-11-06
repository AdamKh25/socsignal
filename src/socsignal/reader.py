"""Read and validate Windows security events from JSONL files."""

import json
from datetime import UTC, datetime
from pathlib import Path

EVENT_LOGS = {
    4625: "Security",
    4720: "Security",
    7045: "System",
}


class EventFormatError(ValueError):
    """An event record does not match the expected format."""


def read_events(path: str | Path) -> list[dict]:
    """Load supported Windows events and normalize timestamps to UTC."""
    events = []

    with Path(path).open(encoding="utf-8-sig") as source:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise EventFormatError(f"line {line_number}: invalid JSON") from exc

            if not isinstance(record, dict):
                raise EventFormatError(f"line {line_number}: expected a JSON object")

            event_id = record.get("event_id")
            if type(event_id) is not int or event_id not in EVENT_LOGS:
                raise EventFormatError(f"line {line_number}: unsupported event_id")

            if record.get("log_name") != EVENT_LOGS[event_id]:
                raise EventFormatError(f"line {line_number}: incorrect event log")

            timestamp = record.get("timestamp")
            if not isinstance(timestamp, str):
                raise EventFormatError(
                    f"line {line_number}: missing or invalid timestamp"
                )

            try:
                parsed = datetime.fromisoformat(timestamp)
            except ValueError as exc:
                raise EventFormatError(
                    f"line {line_number}: invalid timestamp"
                ) from exc

            if parsed.tzinfo is None or parsed.utcoffset() is None:
                raise EventFormatError(
                    f"line {line_number}: timestamp requires timezone"
                )

            record_id = record.get("record_id")
            if type(record_id) is not int or record_id < 1:
                raise EventFormatError(f"line {line_number}: invalid record_id")

            computer = record.get("computer")
            if not isinstance(computer, str) or not computer.strip():
                raise EventFormatError(f"line {line_number}: invalid computer")

            event_data = record.get("event_data")
            if not isinstance(event_data, dict):
                raise EventFormatError(f"line {line_number}: invalid event_data")

            events.append(
                {
                    "event_id": event_id,
                    "log_name": record["log_name"],
                    "timestamp": parsed.astimezone(UTC)
                    .isoformat()
                    .replace("+00:00", "Z"),
                    "record_id": record_id,
                    "computer": computer,
                    "event_data": event_data,
                }
            )

    return events
