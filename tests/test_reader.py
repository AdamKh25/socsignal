"""Tests for the SOCSignal JSONL event reader."""

import json
from pathlib import Path

import pytest

from socsignal.reader import EventFormatError, read_events

SAMPLE = Path(__file__).resolve().parents[1] / "samples" / "synthetic_events.jsonl"


def test_reads_synthetic_events():
    events = read_events(SAMPLE)

    assert len(events) == 5
    assert [event["event_id"] for event in events] == [4625, 4625, 4625, 4720, 7045]


def test_normalizes_timestamp_to_utc():
    events = read_events(SAMPLE)

    assert events[0]["timestamp"] == "2026-11-05T22:30:00Z"


def test_rejects_invalid_json(tmp_path):
    path = tmp_path / "bad.jsonl"
    path.write_text("not valid json\n", encoding="utf-8")

    with pytest.raises(EventFormatError, match="invalid JSON"):
        read_events(path)


def test_rejects_wrong_event_log(tmp_path):
    event = read_events(SAMPLE)[-1]
    event["log_name"] = "Security"

    path = tmp_path / "bad_log.jsonl"
    path.write_text(json.dumps(event) + "\n", encoding="utf-8")

    with pytest.raises(EventFormatError, match="incorrect event log"):
        read_events(path)


def test_rejects_timestamp_without_timezone(tmp_path):
    event = read_events(SAMPLE)[0]
    event["timestamp"] = "2026-11-06T00:30:00"

    path = tmp_path / "bad_time.jsonl"
    path.write_text(json.dumps(event) + "\n", encoding="utf-8")

    with pytest.raises(EventFormatError, match="requires timezone"):
        read_events(path)
