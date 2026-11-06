"""Tests for SOCSignal detection rules."""

from pathlib import Path

import pytest

from socsignal.detections import detect_failed_logon_bursts
from socsignal.reader import read_events

SAMPLE = Path(__file__).resolve().parents[1] / "samples" / "synthetic_events.jsonl"


def test_detects_repeated_failed_logons():
    events = read_events(SAMPLE)

    alerts = detect_failed_logon_bursts(events)

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "SOC-001"
    assert alerts[0]["severity"] == "medium"
    assert alerts[0]["count"] == 3
    assert alerts[0]["record_ids"] == [1001, 1002, 1003]
    assert alerts[0]["source_ip"] == "192.0.2.10"


def test_does_not_alert_below_threshold():
    events = read_events(SAMPLE)[:2]

    alerts = detect_failed_logon_bursts(events)

    assert alerts == []


def test_different_sources_are_not_combined():
    events = read_events(SAMPLE)
    events[2]["event_data"]["source_ip"] = "198.51.100.20"

    alerts = detect_failed_logon_bursts(events)

    assert alerts == []


def test_events_outside_time_window_are_not_combined():
    events = read_events(SAMPLE)
    events[2]["timestamp"] = "2026-11-05T22:40:00Z"

    alerts = detect_failed_logon_bursts(events)

    assert alerts == []


def test_duplicate_event_records_are_not_counted():
    events = read_events(SAMPLE)
    repeated = [events[0], events[1], events[0]]

    alerts = detect_failed_logon_bursts(repeated)

    assert alerts == []


def test_invalid_threshold_is_rejected():
    with pytest.raises(ValueError):
        detect_failed_logon_bursts([], threshold=1)
