"""Tests for noteworthy Windows account and service activity."""

from pathlib import Path

from socsignal.detections import detect_noteworthy_activity
from socsignal.reader import read_events

SAMPLE = Path(__file__).resolve().parents[1] / "samples" / "synthetic_events.jsonl"


def test_detects_account_creation_and_service_installation():
    events = read_events(SAMPLE)
    alerts = detect_noteworthy_activity(events)

    assert len(alerts) == 2
    assert [alert["rule_id"] for alert in alerts] == [
        "SOC-002",
        "SOC-003",
    ]

    assert alerts[0]["target_user"] == "training-account"
    assert alerts[0]["record_ids"] == [1004]
    assert alerts[0]["severity"] == "low"

    assert alerts[1]["service_name"] == "DemoUpdater"
    assert alerts[1]["record_ids"] == [1005]
    assert alerts[1]["severity"] == "low"


def test_ignores_failed_logons():
    events = read_events(SAMPLE)[:3]

    assert detect_noteworthy_activity(events) == []


def test_deduplicates_event_records():
    events = read_events(SAMPLE)

    repeated = [events[3], events[3], events[4], events[4]]

    alerts = detect_noteworthy_activity(repeated)

    assert len(alerts) == 2


def test_skips_events_missing_required_fields():
    events = read_events(SAMPLE)

    events[3]["event_data"]["target_user"] = ""
    events[4]["event_data"]["service_name"] = None

    alerts = detect_noteworthy_activity(events)

    assert alerts == []
