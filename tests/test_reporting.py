"""Tests for SOCSignal triage report generation."""

from pathlib import Path

from socsignal.reader import read_events
from socsignal.reporting import build_triage_report

SAMPLE = Path(__file__).resolve().parents[1] / "samples" / "synthetic_events.jsonl"


def test_report_includes_summary_and_audit_counts():
    report = build_triage_report(read_events(SAMPLE))

    assert "Events analyzed: 5" in report
    assert "Alerts requiring review: 3" in report
    assert "Medium-severity alerts: 1" in report
    assert "Low-severity alerts: 2" in report
    assert "Failed logons (4625): 3" in report
    assert "Accounts created (4720): 1" in report
    assert "Services installed (7045): 1" in report


def test_report_includes_all_detection_rules():
    report = build_triage_report(read_events(SAMPLE))

    assert "SOC-001" in report
    assert "SOC-002" in report
    assert "SOC-003" in report

    assert report.index("SOC-001") < report.index("SOC-002")
    assert report.index("SOC-002") < report.index("SOC-003")


def test_report_includes_evidence_and_recommendations():
    report = build_triage_report(read_events(SAMPLE))

    assert "1001, 1002, 1003" in report
    assert "2026-11-05T22:30:00Z" in report
    assert "192.0.2.10" in report
    assert "Recommended investigation" in report


def test_report_handles_no_alerts():
    events = read_events(SAMPLE)[:1]

    report = build_triage_report(events)

    assert "Alerts requiring review: 0" in report
    assert "No detection rules matched" in report


def test_report_sanitizes_event_text_and_excludes_unknown_fields():
    events = read_events(SAMPLE)

    events[4]["event_data"]["service_name"] = "DemoService\n## Forged heading | value"
    events[4]["event_data"]["private_field"] = "DO_NOT_INCLUDE"

    report = build_triage_report(events)

    assert "DemoService ## Forged heading \\| value" in report
    assert "\n## Forged heading" not in report
    assert "DO_NOT_INCLUDE" not in report
