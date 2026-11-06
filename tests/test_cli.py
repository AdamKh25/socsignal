"""Tests for the SOCSignal command-line interface."""

from pathlib import Path

import pytest

from socsignal.cli import main

SAMPLE = Path(__file__).resolve().parents[1] / "samples" / "synthetic_events.jsonl"


def test_cli_generates_report(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    result = main([str(SAMPLE)])
    report = tmp_path / "reports" / "triage.md"

    assert result == 0
    assert report.exists()

    content = report.read_text(encoding="utf-8")

    assert "Events analyzed: 5" in content
    assert "Alerts requiring review: 3" in content
    assert "SOC-001" in content
    assert "SOC-002" in content
    assert "SOC-003" in content


def test_cli_accepts_multiple_inputs(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    result = main([str(SAMPLE), str(SAMPLE)])

    content = (tmp_path / "reports" / "triage.md").read_text(encoding="utf-8")

    assert result == 0
    assert "Events analyzed: 10" in content


def test_cli_rejects_invalid_json(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    invalid = tmp_path / "invalid.jsonl"
    invalid.write_text("not valid json\n", encoding="utf-8")

    with pytest.raises(SystemExit) as exc:
        main([str(invalid)])

    assert exc.value.code == 1
    assert not (tmp_path / "reports" / "triage.md").exists()


def test_cli_handles_empty_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    empty = tmp_path / "empty.jsonl"
    empty.write_text("", encoding="utf-8")

    result = main([str(empty)])

    report = (tmp_path / "reports" / "triage.md").read_text(encoding="utf-8")

    assert result == 0
    assert "Events analyzed: 0" in report
    assert "No detection rules matched" in report
