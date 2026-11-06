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


def test_cli_warns_about_stale_report(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    report = tmp_path / "reports" / "triage.md"
    report.parent.mkdir()
    report.write_text("PREVIOUS_SYNTHETIC_REPORT", encoding="utf-8")

    invalid = tmp_path / "invalid.jsonl"
    invalid.write_text("invalid json\n", encoding="utf-8")

    with pytest.raises(SystemExit) as exc:
        main([str(invalid)])

    assert exc.value.code == 1
    assert report.read_text(encoding="utf-8") == ("PREVIOUS_SYNTHETIC_REPORT")
    assert "existing report may be stale" in capsys.readouterr().err


def test_cli_replaces_existing_report(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    report = tmp_path / "reports" / "triage.md"
    report.parent.mkdir()
    report.write_text("OLD_SYNTHETIC_REPORT", encoding="utf-8")

    result = main([str(SAMPLE)])

    assert result == 0
    assert "Events analyzed: 5" in report.read_text(encoding="utf-8")
    assert "OLD_SYNTHETIC_REPORT" not in report.read_text(encoding="utf-8")
    assert not list(report.parent.glob(".triage-*.tmp"))


def test_cli_preserves_report_on_replace_failure(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    report = tmp_path / "reports" / "triage.md"
    report.parent.mkdir()
    report.write_text("OLD_SYNTHETIC_REPORT", encoding="utf-8")

    def fail_replace(self, target):
        raise OSError("Synthetic replacement failure")

    monkeypatch.setattr(Path, "replace", fail_replace)

    with pytest.raises(SystemExit) as exc:
        main([str(SAMPLE)])

    assert exc.value.code == 1
    assert report.read_text(encoding="utf-8") == ("OLD_SYNTHETIC_REPORT")
    assert "existing report may be stale" in capsys.readouterr().err
    assert not list(report.parent.glob(".triage-*.tmp"))


def test_cli_rejects_invalid_utf8(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    report = tmp_path / "reports" / "triage.md"
    report.parent.mkdir()
    report.write_text("PREVIOUS_REPORT", encoding="utf-8")

    invalid = tmp_path / "corrupted.jsonl"
    invalid.write_bytes(b"\xff")

    with pytest.raises(SystemExit) as exc:
        main([str(invalid)])

    assert exc.value.code == 1
    assert report.read_text(encoding="utf-8") == "PREVIOUS_REPORT"
    assert "existing report may be stale" in capsys.readouterr().err
    assert not list(report.parent.glob(".triage-*.tmp"))
