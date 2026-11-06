"""Command-line interface for SOCSignal."""

import argparse
from pathlib import Path

from socsignal.reader import EventFormatError, read_events
from socsignal.reporting import build_triage_report


def main(argv: list[str] | None = None) -> int:
    """Analyze JSONL event files and generate a local SOC report."""
    parser = argparse.ArgumentParser(
        description="SOCSignal Windows security event triage toolkit"
    )

    parser.add_argument(
        "inputs",
        nargs="+",
        type=Path,
        help="One or more Windows event JSONL files",
    )

    args = parser.parse_args(argv)
    events = []

    for path in args.inputs:
        try:
            events.extend(read_events(path))
        except (OSError, EventFormatError) as exc:
            parser.exit(
                1,
                f"Error reading {path}: {exc}\n"
                "No report written; an existing report may be stale.\n",
            )

    report = build_triage_report(events)
    output = Path("reports/triage.md")

    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(report, encoding="utf-8")
    except OSError as exc:
        parser.exit(1, f"Error writing report: {exc}\n")

    print("SOCSignal analysis complete.")
    print(f"Events analyzed: {len(events)}")
    print(f"Report saved to: {output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
