"""Command-line interface for SOCSignal."""

import argparse
import tempfile
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

    temporary_path = None

    try:
        output.parent.mkdir(parents=True, exist_ok=True)

        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=output.parent,
            prefix=".triage-",
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)
            temporary_file.write(report)

        temporary_path.replace(output)

    except OSError as exc:
        parser.exit(
            1,
            f"Error writing report: {exc}\n"
            "Report not updated; an existing report may be stale.\n",
        )

    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)

    print("SOCSignal analysis complete.")
    print(f"Events analyzed: {len(events)}")
    print(f"Report saved to: {output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
