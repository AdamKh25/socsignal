"""Generate human-readable SOC triage reports."""

from collections import Counter

from socsignal.detections import (
    detect_failed_logon_bursts,
    detect_noteworthy_activity,
)


def _safe(value: object) -> str:
    """Keep untrusted event fields on one Markdown-safe line."""
    text = " ".join(str(value if value is not None else "Unknown").split())

    for character in ("\\", "`", "*", "_", "[", "]", "|", "<", ">"):
        text = text.replace(character, "\\" + character)

    return text


def build_triage_report(events: list[dict]) -> str:
    """Build a Markdown report from normalized security events."""
    alerts = detect_failed_logon_bursts(events) + detect_noteworthy_activity(events)

    alerts.sort(
        key=lambda alert: (
            alert["first_seen"],
            alert["rule_id"],
            alert["computer"],
        )
    )

    event_counts = Counter(event["event_id"] for event in events)
    severity_counts = Counter(alert["severity"] for alert in alerts)

    lines = [
        "# SOCSignal - SOC Triage Report",
        "",
        "## Executive Summary",
        "",
        f"- Events analyzed: {len(events)}",
        f"- Alerts requiring review: {len(alerts)}",
        f"- Medium-severity alerts: {severity_counts['medium']}",
        f"- Low-severity alerts: {severity_counts['low']}",
        "",
        "## Security Activity Snapshot",
        "",
        f"- Failed logons (4625): {event_counts[4625]}",
        f"- Accounts created (4720): {event_counts[4720]}",
        f"- Services installed (7045): {event_counts[7045]}",
        "",
        "These counts cover only the supplied event records.",
        "They do not establish audit completeness or compliance.",
        "",
        "## Detection Findings",
        "",
    ]

    if not alerts:
        lines.extend(
            [
                "No detection rules matched the supplied records.",
                "",
                "This does not prove that the system is secure.",
            ]
        )

    for number, alert in enumerate(alerts, start=1):
        lines.extend(
            [
                f"### {number}. {_safe(alert['rule_id'])} - {_safe(alert['title'])}",
                "",
                f"- Severity: {_safe(alert['severity']).upper()}",
                f"- Computer: {_safe(alert['computer'])}",
                f"- First seen (UTC): {_safe(alert['first_seen'])}",
                f"- Last seen (UTC): {_safe(alert['last_seen'])}",
                "- Windows record IDs: "
                + ", ".join(str(record) for record in alert["record_ids"]),
            ]
        )

        fields = {
            "source_ip": "Source IP",
            "target_user": "Target account",
            "subject_user": "Initiating account",
            "service_name": "Service name",
            "start_type": "Service startup type",
            "count": "Failed logon count",
        }

        for key, label in fields.items():
            if key in alert and alert[key] is not None:
                lines.append(f"- {label}: {_safe(alert[key])}")

        lines.extend(
            [
                "",
                "**Recommended investigation:**",
                "",
                _safe(alert["recommended_action"]),
                "",
            ]
        )

    lines.extend(
        [
            "## Analyst Notes",
            "",
            "- Validate detections against authorized system activity.",
            "- Correlate findings with additional event sources.",
            "- Document investigation results before escalation.",
            "- Treat these alerts as review findings, not confirmed incidents.",
            "",
        ]
    )

    return "\n".join(lines)
