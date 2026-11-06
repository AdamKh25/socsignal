"""Detection rules for normalized Windows security events."""

from collections import defaultdict, deque
from datetime import datetime, timedelta


def detect_failed_logon_bursts(
    events: list[dict],
    threshold: int = 3,
    window_minutes: int = 5,
) -> list[dict]:
    """Find repeated failed logons for the same host, IP, and account."""
    if threshold < 2 or window_minutes < 1:
        raise ValueError("Threshold must be >= 2 and window_minutes >= 1")

    groups = defaultdict(dict)

    for event in events:
        if event["event_id"] != 4625:
            continue

        data = event["event_data"]
        source_ip = data.get("source_ip")
        target_user = data.get("target_user")

        if not isinstance(source_ip, str) or not source_ip.strip():
            continue

        if source_ip.strip() == "-":
            continue

        if not isinstance(target_user, str) or not target_user.strip():
            continue

        key = (
            event["computer"],
            source_ip.strip(),
            target_user.strip(),
        )

        # Do not count the same Windows record twice.
        groups[key][event["record_id"]] = event

    alerts = []
    window = timedelta(minutes=window_minutes)

    for (computer, source_ip, target_user), records in groups.items():
        ordered = sorted(
            records.values(),
            key=lambda event: datetime.fromisoformat(event["timestamp"]),
        )

        recent = deque()

        for event in ordered:
            timestamp = datetime.fromisoformat(event["timestamp"])
            recent.append((timestamp, event))

            while recent and timestamp - recent[0][0] > window:
                recent.popleft()

            if len(recent) >= threshold:
                evidence = [record for _, record in recent]

                alerts.append(
                    {
                        "rule_id": "SOC-001",
                        "title": "Repeated failed logons",
                        "severity": "medium",
                        "computer": computer,
                        "source_ip": source_ip,
                        "target_user": target_user,
                        "count": len(evidence),
                        "first_seen": evidence[0]["timestamp"],
                        "last_seen": evidence[-1]["timestamp"],
                        "record_ids": [record["record_id"] for record in evidence],
                        "recommended_action": (
                            "Review logon failure status codes, verify "
                            "the source and account, and check for "
                            "related successful logons."
                        ),
                    }
                )

                # Version 1 reports the first qualifying burst
                # per computer, source IP, and target account.
                break

    return sorted(alerts, key=lambda alert: alert["first_seen"])


def detect_noteworthy_activity(events: list[dict]) -> list[dict]:
    """Flag account creations and service installations for review."""
    alerts = []
    seen = set()

    for event in events:
        event_id = event["event_id"]

        if event_id not in (4720, 7045):
            continue

        data = event["event_data"]

        if event_id == 4720:
            account = data.get("target_user")

            if not isinstance(account, str) or not account.strip():
                continue

            rule_id = "SOC-002"
            title = "New Windows account created"
            details = {
                "target_user": account.strip(),
                "subject_user": data.get("subject_user"),
            }
            recommendation = (
                "Verify the account creation was authorized, "
                "review the requesting user, and inspect "
                "the account's assigned privileges."
            )

        else:
            service = data.get("service_name")

            if not isinstance(service, str) or not service.strip():
                continue

            rule_id = "SOC-003"
            title = "New Windows service installed"
            details = {
                "service_name": service.strip(),
                "start_type": data.get("start_type"),
            }
            recommendation = (
                "Verify the service is authorized, inspect "
                "its configuration and executable path, and "
                "review related host activity."
            )

        # Deduplicate Windows records per host, log, and record ID.
        key = (
            event["computer"],
            event["log_name"],
            event["record_id"],
        )

        if key in seen:
            continue

        seen.add(key)

        alerts.append(
            {
                "rule_id": rule_id,
                "title": title,
                "severity": "low",
                "computer": event["computer"],
                "first_seen": event["timestamp"],
                "last_seen": event["timestamp"],
                "record_ids": [event["record_id"]],
                "recommended_action": recommendation,
                **details,
            }
        )

    return sorted(
        alerts,
        key=lambda alert: (
            alert["first_seen"],
            alert["computer"],
            alert["rule_id"],
        ),
    )
