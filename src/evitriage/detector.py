from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from .models import Event, Finding

FAILURE_WINDOW = timedelta(minutes=10)
FAILURE_THRESHOLD = 5


def _failed_login(event: Event) -> bool:
    return event.event_id == 4625 or (event.action.lower() == "login" and event.outcome == "failure")


def _successful_login(event: Event) -> bool:
    return event.event_id == 4624 or (event.action.lower() == "login" and event.outcome == "success")


def detect(events: list[Event]) -> list[Finding]:
    findings: list[Finding] = []
    failures_by_identity: dict[tuple[str, str], list[Event]] = defaultdict(list)

    for event in events:
        if _failed_login(event):
            failures_by_identity[(event.user, event.source_ip)].append(event)

    qualifying_failures: dict[tuple[str, str], list[Event]] = {}
    for identity, failures in failures_by_identity.items():
        for start in range(len(failures)):
            window = [event for event in failures[start:] if event.timestamp - failures[start].timestamp <= FAILURE_WINDOW]
            if len(window) >= FAILURE_THRESHOLD:
                qualifying_failures[identity] = window
                findings.append(Finding(
                    rule_id="AUTH_FAILURE_BURST",
                    title="Repeated failed logins",
                    severity="Medium",
                    explanation=f"{len(window)} failed logins targeted user '{identity[0]}' from {identity[1] or 'an unknown source'} within ten minutes.",
                    recommendation="Confirm whether the source and account activity are expected, review authentication logs, and consider account or source-based protections.",
                    evidence=window,
                ))
                break

    for success in [event for event in events if _successful_login(event)]:
        identity = (success.user, success.source_ip)
        prior = [event for event in qualifying_failures.get(identity, []) if timedelta(0) <= success.timestamp - event.timestamp <= FAILURE_WINDOW]
        if len(prior) >= FAILURE_THRESHOLD:
            findings.append(Finding(
                rule_id="SUCCESS_AFTER_FAILURES",
                title="Successful login after repeated failures",
                severity="High",
                explanation=f"User '{success.user}' successfully logged in from {success.source_ip} shortly after {len(prior)} failed attempts from the same source.",
                recommendation="Validate the login with the account owner, review subsequent activity, preserve related logs, and reset credentials if the activity is unauthorized.",
                evidence=prior + [success],
            ))

    for event in events:
        if event.event_id == 4720 or event.action.lower() == "account created":
            findings.append(Finding(
                rule_id="ACCOUNT_CREATED",
                title="User account created",
                severity="Medium",
                explanation=f"A user-account creation event was recorded for '{event.user or 'an unspecified account'}'.",
                recommendation="Confirm the account was authorized and review the creating administrator and subsequent account activity.",
                evidence=[event],
            ))
        if event.event_id == 4672 or event.action.lower() == "special privileges assigned":
            findings.append(Finding(
                rule_id="SPECIAL_PRIVILEGES",
                title="Special privileges assigned",
                severity="Medium",
                explanation=f"Special privileges were assigned to '{event.user or 'an unspecified account'}'. This may be legitimate administrative activity but warrants review.",
                recommendation="Verify the privileged session was authorized and correlate it with logon, process, and account-management events.",
                evidence=[event],
            ))

    order = {"High": 0, "Medium": 1, "Low": 2}
    return sorted(findings, key=lambda finding: (order.get(finding.severity, 9), finding.evidence[0].timestamp))

