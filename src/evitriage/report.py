from __future__ import annotations

from collections import Counter
from datetime import timezone

from .ai import AIAnalysis
from .models import EvidenceFile, Event, Finding


def _time(event: Event) -> str:
    return event.timestamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if event.timestamp.tzinfo else event.timestamp.isoformat()


def generate_report(
    evidence: EvidenceFile, events: list[Event], findings: list[Finding],
    *, ai_analysis: AIAnalysis | None = None, ai_status: str | None = None
) -> str:
    counts = Counter(finding.severity for finding in findings)
    lines = [
        "# EviTriage Forensic Incident Triage Report",
        "",
        "> **Authorized or synthetic evidence only.** Findings are triage indicators, not proof of compromise.",
        "",
        "## Executive Summary",
        "",
        f"EviTriage preserved and normalized **{len(events)} event(s)** and produced **{len(findings)} finding(s)**: "
        f"**{counts['High']} High**, **{counts['Medium']} Medium**, and **{counts['Low']} Low**.",
        "",
        "## Evidence Integrity",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Source file | `{evidence.path}` |",
        f"| Size | {evidence.size_bytes} bytes |",
        f"| SHA-256 | `{evidence.sha256}` |",
        "| Processing | Read-only; output written separately |",
        "",
        "## Chronological Timeline",
        "",
        "| Time | Record | Event ID | Computer | User | Source | Action | Outcome |",
        "|---|---:|---:|---|---|---|---|---|",
    ]
    for event in events:
        lines.append(f"| {_time(event)} | {event.source_record} | {event.event_id} | {event.computer or '-'} | {event.user or '-'} | {event.source_ip or '-'} | {event.action or '-'} | {event.outcome or '-'} |")

    lines.extend(["", "## Findings", ""])
    if not findings:
        lines.extend(["No configured suspicious patterns were detected.", ""])
    for index, finding in enumerate(findings, start=1):
        lines.extend([
            f"### {index}. {finding.title}", "",
            f"- **Severity:** {finding.severity}",
            f"- **Rule:** `{finding.rule_id}`", "",
            "**Why it matters**", "", finding.explanation, "",
            "**Evidence references**", "",
        ])
        for event in finding.evidence:
            lines.append(f"- Record {event.source_record}: {_time(event)}, Event ID {event.event_id}, user `{event.user or '-'}`, source `{event.source_ip or '-'}`")
        lines.extend(["", "**Suggested next step**", "", finding.recommendation, "", "**Analysis source:** Deterministic EviTriage rule. Manual validation required.", ""])

    lines.extend(["## AI Analysis Status", ""])
    if ai_analysis is not None:
        lines.extend([
            "**AI interpretation — advisory only; not original evidence.**", "",
            "### AI Incident Summary", "", ai_analysis.incident_summary, "",
            "### AI Plain-Language Explanations", "",
        ])
        for item in ai_analysis.finding_explanations:
            lines.extend([f"**Finding {item.finding_index}:** {item.explanation}", ""])
        lines.extend(["### AI Suggested Investigative Next Steps", ""])
        if ai_analysis.investigative_next_steps:
            for step in ai_analysis.investigative_next_steps:
                lines.append(f"- {step}")
        else:
            lines.append("No additional steps suggested.")
        lines.append("")
    elif ai_status is not None:
        lines.extend([ai_status, "", "The evidence, findings, and timeline above remain rule-based.", ""])
    else:
        lines.extend(["AI enhancement was not enabled for this report. Evidence, findings, explanations, and recommendations above were produced by transparent deterministic rules.", ""])
    lines.extend([
        "## Limitations", "",
        "- The input is normalized CSV or JSON rather than native EVTX.",
        "- Detection coverage is intentionally limited and may produce false positives or miss activity.",
        "- Log evidence may be incomplete, altered before collection, or affected by clock differences.",
        "- Findings must be validated by an authorized investigator.", "",
    ])
    return "\n".join(lines)

