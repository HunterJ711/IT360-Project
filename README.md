# EviTriage

EviTriage is a Python command-line tool that performs evidence-preserving triage of structured Windows security events. It hashes the source evidence, normalizes CSV or JSON records, detects suspicious event patterns, builds a chronological timeline, and produces a readable forensic incident report.

This project was created by Hunter Jackson and Will Puls for IT 360. It is intended only for authorized or synthetic evidence.

## Current features

- Read-only CSV and JSON evidence ingestion
- SHA-256 source-file hashing
- Normalized event records with source-row references
- Detection of repeated failed logins
- Detection of a successful login following repeated failures
- Detection of new account creation
- Detection of special privileges assigned to an account
- Chronological incident timeline
- Markdown report with evidence, deterministic findings, limitations, and AI status
- Automated tests and synthetic demonstration evidence

AI-assisted incident interpretation through the ISU Sushi server is planned as an optional advisory layer. The offline parser, detections, timeline, and report will remain functional without AI.

## Setup

```bash
git clone https://github.com/HunterJ711/IT360-Project.git
cd IT360-Project
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

On Windows, activate the environment with `.venv\\Scripts\\activate`.

## Run the demonstration

```bash
evitriage analyze data/sample_incident.csv --output reports/demo_report.md
```

The input file is never modified. Open `reports/demo_report.md` to review the evidence hash, normalized timeline, findings, and investigative recommendations.

## Run the tests

```bash
python -m unittest discover -s tests -v
```

## Supported evidence schema

CSV headers and JSON object keys use:

`timestamp,event_id,computer,user,source_ip,outcome,action,details`

Timestamps must be ISO 8601 values. Unknown optional fields may be blank, but each record must contain `timestamp` and `event_id`.

## Detection thresholds

The initial brute-force threshold is five failed-login events for the same user and source address within ten minutes. A successful login within ten minutes after those failures produces a separate high-severity finding. Thresholds are deliberately transparent and are not claims of proven compromise.

## Limitations

- Current input is normalized CSV or JSON, not native EVTX.
- Rules support a small set of Windows Security event patterns.
- Findings require review by an authorized investigator.
- Source logs may be incomplete or inaccurate.
- AI interpretation, when added, will be advisory and clearly separated from evidence.

