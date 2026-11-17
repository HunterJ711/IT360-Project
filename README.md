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


On Windows, activate the virtual environment using:

**Command Prompt (CMD):**
```cmd
.venv\Scripts\activate.bat
```

**PowerShell:**
```powershell
.\.venv\Scripts\Activate.ps1
```

Then install EviTriage:

```powershell
python -m pip install -e .
```

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



## Optional AI Integration — Sushi and Ollama

EviTriage supports AI-assisted interpretation of security findings using ISU's Sushi server or a locally hosted Ollama model.

The AI generates:
- A concise incident summary
- Plain-language explanations for each finding
- Suggested investigative next steps

AI interpretation is advisory only. It does not modify the original evidence, severity ratings, detection rules, or chronological timeline.

### Supported AI Providers

| Provider | Model | API Endpoint |
|---|---|---|
| Sushi (Primary) | `llama3.1:latest` | `http://sushi.it.ilstu.edu:8080/api/chat/completions` |
| Ollama (Fallback) | `llama3.2:3b` | `http://localhost:11434/v1/chat/completions` |

The Sushi endpoint is currently unverified and requires authorized API access. Ollama has been tested locally on Windows.

### Option 1: Sushi Setup

1. Obtain Sushi access and an API key from ISU.
2. Connect to the ISU network or VPN.
3. Set the API key as an environment variable.

PowerShell:

```powershell
$env:SUSHI_API_KEY = "your-api-key"
```

Linux:

```bash
export SUSHI_API_KEY="your-api-key"
```

Never save API keys in the source code or commit them to GitHub.


### Option 2: Ollama Setup (Local AI)

1. Download and install Ollama from https://ollama.com/download.
2. Open a terminal and download the model:

```bash
ollama pull llama3.2:3b
```

3. Verify that the model is installed:

```bash
ollama list
```

4. Make sure Ollama is running.

Ollama provides a local API on port 11434 and does not require an API key for local requests.

The model runs on your computer rather than an external AI service. Once downloaded, the model can run without an internet connection.

### Automatic AI Fallback

When AI analysis is enabled, EviTriage:

1. Analyzes the security evidence using deterministic Python detection rules.
2. Converts the findings and supporting events into JSON.
3. Attempts AI interpretation using Sushi.
4. Falls back to local Ollama if Sushi is unavailable or its response is invalid.
5. Validates the AI response before including it in the report.
6. Generates the original rule-based report if both AI providers fail.

The generated report identifies which AI provider was used when analysis succeeds.

### Running EviTriage Without AI

```bash
evitriage analyze data/sample_incident.csv --output reports/demo_offline.md
```

### Running EviTriage With AI

```bash
evitriage analyze data/sample_incident.csv --ai --output reports/demo_ai.md
```

The `--ai` flag enables the Sushi-to-Ollama fallback process.

The `evitriage` command requires installing the project as described in the Setup section.

### Running Automated Tests

```bash
python -m unittest discover -s tests -v
```

The test suite uses mocked AI responses and does not require an active Sushi connection or Ollama installation.

### AI Limitations

- AI-generated explanations can contain inaccurate or unsupported conclusions.
- Smaller models may occasionally return invalid or incomplete JSON.
- The AI only receives detected findings and their supporting events, not the complete original evidence file.
- AI output requires human review before drawing forensic conclusions.
- The rule-based detection engine remains functional when AI is unavailable.
- Only synthetic or authorized security evidence should be submitted to an AI service.

