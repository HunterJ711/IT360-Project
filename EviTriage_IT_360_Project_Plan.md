# IT 360 Final Project Plan

## EviTriage

**AI-Assisted Security Log Analysis and Forensic Incident Reporting Tool**

| Project Information | Details |
|---|---|
| Course | IT 360: Security Incident and Event Management and Forensics |
| Project Team | Hunter Jackson and Will Puls |
| Project Start | August 26, 2026 |
| Project Completion | December 3, 2026 |
| Intended Use | Educational use with authorized or synthetic evidence only |

---

## Overview

### Project Description

EviTriage will be a Python-based digital-forensics support tool that imports security event logs, organizes important events, identifies suspicious patterns, reconstructs a basic incident timeline, and generates a readable forensic incident report. Initial support will focus on exported Windows Event Log data or normalized CSV/JSON samples so the project remains reliable and demonstrable.

Rule-based analysis will detect patterns such as repeated failed logins, a successful login following multiple failures, unusual login times, account creation, privilege changes, and suspicious process activity when those fields are available. Artificial intelligence will explain selected findings in plain language, summarize the likely incident narrative, and recommend reasonable next investigative steps.

The original log evidence, timestamps, event identifiers, and rule results will remain separate from AI interpretation. EviTriage will not modify evidence, automatically contain systems, or present AI conclusions as proven facts.

### Project Objectives

- Create a functional Python digital-forensics tool.
- Import and normalize authorized Windows Event Log exports or structured CSV/JSON logs.
- Extract timestamps, users, hosts, event IDs, source addresses, actions, and outcomes when available.
- Detect and correlate suspicious authentication, account, privilege, and process events.
- Assign Low, Medium, or High triage severity using transparent rules.
- Construct a chronological incident timeline.
- Use AI to explain findings, summarize a possible incident narrative, and suggest follow-up investigation steps.
- Generate a readable forensic incident report containing evidence, analysis, limitations, and recommendations.
- Test with synthetic or authorized sample evidence.
- Document installation, dependencies, operation, and limitations.

### Success Criteria

The project will be considered successful if:

1. The tool runs in the intended environment and processes at least two known-good sample datasets.
2. Relevant fields are extracted accurately and normalized into a consistent structure.
3. At least four defined suspicious-event patterns are detected reliably.
4. Events are ordered into a clear incident timeline with source references.
5. AI produces useful explanations and investigation suggestions for selected findings.
6. Reports clearly distinguish source evidence, deterministic rule results, and AI interpretation.
7. Malformed input and missing fields are handled without silently changing evidence.
8. The public GitHub repository includes source code, a README, dependencies, sample data, the final PDF report, and `docs/presentation_slides.pdf`.
9. Both team members deliver a clear 10–15 minute in-person presentation with a working live demonstration and backup screenshots.

### Project Dates

| Milestone | Date |
|---|---|
| Project start | August 26, 2026 |
| Target feature-complete version | November 13, 2026 |
| Testing and documentation complete | November 30, 2026 |
| Final project ready | December 3, 2026 |

---

## Stakeholders

### Sponsor Designation

**Project Sponsor / Evaluator:** IT 360 Course Instructor

The instructor defines academic expectations, provides guidance, and evaluates the tool, repository, report, and presentation.

### Stakeholder List

| Stakeholder | Role | Responsibilities |
|---|---|---|
| Hunter Jackson | Co-Project Lead / Developer | Project coordination, log ingestion, parsing, normalization, testing, repository organization, and documentation |
| Will Puls | Co-Project Lead / Developer | Detection rules, event correlation, AI integration, report generation, testing, and documentation |
| IT 360 Instructor | Sponsor / Evaluator | Define requirements, provide academic guidance, and evaluate deliverables |
| Authorized Lab / Sample Evidence Users | Test Users | Provide permitted evidence and feedback for testing and demonstration |

Both students will participate in architecture, code review, debugging, final report writing, and the in-person presentation. Each student will speak and understand the portion presented. Ownership may overlap to avoid a single point of failure.

---

## Scope Management

### In-Scope Items

- Python command-line application.
- Import of exported Windows event data or normalized CSV/JSON security logs.
- Evidence hashing for imported files and read-only processing.
- Field extraction and normalization.
- Rule-based detection of selected suspicious patterns.
- Basic event correlation and chronological timeline generation.
- Severity classification with explainable rules.
- AI-generated explanations, incident summaries, and suggested investigative next steps.
- Markdown or HTML forensic incident report generation.
- Input validation and error handling.
- Authorized or synthetic test fixtures.
- Public GitHub repository with a professional README and `requirements.txt`.
- Final PDF report and 10–15 minute presentation.

### Out-of-Scope Items

- Live enterprise SIEM deployment or continuous monitoring.
- Endpoint isolation, account disabling, or automated incident response.
- Malware detonation, reverse engineering, memory forensics, or disk imaging.
- Full file carving or password cracking.
- Bypassing access controls or collecting unauthorized evidence.
- Support for every operating system and log format.
- Treating AI output as verified evidence or allowing AI to alter evidence.
- A complex graphical interface or full commercial forensic suite.

### Project Assumptions

- Authorized or synthetic log evidence is available.
- Python, Git, and GitHub are available.
- Sample logs contain enough fields to support the selected detection rules.
- Internet access is available if a cloud AI service is selected.
- AI findings are reviewed by the team and labeled as interpretation.
- The same general application architecture used for APTriage can be reused without combining the two projects or their evidence.

### Project Constraints

- Two students must complete the project during the Fall 2026 semester while balancing other coursework.
- Log formats and field availability vary.
- AI output may be inaccurate, and APIs may have usage limits or small costs.
- Evidence integrity and authorization must be maintained.
- The scope must remain small enough for reliable testing, documentation, and demonstration.

---

## Technical Design and Shared Architecture

EviTriage intentionally uses the same reusable application pattern as APTriage while solving a separate IT 360 forensics problem.

| Stage | EviTriage Output | Reusable Component |
|---|---|---|
| 1. Evidence input | Authorized CSV/JSON or exported event logs | Input validation and file-handling pattern |
| 2. Parser / normalizer | Consistent event records | Parser interfaces and data models |
| 3. Rules / correlation | Suspicious patterns, severity, and timeline | Severity framework and finding objects |
| 4. AI analysis | Explanations and investigation suggestions | AI client, prompt templates, and safeguards |
| 5. Report generation | Forensic incident report | Markdown/HTML reporting framework |

This approach reduces duplicate development while keeping each course project academically distinct. APTriage analyzes Nmap reconnaissance findings, while EviTriage analyzes forensic event evidence and reconstructs incident activity.

### Example Workflow

```text
Authorized or Synthetic Log Evidence
                 |
                 v
       Input Validation and Hashing
                 |
                 v
         Parser and Normalizer
                 |
                 v
       Detection and Correlation
                 |
                 v
        Incident Timeline Builder
                 |
                 v
         AI-Assisted Explanation
                 |
                 v
       Forensic Incident Report
```

---

## Timeline

| Date | Milestone | Deliverables |
|---|---|---|
| August 26 | Planning | Submit the project plan and confirm scope, roles, evidence types, and success criteria. |
| September 4 | Environment and repository | Create the GitHub repository, folder structure, Python environment, requirements file, and sample-data policy. |
| September 18 | Evidence ingestion | Import CSV/JSON logs, validate files, calculate hashes, and handle missing fields. |
| October 2 | Parser and normalization | Extract timestamps, users, hosts, event IDs, sources, actions, and outcomes into common records. |
| October 16 | Detection rules | Implement and test at least four suspicious-event patterns and severity logic. |
| October 30 | Correlation and timeline | Group related events and generate a chronological incident timeline. |
| November 14 | Offline MVP | Complete evidence hashing, normalization, four detection patterns, timeline generation, reporting, sample evidence, and automated tests. |
| November 20 | AI and reporting integration | Add labeled Sushi AI incident summaries and investigation steps while retaining offline fallback behavior. |
| November 25 | Testing and debugging | Test known-good, suspicious, malformed, and incomplete datasets; correct major defects. |
| November 30 | Documentation | Finish the README, setup instructions, examples, screenshots, results, lessons learned, final PDF report, and presentation slides. |
| Before presentation day | Presentation rehearsal | Test the live demonstration, classroom equipment, timing, speaking roles, and backup screenshots. |
| December 3 | Project completion | Finalize the public repository, add the instructor as a collaborator, and complete the submission review. |

---

## Risk Management

| Risk | Probability | Impact | Response / Mitigation |
|---|---|---|---|
| Different log formats break parsing | Medium | High | Use a normalized schema, documented sample format, input validation, and multiple fixtures. |
| AI invents or overstates conclusions | Medium | High | Keep evidence separate, label AI content, constrain prompts, and manually review outputs. |
| Evidence is altered accidentally | Low | High | Use read-only inputs, record hashes, and write results to separate output files. |
| Project scope becomes too large | Medium | High | Complete the MVP before adding formats, detections, or visual features. |
| Insufficient sample evidence | Medium | Medium | Create synthetic fixtures and retain authorized known-good datasets. |
| Correlation produces false positives | Medium | Medium | Use transparent thresholds and document limitations. |
| AI service or quota becomes unavailable | Low–Medium | Medium | Keep parsing, rules, timeline creation, and reporting functional without AI. |
| Integration defects delay development | Medium | Medium | Use shared data models, frequent commits, code review, and staged tests. |
| One team member becomes unavailable | Low–Medium | Medium | Keep all work in GitHub and maintain overlapping knowledge. |
| Demonstration fails | Medium | Medium | Maintain a known-good dataset and pre-generated example report. |
| Unauthorized or sensitive data enters the repository | Low | High | Use synthetic or sanitized evidence and review the public repository before submission. |
| Project falls behind schedule | Medium | High | Track MVP milestones in GSD and defer optional enhancements. |

---

## Resources

### Budget Allocation

| Resource | Estimated Cost |
|---|---:|
| Python, Git, and GitHub | $0 |
| Visual Studio Code or similar IDE | $0 |
| Sample or synthetic log evidence | $0 |
| Windows VM or course lab | $0 |
| AI service | $0–$20 |
| **Estimated Total** | **$0–$20** |

The team will prioritize free and open-source resources whenever possible.

### Required Tools and Technology

- Python 3.
- Git and GitHub.
- Visual Studio Code or an equivalent development environment.
- CSV, JSON, and optionally exported Windows Event Log data converted to a documented format.
- Python standard libraries such as `csv`, `json`, `datetime`, `hashlib`, `pathlib`, and `collections`.
- Optional libraries such as `pandas` for structured analysis and `Jinja2` for report templates.
- An approved AI API or model and its client library.
- An authorized Windows VM, course lab, or synthetic evidence.
- Markdown or HTML report output.

### Project Dependencies

1. The evidence format and sample data must be finalized before parser testing.
2. Normalized event records are required before detection and correlation.
3. Reliable detections and timelines are required before AI prompt and report integration.
4. The application must remain useful if the AI service is unavailable.
5. Documentation and demonstration assets depend on a stable, feature-complete build.

---

## Communication

### Meeting Cadence and Reporting Frequency

Hunter Jackson and Will Puls will meet at least twice per week during active development. Each sync will review completed work, current assignments, blockers, testing results, integration status, and the next milestone.

The team will review the schedule weekly and record major progress through GitHub history and GSD tasks. Additional meetings may be scheduled near major integration, testing, and presentation deadlines.

### Communication Channels

- **GitHub:** Source control, repository files, issues, and progress history.
- **GSD:** Actionable tasks and main-inbox synchronization.
- **Text/Discord:** Quick team coordination.
- **Email:** Instructor questions and formal communication.
- **Class/In-person discussion:** Feedback, questions, and demonstrations.

---

## Action Items

| Action Item | Owner | Due Date | GSD Sync |
|---|---|---|---|
| Submit project plan | Hunter / Will | August 26 | Yes |
| Create repository and folder structure | Hunter | September 4 | Yes |
| Finalize evidence schema and sample-data policy | Hunter / Will | September 4 | Yes |
| Configure Python environment and dependencies | Hunter / Will | September 4 | Yes |
| Create authorized or synthetic sample logs | Hunter | September 11 | Yes |
| Implement input validation and file hashing | Hunter | September 18 | Yes |
| Build parser and normalization model | Hunter | October 2 | Yes |
| Define suspicious-event rules and thresholds | Will | October 9 | Yes |
| Implement and test detection rules | Will | October 16 | Yes |
| Build correlation and incident timeline | Hunter / Will | October 30 | Yes |
| Select and connect AI service | Will | November 6 | Yes |
| Develop forensic AI prompts and safeguards | Will | November 13 | Yes |
| Develop report generator | Will | November 13 | Yes |
| Integrate all modules | Hunter / Will | November 13 | Yes |
| Complete functional and error testing | Hunter / Will | November 20 | Yes |
| Fix major defects | Hunter / Will | November 25 | Yes |
| Complete README and final PDF report | Hunter / Will | November 30 | Yes |
| Prepare demonstration dataset | Hunter | December 1 | Yes |
| Create 8–12 slides and export `docs/presentation_slides.pdf` | Hunter / Will | November 30 | Yes |
| Rehearse the in-person presentation and live demonstration | Hunter / Will | Before presentation day | Yes |
| Add instructor and review public repository | Hunter / Will | December 3 | Yes |

Items marked **Yes** under GSD Sync can be pushed to the main GSD inbox for tracking.

---

## Division of Responsibilities

### Hunter Jackson

- Project coordination and repository organization.
- Evidence input, validation, hashing, parsing, and normalization.
- Sample datasets and testing environment.
- Application integration and README documentation.

### Will Puls

- Detection rules, thresholds, event correlation, and severity logic.
- AI integration and prompt development.
- Incident explanations and investigation recommendations.
- Report-generation functionality, testing, and documentation.

### Shared Responsibilities

- Architecture decisions and code review.
- Debugging, integration, and functional testing.
- Final written report.
- Presentation preparation, speaking-role practice, and live-demo rehearsal.
- Final repository and submission review.

This division provides clear ownership while allowing both team members to understand and contribute to the complete application.

---

## Minimum Viable Product (MVP)

The minimum required version of EviTriage will:

1. Accept an authorized or synthetic structured security-log file.
2. Record the source file hash and parse events without modifying the input.
3. Normalize essential event fields.
4. Detect at least four suspicious patterns and assign severity.
5. Generate a chronological incident timeline.
6. Use AI to explain selected findings and recommend investigative next steps.
7. Produce a report that clearly separates evidence, deterministic analysis, and AI interpretation.

If these seven steps work reliably with the demonstration dataset, the project has a complete and presentable core product.

---

## Future Enhancements

The following features may be considered only after the MVP is complete, tested, and documented:

- Native EVTX parsing and additional log-source adapters.
- MITRE ATT&CK technique mapping.
- Sigma-rule support and configurable detections.
- Interactive timeline or simple graphical interface.
- Threat-intelligence enrichment.
- Scan-to-log correlation with APTriage exports.
- Local or offline AI support.
- Case comparison and advanced PDF report templates.

---

## Final Deliverables

- A public GitHub repository with the instructor added as a collaborator.
- A functional digital-forensics programming project worth 75 points.
- A detailed PDF report covering the introduction, technical implementation, results, and lessons learned/conclusion, worth 45 points.
- An 8–12 slide deck saved as `docs/presentation_slides.pdf` and a professional 10–15 minute in-person presentation with a live demonstration, worth 30 points per student.
- A comprehensive `README.md` containing the project overview, features, setup instructions, and usage instructions.

---

## Project Completion Definition

EviTriage will be considered complete when it reliably processes authorized or synthetic security-log evidence, preserves the source file and its hash, normalizes events, detects defined suspicious patterns, builds an incident timeline, uses AI as a clearly labeled advisory layer, and produces a readable forensic incident report.

The public repository must contain clean source code, documented dependencies, sample evidence in `data/`, a comprehensive README, `docs/final_report.pdf`, and `docs/presentation_slides.pdf`. The tool must be tested, demonstrable live in class, and useful even when the AI service is unavailable. Both team members must understand and present meaningful portions. Optional enhancements are not required for project completion.

