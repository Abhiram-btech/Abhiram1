# SIEM Lab Architecture

This lab models a practical detection engineering workflow using endpoint and cloud telemetry.

## Data Sources

1. **Sysmon (Windows endpoint)**
   - Process creation (Event ID 1)
   - Process access (Event ID 10)
2. **Windows Security logs**
   - Failed logon (4625)
   - Account creation (4720)
   - Service install (4697)
   - Scheduled task creation (4698)
3. **AWS CloudTrail**
   - IAM policy changes
   - Console logins
   - User/role activity
4. **AWS GuardDuty findings**
   - Threat findings with severity and finding type

## Pipeline Flow

```text
Attack Simulations -> JSONL Logs -> Parser/Normalizer -> Detection Engine -> Alerts + GuardDuty Summary
                         |                                  |
                         +---- Splunk Queries/Rules --------+
```

- `simulations/generate_attack_data.py` creates representative attack and benign events.
- `automation/parser.py` ingests and normalizes JSONL telemetry.
- `automation/detection_engine.py` evaluates MITRE-aligned detections.
- `automation/guardduty_analyzer.py` summarizes GuardDuty findings for triage.
- `automation/run_pipeline.py` orchestrates the full workflow and writes `alerts.json`.

## Detection Engineering Model

Each detection has:
- Rule ID and title
- MITRE ATT&CK technique mapping
- Severity and tactic
- Trigger logic (Python + SPL query reference)
- Validation through generated attack telemetry

## Splunk Integration

Splunk-side assets in `configs/splunk` and `detections/splunk` include:
- Example `inputs.conf` and `props.conf` for ingestion
- `savedsearches.conf` for alert scheduling and metadata
- SPL detection queries for analyst workflows

## Security Operations Outcome

This lab demonstrates:
- Endpoint + cloud detection coverage in one pipeline
- Automated triage and alert generation
- Rule validation through repeatable attack simulation
