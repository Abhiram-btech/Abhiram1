# Detection Engineering Lab (SIEM & Threat Hunting)

End-to-end SIEM project that simulates endpoint and cloud attacks, ingests telemetry, and validates detections using Splunk-style analytics and Python automation.

## Project Highlights

- SIEM pipeline design for **Splunk + Sysmon** endpoint telemetry.
- **12 detection rules** mapped to MITRE ATT&CK techniques.
- Attack simulation for:
  - Brute-force authentication activity
  - Privilege escalation behavior
  - Suspicious AWS IAM actions
- Python automation for:
  - Log normalization and parsing
  - Detection/alert generation
  - GuardDuty finding triage
- Cloud log coverage:
  - AWS CloudTrail IAM activity monitoring
  - GuardDuty finding analysis

## Repository Structure

```text
.
├── automation/                  # Python pipeline and detection engine
├── configs/
│   ├── splunk/                  # Splunk onboarding + saved search examples
│   └── sysmon/                  # Sysmon collection config
├── data/sample_logs/            # Generated sample telemetry
├── detections/
│   ├── catalog/                 # Detection metadata + MITRE mappings
│   └── splunk/                  # Splunk SPL detection queries
├── docs/                        # Architecture and setup documentation
├── simulations/                 # Attack simulation data generators
└── tests/                       # Unit tests
```

## Quick Start

### 1) Generate sample telemetry

```bash
python3 simulations/generate_attack_data.py --output-dir data/sample_logs
```

### 2) Run the detection pipeline

```bash
python3 automation/run_pipeline.py --input-dir data/sample_logs --output alerts.json
```

### 3) Run tests

```bash
python3 -m unittest discover -s tests -p "test_*.py"
```

## Detection Coverage (MITRE ATT&CK)

The project includes detections for these common techniques:

- T1110.001 - Brute Force: Password Guessing
- T1059.001 - PowerShell (encoded/obfuscated command usage)
- T1003.001 - OS Credential Dumping: LSASS Memory
- T1136.001 - Create Account: Local Account
- T1543.003 - Create or Modify System Process: Windows Service
- T1218.011 - Signed Binary Proxy Execution: Rundll32
- T1053.005 - Scheduled Task/Job: Scheduled Task
- T1047 - Windows Management Instrumentation
- T1562.001 - Impair Defenses: Disable or Modify Tools
- T1098 - Account Manipulation (IAM policy abuse)
- T1078.004 - Valid Accounts: Cloud Accounts (root login without MFA)
- T1087.004 - Account Discovery / Suspicious IAM user activity

See full mapping in `docs/DETECTION_CATALOG.md` and `detections/catalog/detection_rules.json`.

## Notes

- This repo is intentionally lab-focused and uses generated data to validate detections.
- Splunk config and searches are provided as production-style examples; adjust indexes/sourcetypes for your environment.