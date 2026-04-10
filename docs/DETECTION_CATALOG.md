# Detection Catalog

| Rule ID | Detection | MITRE Technique | Severity |
|---|---|---|---|
| DET-001 | Multiple Failed Logons (Brute Force) | T1110.001 | high |
| DET-002 | Encoded PowerShell Execution | T1059.001 | high |
| DET-003 | LSASS Access Attempt | T1003.001 | critical |
| DET-004 | Local Account Creation | T1136.001 | medium |
| DET-005 | Suspicious Service Creation | T1543.003 | high |
| DET-006 | Suspicious Rundll32 Execution | T1218.011 | high |
| DET-007 | Scheduled Task Creation | T1053.005 | medium |
| DET-008 | Suspicious WMI Execution | T1047 | medium |
| DET-009 | Endpoint Defense Tampering | T1562.001 | high |
| DET-010 | IAM Privilege Escalation Policy Change | T1098 | high |
| DET-011 | Root Console Login Without MFA | T1078.004 | critical |
| DET-012 | High-Severity GuardDuty Finding | T1087.004 | high |

Full machine-readable rule data is in `detections/catalog/detection_rules.json`.
