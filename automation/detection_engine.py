from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Callable, Dict, List


Event = Dict[str, Any]


@dataclass(frozen=True)
class DetectionRule:
    rule_id: str
    name: str
    mitre_technique: str
    severity: str
    tactic: str
    description: str
    matcher: Callable[[Event], bool]


def _lower(value: Any) -> str:
    return str(value or "").lower()


def _is_sysmon(event: Event) -> bool:
    return event.get("log_type") == "sysmon"


def _is_security(event: Event) -> bool:
    return event.get("log_type") == "security"


def _is_cloudtrail(event: Event) -> bool:
    return event.get("log_type") == "cloudtrail"


def _is_guardduty(event: Event) -> bool:
    return event.get("log_type") == "guardduty"


RULES: List[DetectionRule] = [
    DetectionRule(
        "DET-002",
        "Encoded PowerShell Execution",
        "T1059.001",
        "high",
        "Execution",
        "PowerShell launched with encoded/obfuscated command arguments.",
        lambda e: _is_sysmon(e)
        and int(e.get("EventID", 0)) == 1
        and "powershell" in _lower(e.get("Image"))
        and ("-enc" in _lower(e.get("CommandLine")) or "frombase64string" in _lower(e.get("CommandLine"))),
    ),
    DetectionRule(
        "DET-003",
        "LSASS Access Attempt",
        "T1003.001",
        "critical",
        "Credential Access",
        "Process attempted to access LSASS memory.",
        lambda e: _is_sysmon(e)
        and int(e.get("EventID", 0)) == 10
        and "lsass.exe" in _lower(e.get("TargetImage")),
    ),
    DetectionRule(
        "DET-004",
        "Local Account Creation",
        "T1136.001",
        "medium",
        "Persistence",
        "Local user account creation detected.",
        lambda e: _is_security(e) and int(e.get("EventID", 0)) == 4720,
    ),
    DetectionRule(
        "DET-005",
        "Suspicious Service Creation",
        "T1543.003",
        "high",
        "Persistence",
        "Service creation or modification event.",
        lambda e: (_is_security(e) and int(e.get("EventID", 0)) == 4697)
        or (
            _is_sysmon(e)
            and int(e.get("EventID", 0)) == 1
            and "sc create" in _lower(e.get("CommandLine"))
        ),
    ),
    DetectionRule(
        "DET-006",
        "Suspicious Rundll32 Execution",
        "T1218.011",
        "high",
        "Defense Evasion",
        "Rundll32 used to execute remote or scripted payload.",
        lambda e: _is_sysmon(e)
        and int(e.get("EventID", 0)) == 1
        and "rundll32.exe" in _lower(e.get("Image"))
        and ("http" in _lower(e.get("CommandLine")) or ".dll," in _lower(e.get("CommandLine"))),
    ),
    DetectionRule(
        "DET-007",
        "Scheduled Task Creation",
        "T1053.005",
        "medium",
        "Persistence",
        "Scheduled task creation activity.",
        lambda e: (_is_security(e) and int(e.get("EventID", 0)) == 4698)
        or (
            _is_sysmon(e)
            and int(e.get("EventID", 0)) == 1
            and "schtasks" in _lower(e.get("CommandLine"))
            and "/create" in _lower(e.get("CommandLine"))
        ),
    ),
    DetectionRule(
        "DET-008",
        "Suspicious WMI Execution",
        "T1047",
        "medium",
        "Execution",
        "WMI execution from command line.",
        lambda e: _is_sysmon(e)
        and int(e.get("EventID", 0)) == 1
        and ("wmic.exe" in _lower(e.get("Image")) or "wmic process call create" in _lower(e.get("CommandLine"))),
    ),
    DetectionRule(
        "DET-009",
        "Endpoint Defense Tampering",
        "T1562.001",
        "high",
        "Defense Evasion",
        "Attempt to disable endpoint security controls.",
        lambda e: _is_sysmon(e)
        and int(e.get("EventID", 0)) == 1
        and "set-mppreference" in _lower(e.get("CommandLine"))
        and "disablerealtimemonitoring" in _lower(e.get("CommandLine")),
    ),
    DetectionRule(
        "DET-010",
        "IAM Privilege Escalation Policy Change",
        "T1098",
        "high",
        "Privilege Escalation",
        "Suspicious IAM policy attachment or inline policy change.",
        lambda e: _is_cloudtrail(e)
        and _lower(e.get("eventSource")) == "iam.amazonaws.com"
        and _lower(e.get("eventName"))
        in {"attachuserpolicy", "putuserpolicy", "attachrolepolicy"},
    ),
    DetectionRule(
        "DET-011",
        "Root Console Login Without MFA",
        "T1078.004",
        "critical",
        "Initial Access",
        "Root account console access without MFA.",
        lambda e: _is_cloudtrail(e)
        and _lower(e.get("eventName")) == "consolelogin"
        and _lower(e.get("userIdentity", {}).get("type")) == "root"
        and _lower(e.get("responseElements", {}).get("ConsoleLogin")) == "success"
        and _lower(e.get("additionalEventData", {}).get("MFAUsed")) == "no",
    ),
    DetectionRule(
        "DET-012",
        "High-Severity GuardDuty Finding",
        "T1087.004",
        "high",
        "Discovery",
        "High-severity GuardDuty finding requires immediate triage.",
        lambda e: _is_guardduty(e) and float(e.get("severity", 0)) >= 7,
    ),
]


def _build_alert(rule: DetectionRule, event: Event, note: str = "") -> Dict[str, Any]:
    return {
        "rule_id": rule.rule_id,
        "name": rule.name,
        "mitre_technique": rule.mitre_technique,
        "severity": rule.severity,
        "tactic": rule.tactic,
        "description": rule.description,
        "note": note,
        "event": event,
    }


def _detect_bruteforce(events: List[Event]) -> List[Dict[str, Any]]:
    grouped: Dict[str, List[Event]] = defaultdict(list)
    for event in events:
        if not (_is_security(event) and int(event.get("EventID", 0)) == 4625):
            continue
        account = str(event.get("AccountName") or "unknown")
        source_ip = str(event.get("IpAddress") or "unknown")
        grouped[f"{account}|{source_ip}"].append(event)

    alerts: List[Dict[str, Any]] = []
    rule = DetectionRule(
        "DET-001",
        "Multiple Failed Logons (Brute Force)",
        "T1110.001",
        "high",
        "Credential Access",
        "Repeated failed logons from a single source.",
        lambda e: True,
    )

    for key, bucket in grouped.items():
        if len(bucket) >= 5:
            account, source_ip = key.split("|", 1)
            note = f"{len(bucket)} failed logons for account={account} source_ip={source_ip}"
            alerts.append(_build_alert(rule, bucket[-1], note=note))
    return alerts


def run_detections(events: List[Event]) -> List[Dict[str, Any]]:
    alerts: List[Dict[str, Any]] = []
    alerts.extend(_detect_bruteforce(events))

    for event in events:
        for rule in RULES:
            if rule.matcher(event):
                alerts.append(_build_alert(rule, event))

    return alerts
