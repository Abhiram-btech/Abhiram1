import json
from pathlib import Path
from typing import Any, Dict, List


def _infer_log_type(path: Path) -> str:
    name = path.name.lower()
    if "sysmon" in name:
        return "sysmon"
    if "security" in name:
        return "security"
    if "cloudtrail" in name:
        return "cloudtrail"
    if "guardduty" in name:
        return "guardduty"
    return "unknown"


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            payload = json.loads(line)
            if not isinstance(payload, dict):
                continue
            payload.setdefault("log_type", _infer_log_type(path))
            payload["_source_file"] = path.name
            records.append(payload)
    return records


def load_events(input_dir: str) -> List[Dict[str, Any]]:
    root = Path(input_dir)
    if not root.exists():
        raise FileNotFoundError(f"Input directory does not exist: {input_dir}")

    events: List[Dict[str, Any]] = []
    for jsonl_file in sorted(root.glob("*.jsonl")):
        events.extend(load_jsonl(jsonl_file))
    return events
