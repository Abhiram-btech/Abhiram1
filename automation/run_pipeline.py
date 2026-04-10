import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

if __package__ is None or __package__ == "":
    sys.path.append(str(Path(__file__).resolve().parent.parent))

from automation.detection_engine import run_detections
from automation.guardduty_analyzer import analyze_guardduty
from automation.parser import load_events


def main() -> None:
    parser = argparse.ArgumentParser(description="Run SIEM lab detection pipeline")
    parser.add_argument("--input-dir", required=True, help="Directory containing JSONL telemetry")
    parser.add_argument("--output", default="alerts.json", help="Output alert JSON path")
    args = parser.parse_args()

    events = load_events(args.input_dir)
    alerts = run_detections(events)
    guardduty_summary = analyze_guardduty(events)

    output_payload = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "input_dir": args.input_dir,
        "event_count": len(events),
        "alert_count": len(alerts),
        "alerts": alerts,
        "guardduty_summary": guardduty_summary,
    }

    output_path = Path(args.output)
    output_path.write_text(json.dumps(output_payload, indent=2), encoding="utf-8")

    print(f"Loaded events: {len(events)}")
    print(f"Generated alerts: {len(alerts)}")
    print(f"Wrote: {output_path}")


if __name__ == "__main__":
    main()
