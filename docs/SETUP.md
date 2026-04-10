# Setup Guide

## Prerequisites

- Python 3.10+
- Splunk Enterprise or Splunk Free (optional for SPL validation)
- Sysmon installed on Windows hosts (for real telemetry)

## Local Run (Lab Mode)

1. Generate telemetry:

```bash
python3 simulations/generate_attack_data.py --output-dir data/sample_logs
```

2. Run detection pipeline:

```bash
python3 automation/run_pipeline.py --input-dir data/sample_logs --output alerts.json
```

3. Review output:

```bash
python3 -m json.tool alerts.json
```

## Splunk Notes

1. Copy examples in `configs/splunk` into your Splunk app directory.
2. Update indexes/sourcetypes based on your environment.
3. Load queries from `detections/splunk/` or use `savedsearches.conf` entries.

## Validation

Run tests:

```bash
python3 -m unittest discover -s tests -p "test_*.py"
```
