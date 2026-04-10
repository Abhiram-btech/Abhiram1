import unittest

from automation.detection_engine import run_detections


class DetectionEngineTests(unittest.TestCase):
    def test_bruteforce_detection_fires_at_threshold(self) -> None:
        events = [
            {
                "log_type": "security",
                "EventID": 4625,
                "AccountName": "admin",
                "IpAddress": "10.0.0.9",
            }
            for _ in range(5)
        ]

        alerts = run_detections(events)
        rule_ids = {alert["rule_id"] for alert in alerts}
        self.assertIn("DET-001", rule_ids)

    def test_cloudtrail_policy_abuse_detection(self) -> None:
        events = [
            {
                "log_type": "cloudtrail",
                "eventSource": "iam.amazonaws.com",
                "eventName": "AttachUserPolicy",
                "requestParameters": {"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
            }
        ]

        alerts = run_detections(events)
        rule_ids = {alert["rule_id"] for alert in alerts}
        self.assertIn("DET-010", rule_ids)

    def test_guardduty_high_severity_detection(self) -> None:
        events = [
            {
                "log_type": "guardduty",
                "severity": 8.0,
                "type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration",
            }
        ]

        alerts = run_detections(events)
        rule_ids = {alert["rule_id"] for alert in alerts}
        self.assertIn("DET-012", rule_ids)


if __name__ == "__main__":
    unittest.main()
