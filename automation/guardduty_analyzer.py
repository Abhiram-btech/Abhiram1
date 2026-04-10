from collections import Counter
from typing import Any, Dict, List


def analyze_guardduty(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    findings = [e for e in events if e.get("log_type") == "guardduty"]
    if not findings:
        return {
            "total_findings": 0,
            "high_or_critical": 0,
            "top_finding_types": [],
            "recommendations": [],
        }

    type_counter = Counter(str(item.get("type", "Unknown")) for item in findings)
    high_or_critical = sum(1 for item in findings if float(item.get("severity", 0)) >= 7)

    recommendations = []
    if high_or_critical:
        recommendations.append(
            "Prioritize high-severity findings for investigation and containment."
        )
    if any("IAM" in finding_type.upper() for finding_type in type_counter):
        recommendations.append(
            "Review IAM policies, key usage, and role trust relationships for abuse."
        )
    if any("EC2" in finding_type.upper() for finding_type in type_counter):
        recommendations.append(
            "Inspect implicated EC2 instances for persistence and credential theft artifacts."
        )

    return {
        "total_findings": len(findings),
        "high_or_critical": high_or_critical,
        "top_finding_types": type_counter.most_common(5),
        "recommendations": recommendations,
    }
