from typing import Dict, Any
from engine.models import SecurityAlert

class RuleBasedBaseline:
    def triage(self, alert: SecurityAlert) -> Dict[str, Any]:
        if alert.severity in ("CRITICAL", "HIGH"):
            return {
                "verdict": "TRUE_POSITIVE",
                "confidence": 0.70,
                "risk_score": 80,
                "method": "static_severity_threshold"
            }
        elif "newsletter" in (alert.raw_log or "").lower():
            return {
                "verdict": "FALSE_POSITIVE",
                "confidence": 0.60,
                "risk_score": 10,
                "method": "static_keyword_filter"
            }
        elif alert.severity == "LOW":
            return {
                "verdict": "FALSE_POSITIVE",
                "confidence": 0.60,
                "risk_score": 20,
                "method": "static_severity_filter"
            }
        else:
            return {
                "verdict": "SUSPICIOUS",
                "confidence": 0.50,
                "risk_score": 50,
                "method": "fallback_rule"
            }
