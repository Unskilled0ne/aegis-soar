import logging
from typing import Dict, Any, List

logger = logging.getLogger("soar.notifier")

class NotificationService:
    def __init__(self, webhook_url: str = ""):
        self.webhook_url = webhook_url
        self.sent_notifications = []

    def dispatch_alert(self, title: str, severity: str, case_id: str,
                       iocs: List[str], actions_taken: List[str]) -> Dict[str, Any]:
        """
        Formats and dispatches Slack / Teams webhook payload with interactive action blocks.
        """
        color_map = {
            "CRITICAL": "#dc2626",
            "HIGH": "#f59e0b",
            "MEDIUM": "#3b82f6",
            "LOW": "#10b981"
        }

        payload = {
            "text": f"🚨 *SOAR Automated Incident Alert: {title}*",
            "attachments": [
                {
                    "color": color_map.get(severity, "#6b7280"),
                    "fields": [
                        {"title": "Incident ID", "value": case_id, "short": True},
                        {"title": "Severity", "value": severity, "short": True},
                        {"title": "Identified IOCs", "value": "\n".join(f"`{i}`" for i in iocs) if iocs else "None", "short": False},
                        {"title": "Automated Containment Actions", "value": "\n".join(f"• {a}" for a in actions_taken) if actions_taken else "No actions taken", "short": False}
                    ],
                    "actions": [
                        {"type": "button", "text": "Approve Quarantine", "style": "danger"},
                        {"type": "button", "text": "Mark False Positive", "style": "primary"},
                        {"type": "button", "text": "View in TheHive", "url": f"https://thehive.corp/cases/{case_id}"}
                    ]
                }
            ]
        }

        self.sent_notifications.append(payload)
        logger.info(f"[Slack Alert] Dispatched {severity} alert for {case_id}")

        delivery_status = "simulated_local"
        if self.webhook_url and "MOCK" not in self.webhook_url and self.webhook_url.startswith("http"):
            try:
                import requests
                resp = requests.post(self.webhook_url, json=payload, timeout=3.0)
                delivery_status = f"delivered (HTTP {resp.status_code})"
            except Exception as e:
                logger.warning(f"[Slack Alert] Outbound webhook delivery failed: {e}")
                delivery_status = f"delivery_failed: {e}"

        return {
            "status": "dispatched",
            "delivery": delivery_status,
            "channel": "#soc-incidents",
            "payload": payload
        }
