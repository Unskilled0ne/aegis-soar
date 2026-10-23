import re
import uuid
from typing import Dict, Any, List, Optional
import requests
from engine.models import SecurityAlert

class WazuhConnector:
    def __init__(self, api_url: str = "", username: str = "", password: str = ""):
        self.api_url = api_url.rstrip("/")
        self.username = username
        self.password = password
        self._jwt_token: Optional[str] = None

    def parse_webhook_alert(self, payload: Dict[str, Any]) -> SecurityAlert:
        alert_id = payload.get("id") or f"WAZUH-{uuid.uuid4().hex[:8].upper()}"
        timestamp = payload.get("timestamp") or payload.get("@timestamp") or ""
        
        rule = payload.get("rule", {})
        rule_id = str(rule.get("id", ""))
        rule_desc = rule.get("description", "Wazuh Security Event")
        rule_level = rule.get("level", 5)

        severity_map = {
            12: "CRITICAL",
            10: "HIGH",
            7: "MEDIUM",
            3: "LOW"
        }
        severity = "LOW"
        for threshold, level_name in sorted(severity_map.items(), reverse=True):
            if rule_level >= threshold:
                severity = level_name
                break

        data = payload.get("data", {})
        full_log = payload.get("full_log") or data.get("full_log", "")

        src_ip = data.get("srcip") or data.get("source_ip") or data.get("src_ip")
        if not src_ip and full_log:
            ip_match = re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", full_log)
            if ip_match:
                src_ip = ip_match.group(0)

        dst_ip = data.get("dstip") or data.get("destination_ip")
        user = data.get("dstuser") or data.get("srcuser") or data.get("user")

        extracted_urls = []
        if full_log:
            extracted_urls = re.findall(r"https?://[^\s)\]\">]+", full_log)
        if "url" in data and data["url"]:
            extracted_urls.append(data["url"])

        file_hashes = []
        if full_log:
            sha256_matches = re.findall(r"\b[a-fA-F0-9]{64}\b", full_log)
            file_hashes.extend(sha256_matches)
        if "sha256" in data and data["sha256"]:
            file_hashes.append(data["sha256"])

        agent = payload.get("agent", {})
        target_host = agent.get("name") or payload.get("location", "")

        return SecurityAlert(
            alert_id=alert_id,
            source="wazuh",
            timestamp=timestamp,
            event_type=rule_desc,
            severity=severity,
            rule_id=rule_id,
            rule_description=rule_desc,
            source_ip=src_ip,
            destination_ip=dst_ip,
            user_identity=user,
            target_host=target_host,
            extracted_urls=list(set(extracted_urls)),
            file_hashes=list(set(file_hashes)),
            raw_log=full_log,
            metadata=payload
        )
