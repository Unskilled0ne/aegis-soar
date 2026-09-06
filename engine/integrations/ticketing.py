import uuid
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List

logger = logging.getLogger("soar.ticketing")

class CaseManagementService:
    def __init__(self, platform: str = "TheHive"):
        self.platform = platform
        self.cases: Dict[str, Dict[str, Any]] = {}

    def create_case(self, title: str, severity: str, description: str, iocs: List[str]) -> Dict[str, Any]:
        case_id = f"CASE-{uuid.uuid4().hex[:8].upper()}"
        case = {
            "case_id": case_id,
            "title": title,
            "severity": severity,
            "status": "OPEN",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "description": description,
            "iocs": iocs,
            "task_log": ["Case opened automatically by SOAR playbook."]
        }
        self.cases[case_id] = case
        logger.info(f"[{self.platform}] Created incident case {case_id}: {title} [{severity}]")
        return case

    def add_audit_log(self, case_id: str, message: str):
        if case_id in self.cases:
            self.cases[case_id]["task_log"].append(message)

    def close_case(self, case_id: str, resolution: str) -> Dict[str, Any]:
        if case_id in self.cases:
            self.cases[case_id]["status"] = "RESOLVED"
            self.cases[case_id]["resolution"] = resolution
            self.cases[case_id]["closed_at"] = datetime.now(timezone.utc).isoformat()
            return self.cases[case_id]
        return {}
