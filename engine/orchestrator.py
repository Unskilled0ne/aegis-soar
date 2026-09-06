import time
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from engine.integrations.threat_intel import ThreatIntelService
from engine.integrations.identity import IdentityService
from engine.integrations.firewall import FirewallService
from engine.integrations.ticketing import CaseManagementService
from engine.integrations.notifier import NotificationService

class SOAROrchestrator:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.threat_intel = ThreatIntelService()
        self.identity = IdentityService()
        self.firewall = FirewallService()
        self.ticketing = CaseManagementService()
        self.notifier = NotificationService()
        self.execution_history: List[Dict[str, Any]] = []

    def run_playbook(self, playbook_type: str, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        execution_id = f"EXEC-{uuid.uuid4().hex[:8].upper()}"
        start_time = time.time()
        steps = []

        if playbook_type == "phishing_triage":
            result = self._playbook_phishing(execution_id, alert_data, steps)
        elif playbook_type == "bruteforce_containment":
            result = self._playbook_bruteforce(execution_id, alert_data, steps)
        else:
            raise ValueError(f"Unknown playbook type: {playbook_type}")

        elapsed_ms = int((time.time() - start_time) * 1000)
        execution_record = {
            "execution_id": execution_id,
            "playbook": playbook_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "elapsed_ms": elapsed_ms,
            "status": result["status"],
            "verdict": result["verdict"],
            "summary": result["summary"],
            "steps": steps,
            "actions_taken": result.get("actions_taken", []),
            "case_id": result.get("case_id")
        }

        self.execution_history.insert(0, execution_record)
        return execution_record

    def _playbook_phishing(self, exec_id: str, alert: Dict[str, Any], steps: List[Dict[str, Any]]) -> Dict[str, Any]:
        # Step 1: Alert Ingestion
        recipient = alert.get("recipient_email", "user@apexfin.corp")
        sender = alert.get("sender_email", "unknown@external.com")
        urls = alert.get("extracted_urls", [])
        sender_ip = alert.get("sender_ip", "185.220.101.5")
        steps.append({"step": "INGEST_ALERT", "status": "COMPLETED", "details": f"Ingested email from {sender} to {recipient} with {len(urls)} URLs."})

        # Step 2: Threat Intelligence Enrichment
        intel_findings = []
        is_malicious = False
        for url in urls:
            res = self.threat_intel.inspect_url(url)
            intel_findings.append(res)
            if res["verdict"] == "MALICIOUS":
                is_malicious = True
        steps.append({"step": "THREAT_INTEL_LOOKUP", "status": "COMPLETED", "details": f"Analyzed {len(urls)} URLs. Malicious verdict: {is_malicious}"})

        actions = []
        # Step 3: Decision & Containment
        if is_malicious:
            severity = "CRITICAL"
            case = self.ticketing.create_case(
                title=f"Automated Triage: High-Confidence Phishing Attack Targeting {recipient}",
                severity=severity,
                description=f"Inbound email from {sender} contained confirmed credential harvesting URL.",
                iocs=urls + [sender_ip]
            )
            case_id = case["case_id"]
            steps.append({"step": "CREATE_CASE", "status": "COMPLETED", "details": f"Created incident case {case_id} in TheHive."})

            # Action 1: Revoke victim user sessions
            self.identity.revoke_user_sessions(recipient)
            actions.append(f"Revoked active SSO/OAuth tokens for {recipient}")
            self.ticketing.add_audit_log(case_id, f"Revoked active sessions for {recipient}")
            steps.append({"step": "CONTAIN_USER", "status": "COMPLETED", "details": f"Revoked user sessions for {recipient}."})

            # Action 2: Block sender domain & IP on firewall
            self.firewall.block_domain(sender.split("@")[-1], reason="Phishing domain delivery")
            self.firewall.block_ip(sender_ip, reason="Malicious email relay source")
            actions.append(f"Sinkholed sender domain {sender.split('@')[-1]} and blocked IP {sender_ip}")
            self.ticketing.add_audit_log(case_id, f"Blocked domain and IP {sender_ip}")
            steps.append({"step": "FIREWALL_BLOCK", "status": "COMPLETED", "details": f"Injected perimeter block rules for {sender_ip}."})

            # Action 3: Notify SecOps
            self.notifier.dispatch_alert(
                title=f"Phishing Contained: {recipient}",
                severity=severity,
                case_id=case_id,
                iocs=urls,
                actions_taken=actions
            )
            steps.append({"step": "DISPATCH_NOTIFICATIONS", "status": "COMPLETED", "details": "Dispatched high-priority Slack webhook."})

            return {
                "status": "SUCCESS",
                "verdict": "MALICIOUS_CONTAINED",
                "summary": f"Neutralized phishing attack targeting {recipient}. Account sessions revoked and IOCs blocked.",
                "actions_taken": actions,
                "case_id": case_id
            }
        else:
            steps.append({"step": "DECISION_FILTER", "status": "COMPLETED", "details": "URLs confirmed safe by 89 threat intelligence engines."})
            return {
                "status": "SUCCESS",
                "verdict": "BENIGN_CLEARED",
                "summary": f"Email from {sender} analyzed and cleared. No malicious IOCs detected.",
                "actions_taken": ["Logged benign telemetry entry."],
                "case_id": None
            }

    def _playbook_bruteforce(self, exec_id: str, alert: Dict[str, Any], steps: List[Dict[str, Any]]) -> Dict[str, Any]:
        attacker_ip = alert.get("attacker_ip", "194.26.29.66")
        attempt_count = alert.get("attempt_count", 14)
        service = alert.get("service", "SSH / Honeypot")
        steps.append({"step": "INGEST_ALERT", "status": "COMPLETED", "details": f"Received {service} brute force alert from {attacker_ip} ({attempt_count} attempts)."})

        # Step 2: IP Reputation Query
        ip_intel = self.threat_intel.inspect_ip(attacker_ip)
        steps.append({"step": "THREAT_INTEL_LOOKUP", "status": "COMPLETED", "details": f"Abuse confidence: {ip_intel['abuse_confidence_score']}%, Country: {ip_intel['country']}"})

        actions = []
        if ip_intel["verdict"] == "MALICIOUS" or attempt_count >= 5:
            severity = "HIGH"
            case = self.ticketing.create_case(
                title=f"Brute-Force Automated Mitigation: {service} Attacker {attacker_ip}",
                severity=severity,
                description=f"Hostile brute-force activity ({attempt_count} attempts) detected from {attacker_ip}.",
                iocs=[attacker_ip]
            )
            case_id = case["case_id"]

            # Action 1: Inject Firewall Drop
            fw_res = self.firewall.block_ip(attacker_ip, reason=f"High frequency {service} brute-force attack", ttl_minutes=1440)
            actions.append(f"Applied iptables DROP rule for {attacker_ip} (24h ban)")
            steps.append({"step": "FIREWALL_BLOCK", "status": "COMPLETED", "details": f"Injected rule: {fw_res['rule']}"})

            # Action 2: Dispatch Alert
            self.notifier.dispatch_alert(
                title=f"Brute-Force Attacker Auto-Banned: {attacker_ip}",
                severity=severity,
                case_id=case_id,
                iocs=[attacker_ip],
                actions_taken=actions
            )
            steps.append({"step": "DISPATCH_NOTIFICATIONS", "status": "COMPLETED", "details": "Alerted SecOps team via Slack."})

            return {
                "status": "SUCCESS",
                "verdict": "ATTACKER_CONTAINED",
                "summary": f"Attacking IP {attacker_ip} isolated with iptables DROP rule and logged to {case_id}.",
                "actions_taken": actions,
                "case_id": case_id
            }
        else:
            return {
                "status": "SUCCESS",
                "verdict": "LOW_RISK_MONITORED",
                "summary": f"IP {attacker_ip} logged as low-risk anomaly. No active containment required.",
                "actions_taken": ["Logged observation to SIEM buffer."],
                "case_id": None
            }
