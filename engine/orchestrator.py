import email.utils
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from engine.integrations.threat_intel import ThreatIntelService
from engine.integrations.identity import IdentityService
from engine.integrations.firewall import FirewallService
from engine.integrations.ticketing import CaseManagementService
from engine.integrations.notifier import NotificationService
from engine.integrations.wazuh_client import WazuhConnector
from engine.models import SecurityAlert, PendingInvestigation
from engine.enrichment import EnrichmentPipeline
from engine.investigator import LLMInvestigator
from engine.approval import ApprovalGate

logger = logging.getLogger("soar.orchestrator")

class SOAROrchestrator:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        
        integrations_cfg = self.config.get("integrations", {})
        vt_key = integrations_cfg.get("virustotal", {}).get("api_key", "")
        abuse_key = integrations_cfg.get("abuseipdb", {}).get("api_key", "")
        slack_url = integrations_cfg.get("slack", {}).get("webhook_url", "")
        fw_driver = integrations_cfg.get("firewall", {}).get("driver", "mock_iptables")
        id_driver = integrations_cfg.get("identity", {}).get("driver", "mock_okta")

        thresholds = self.config.get("thresholds", {})
        self.phishing_threshold = thresholds.get("phishing_malicious_engines", 3)
        self.abuse_score_threshold = thresholds.get("abuseipdb_confidence_score", 75)
        self.bruteforce_attempts_threshold = thresholds.get("brute_force_failed_attempts", 5)

        self.threat_intel = ThreatIntelService(vt_api_key=vt_key, abuse_api_key=abuse_key)
        self.identity = IdentityService(driver=id_driver)
        self.firewall = FirewallService(driver=fw_driver)
        self.ticketing = CaseManagementService()
        self.notifier = NotificationService(webhook_url=slack_url)
        self.wazuh = WazuhConnector()
        self.enrichment = EnrichmentPipeline(threat_intel=self.threat_intel, config=self.config)
        self.investigator = LLMInvestigator(config=self.config)
        self.approval_gate = ApprovalGate(
            firewall=self.firewall,
            identity=self.identity,
            ticketing=self.ticketing,
            notifier=self.notifier
        )
        self.execution_history: List[Dict[str, Any]] = []

    def investigate_alert(self, alert: SecurityAlert) -> PendingInvestigation:
        t0 = time.time()
        enrichment = self.enrichment.enrich(alert)
        verdict = self.investigator.investigate(alert, enrichment)
        pending = self.approval_gate.register(alert, enrichment, verdict)
        elapsed_ms = int((time.time() - t0) * 1000)

        execution_id = f"EXEC-{uuid.uuid4().hex[:8].upper()}"
        self.execution_history.insert(0, {
            "execution_id": execution_id,
            "playbook": "ai_investigator_triage",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "elapsed_ms": elapsed_ms,
            "status": "COMPLETED",
            "verdict": verdict.verdict,
            "summary": verdict.summary,
            "steps": [
                {"step": "ALERT_INGESTION", "status": "COMPLETED", "details": f"Ingested alert {alert.alert_id}: {alert.event_type}"},
                {"step": "ENRICHMENT_PIPELINE", "status": "COMPLETED", "details": f"Correlated {len(enrichment.threat_intel)} IOCs, asset/user context"},
                {"step": "LLM_INVESTIGATION", "status": "COMPLETED", "details": f"Verdict: {verdict.verdict} ({verdict.attack_technique})"},
                {"step": "APPROVAL_GATE", "status": "COMPLETED", "details": f"Registered in approval queue ({pending.status})"}
            ],
            "actions_taken": [f"{a.action_type}: {a.target}" for a in verdict.recommended_actions],
            "case_id": pending.investigation_id
        })
        if len(self.execution_history) > 500:
            self.execution_history = self.execution_history[:500]

        return pending

    def run_playbook(self, playbook_type: str, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        execution_id = f"EXEC-{uuid.uuid4().hex[:8].upper()}"
        start_time = time.time()
        steps = []

        try:
            if playbook_type == "phishing_triage":
                result = self._playbook_phishing(execution_id, alert_data, steps)
            elif playbook_type == "bruteforce_containment":
                result = self._playbook_bruteforce(execution_id, alert_data, steps)
            else:
                raise ValueError(f"Unknown playbook type: {playbook_type}")
        except Exception as e:
            logger.error(f"Playbook execution failed for {execution_id}: {e}", exc_info=True)
            result = {
                "status": "FAILED",
                "verdict": "EXECUTION_ERROR",
                "summary": f"Playbook failed with error: {str(e)}",
                "actions_taken": [],
                "case_id": None
            }

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
        if len(self.execution_history) > 500:
            self.execution_history = self.execution_history[:500]
        return execution_record

    def _playbook_phishing(self, exec_id: str, alert: Dict[str, Any], steps: List[Dict[str, Any]]) -> Dict[str, Any]:
        recipient = alert.get("recipient_email") or "user@apexfin.corp"
        sender = alert.get("sender_email") or "unknown@external.com"
        urls = alert.get("extracted_urls") or []
        sender_ip = alert.get("sender_ip") or "185.220.101.5"
        steps.append({"step": "INGEST_ALERT", "status": "COMPLETED", "details": f"Ingested email from {sender} to {recipient} with {len(urls)} URLs."})

        intel_findings = []
        is_malicious = False
        for url in urls:
            res = self.threat_intel.inspect_url(url)
            intel_findings.append(res)
            if res.get("verdict") == "MALICIOUS" or res.get("malicious_engines", 0) >= self.phishing_threshold:
                is_malicious = True
        steps.append({"step": "THREAT_INTEL_LOOKUP", "status": "COMPLETED", "details": f"Analyzed {len(urls)} URLs. Malicious verdict: {is_malicious}"})

        actions = []
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

            self.identity.revoke_user_sessions(recipient)
            actions.append(f"Revoked active SSO/OAuth tokens for {recipient}")
            self.ticketing.add_audit_log(case_id, f"Revoked active sessions for {recipient}")
            steps.append({"step": "CONTAIN_USER", "status": "COMPLETED", "details": f"Revoked user sessions for {recipient}."})

            sender_addr = email.utils.parseaddr(sender)[1]
            sender_domain = sender_addr.split("@")[-1] if "@" in sender_addr else "external-domain.com"
            self.firewall.block_domain(sender_domain, reason="Phishing domain delivery")
            self.firewall.block_ip(sender_ip, reason="Malicious email relay source")
            actions.append(f"Sinkholed sender domain {sender_domain} and blocked IP {sender_ip}")
            self.ticketing.add_audit_log(case_id, f"Blocked domain {sender_domain} and IP {sender_ip}")
            steps.append({"step": "FIREWALL_BLOCK", "status": "COMPLETED", "details": f"Injected perimeter block rules for {sender_ip}."})

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
            steps.append({"step": "DECISION_FILTER", "status": "COMPLETED", "details": "URLs confirmed safe by threat intelligence engines."})
            return {
                "status": "SUCCESS",
                "verdict": "BENIGN_CLEARED",
                "summary": f"Email from {sender} analyzed and cleared. No malicious IOCs detected.",
                "actions_taken": ["Logged benign telemetry entry."],
                "case_id": None
            }

    def _playbook_bruteforce(self, exec_id: str, alert: Dict[str, Any], steps: List[Dict[str, Any]]) -> Dict[str, Any]:
        attacker_ip = alert.get("attacker_ip") or "194.26.29.66"
        attempt_count = alert.get("attempt_count") if alert.get("attempt_count") is not None else 14
        service = alert.get("service") or "SSH / Honeypot"
        steps.append({"step": "INGEST_ALERT", "status": "COMPLETED", "details": f"Received {service} brute force alert from {attacker_ip} ({attempt_count} attempts)."})

        ip_intel = self.threat_intel.inspect_ip(attacker_ip)
        steps.append({"step": "THREAT_INTEL_LOOKUP", "status": "COMPLETED", "details": f"Abuse confidence: {ip_intel['abuse_confidence_score']}%, Country: {ip_intel['country']}"})

        actions = []
        is_threat = (
            ip_intel["verdict"] == "MALICIOUS" or 
            ip_intel.get("abuse_confidence_score", 0) >= self.abuse_score_threshold or 
            attempt_count >= self.bruteforce_attempts_threshold
        )
        if is_threat:
            severity = "HIGH"
            case = self.ticketing.create_case(
                title=f"Brute-Force Automated Mitigation: {service} Attacker {attacker_ip}",
                severity=severity,
                description=f"Hostile brute-force activity ({attempt_count} attempts) detected from {attacker_ip}.",
                iocs=[attacker_ip]
            )
            case_id = case["case_id"]

            fw_res = self.firewall.block_ip(attacker_ip, reason=f"High frequency {service} brute-force attack", ttl_minutes=1440)
            actions.append(f"Applied iptables DROP rule for {attacker_ip} (24h ban)")
            steps.append({"step": "FIREWALL_BLOCK", "status": "COMPLETED", "details": f"Injected rule: {fw_res['rule']}"})

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
