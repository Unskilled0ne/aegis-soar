from datetime import datetime, timezone
import logging
from typing import Dict, Any, List, Optional
import uuid

from engine.models import SecurityAlert, EnrichmentContext, InvestigationVerdict, PendingInvestigation
from engine.integrations.firewall import FirewallService
from engine.integrations.identity import IdentityService
from engine.integrations.ticketing import CaseManagementService
from engine.integrations.notifier import NotificationService

logger = logging.getLogger("soar.approval")

class ApprovalGate:
    def __init__(
        self,
        firewall: FirewallService,
        identity: IdentityService,
        ticketing: CaseManagementService,
        notifier: NotificationService
    ):
        self.firewall = firewall
        self.identity = identity
        self.ticketing = ticketing
        self.notifier = notifier
        self.investigations: Dict[str, PendingInvestigation] = {}

    def register(
        self,
        alert: SecurityAlert,
        enrichment: EnrichmentContext,
        verdict: InvestigationVerdict
    ) -> PendingInvestigation:
        inv_id = f"INV-{uuid.uuid4().hex[:8].upper()}"
        
        has_containment = any(
            a.action_type not in ("NO_ACTION",) for a in verdict.recommended_actions
        )
        status = "PENDING_APPROVAL" if has_containment else "RESOLVED_BENIGN"

        pending = PendingInvestigation(
            investigation_id=inv_id,
            alert=alert,
            enrichment=enrichment,
            verdict=verdict,
            status=status if status == "PENDING_APPROVAL" else "REJECTED"
        )
        self.investigations[inv_id] = pending
        return pending

    def list_pending(self) -> List[PendingInvestigation]:
        return [
            inv for inv in self.investigations.values()
            if inv.status == "PENDING_APPROVAL"
        ]

    def get_investigation(self, investigation_id: str) -> Optional[PendingInvestigation]:
        return self.investigations.get(investigation_id)

    def approve(
        self,
        investigation_id: str,
        analyst_id: str = "analyst@apexfin.corp",
        notes: str = ""
    ) -> Dict[str, Any]:
        inv = self.investigations.get(investigation_id)
        if not inv:
            raise KeyError(f"Investigation {investigation_id} not found.")

        if inv.status != "PENDING_APPROVAL":
            return {
                "status": "error",
                "message": f"Investigation {investigation_id} is already in state '{inv.status}'."
            }

        executed_actions = []
        case_id = None

        for action in inv.verdict.recommended_actions:
            if action.action_type == "FIREWALL_BLOCK_IP":
                self.firewall.block_ip(action.target, reason=action.reason)
                executed_actions.append(f"Firewall: Blocked IP {action.target}")
            elif action.action_type == "BLOCK_DOMAIN":
                self.firewall.block_domain(action.target, reason=action.reason)
                executed_actions.append(f"Firewall: Sinkholed domain {action.target}")
            elif action.action_type == "REVOKE_USER_SESSIONS":
                self.identity.revoke_user_sessions(action.target)
                executed_actions.append(f"Identity: Revoked active sessions for {action.target}")
            elif action.action_type == "DISABLE_USER_ACCOUNT":
                self.identity.disable_account(action.target, reason=action.reason)
                executed_actions.append(f"Identity: Disabled account {action.target}")
            elif action.action_type == "CREATE_THEHIVE_CASE":
                c = self.ticketing.create_case(
                    title=f"[Analyst Approved] {inv.verdict.attack_technique}: {inv.alert.event_type}",
                    severity="CRITICAL" if inv.verdict.risk_score > 75 else "HIGH",
                    description=inv.verdict.summary,
                    iocs=[inv.alert.source_ip] if inv.alert.source_ip else []
                )
                case_id = c["case_id"]
                executed_actions.append(f"Ticketing: Created Case {case_id}")

        self.notifier.dispatch_alert(
            title=f"Containment Executed: {inv.alert.event_type}",
            severity="CRITICAL" if inv.verdict.risk_score > 75 else "HIGH",
            case_id=case_id or "N/A",
            iocs=[inv.alert.source_ip] if inv.alert.source_ip else [],
            actions_taken=executed_actions
        )

        inv.status = "APPROVED_CONTAINED"
        inv.resolved_at = datetime.now(timezone.utc).isoformat()
        inv.resolved_by = analyst_id
        inv.resolution_notes = notes
        inv.actions_executed = executed_actions

        return {
            "status": "success",
            "investigation_id": investigation_id,
            "verdict": inv.verdict.verdict,
            "actions_executed": executed_actions,
            "case_id": case_id,
            "approved_by": analyst_id
        }

    def reject(
        self,
        investigation_id: str,
        analyst_id: str = "analyst@apexfin.corp",
        notes: str = ""
    ) -> Dict[str, Any]:
        inv = self.investigations.get(investigation_id)
        if not inv:
            raise KeyError(f"Investigation {investigation_id} not found.")

        if inv.status != "PENDING_APPROVAL":
            return {
                "status": "error",
                "message": f"Investigation {investigation_id} is already in state '{inv.status}'."
            }

        inv.status = "REJECTED"
        inv.resolved_at = datetime.now(timezone.utc).isoformat()
        inv.resolved_by = analyst_id
        inv.resolution_notes = notes or "Marked as false positive by analyst."
        inv.actions_executed = ["Containment aborted - marked false positive"]

        return {
            "status": "success",
            "investigation_id": investigation_id,
            "resolution": "REJECTED_FALSE_POSITIVE",
            "resolved_by": analyst_id,
            "notes": inv.resolution_notes
        }
