from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Literal
from pydantic import BaseModel, Field

class TimelineEvent(BaseModel):
    timestamp: str
    source: str
    event: str

class RecommendedAction(BaseModel):
    action_type: Literal[
        "FIREWALL_BLOCK_IP",
        "BLOCK_DOMAIN",
        "REVOKE_USER_SESSIONS",
        "DISABLE_USER_ACCOUNT",
        "ISOLATE_HOST",
        "CREATE_THEHIVE_CASE",
        "NO_ACTION"
    ]
    target: str
    reason: str
    parameters: Dict[str, Any] = Field(default_factory=dict)

class InvestigationVerdict(BaseModel):
    verdict: Literal["TRUE_POSITIVE", "FALSE_POSITIVE", "SUSPICIOUS", "INSUFFICIENT_DATA"]
    confidence: float = Field(..., ge=0.0, le=1.0)
    risk_score: int = Field(..., ge=1, le=100)
    attack_tactic: str
    attack_technique: str
    summary: str
    timeline: List[TimelineEvent] = Field(default_factory=list)
    evidence: List[str] = Field(default_factory=list)
    recommended_actions: List[RecommendedAction] = Field(default_factory=list)

class SecurityAlert(BaseModel):
    alert_id: str
    source: str = "wazuh"
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    event_type: str
    severity: str = "MEDIUM"
    rule_id: Optional[str] = None
    rule_description: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    user_identity: Optional[str] = None
    target_host: Optional[str] = None
    extracted_urls: List[str] = Field(default_factory=list)
    file_hashes: List[str] = Field(default_factory=list)
    raw_log: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

class UserContext(BaseModel):
    username: str
    email: str
    department: str = "Engineering"
    role: str = "Standard User"
    is_vip: bool = False
    mfa_enabled: bool = True
    account_status: str = "ACTIVE"

class AssetContext(BaseModel):
    hostname: str
    ip_address: str
    asset_criticality: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] = "MEDIUM"
    environment: Literal["production", "staging", "development", "corporate"] = "production"
    os: str = "Linux Ubuntu 22.04"
    owner: str = "SecOps"

class EnrichmentContext(BaseModel):
    alert_id: str
    threat_intel: Dict[str, Any] = Field(default_factory=dict)
    user_context: Optional[UserContext] = None
    asset_context: Optional[AssetContext] = None
    correlated_logs: List[Dict[str, Any]] = Field(default_factory=list)

class PendingInvestigation(BaseModel):
    investigation_id: str
    alert: SecurityAlert
    enrichment: EnrichmentContext
    verdict: InvestigationVerdict
    status: Literal["PENDING_APPROVAL", "APPROVED_CONTAINED", "REJECTED", "EXPIRED"] = "PENDING_APPROVAL"
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    resolved_at: Optional[str] = None
    resolved_by: Optional[str] = None
    resolution_notes: Optional[str] = None
    actions_executed: List[str] = Field(default_factory=list)
