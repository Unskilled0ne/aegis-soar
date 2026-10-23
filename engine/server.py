import os
import yaml
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from engine.orchestrator import SOAROrchestrator

def load_config() -> Dict[str, Any]:
    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.yaml")
    if os.path.exists(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception:
            pass
    return {}

config = load_config()
orchestrator = SOAROrchestrator(config=config)

app_title = config.get("soar", {}).get("name", "Aegis-SOAR Incident Response Orchestrator")
app_version = config.get("soar", {}).get("version", "1.0.0")
app = FastAPI(title=app_title, version=app_version)

static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

class WebhookAlert(BaseModel):
    playbook: str = Field(default="phishing_triage", description="'phishing_triage' or 'bruteforce_containment'")
    recipient_email: Optional[str] = None
    sender_email: Optional[str] = None
    sender_ip: Optional[str] = None
    extracted_urls: List[str] = []
    attacker_ip: Optional[str] = None
    attempt_count: Optional[int] = None
    service: Optional[str] = None

@app.get("/", response_class=HTMLResponse)
async def index():
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return HTMLResponse("<h1>Aegis-SOAR Orchestrator</h1><p>static/index.html missing.</p>")

@app.post("/api/v1/alerts/webhook")
async def receive_webhook(alert: WebhookAlert):
    if alert.playbook == "phishing_triage":
        if not alert.recipient_email and not alert.sender_email and not alert.extracted_urls:
            raise HTTPException(
                status_code=400,
                detail="Invalid phishing alert: must specify recipient_email, sender_email, or extracted_urls."
            )
    elif alert.playbook == "bruteforce_containment":
        if not alert.attacker_ip:
            raise HTTPException(
                status_code=400,
                detail="Invalid brute-force alert: must specify attacker_ip."
            )
    else:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown playbook '{alert.playbook}'. Supported: phishing_triage, bruteforce_containment."
        )

    try:
        record = orchestrator.run_playbook(alert.playbook, alert.model_dump())
        return record
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/executions")
async def get_executions():
    return orchestrator.execution_history

@app.post("/api/v1/alerts/wazuh")
async def ingest_wazuh_alert(payload: Dict[str, Any]):
    try:
        alert = orchestrator.wazuh.parse_webhook_alert(payload)
        investigation = orchestrator.investigate_alert(alert)
        return investigation
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/alerts/investigate")
async def investigate_alert_endpoint(payload: Dict[str, Any]):
    try:
        from engine.models import SecurityAlert
        import uuid
        if "alert_id" not in payload:
            payload["alert_id"] = f"ALT-{uuid.uuid4().hex[:8].upper()}"
        alert = SecurityAlert(**payload)
        investigation = orchestrator.investigate_alert(alert)
        return investigation
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/v1/verdicts/pending")
async def list_pending_verdicts():
    return orchestrator.approval_gate.list_pending()

@app.get("/api/v1/verdicts/{investigation_id}")
async def get_verdict_details(investigation_id: str):
    inv = orchestrator.approval_gate.get_investigation(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return inv

class ApprovalDecision(BaseModel):
    analyst_id: str = "analyst@apexfin.corp"
    notes: Optional[str] = "Approved after review"

@app.post("/api/v1/verdicts/{investigation_id}/approve")
async def approve_verdict(investigation_id: str, decision: ApprovalDecision = ApprovalDecision()):
    try:
        result = orchestrator.approval_gate.approve(
            investigation_id=investigation_id,
            analyst_id=decision.analyst_id,
            notes=decision.notes or ""
        )
        return result
    except KeyError:
        raise HTTPException(status_code=404, detail="Investigation not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/verdicts/{investigation_id}/reject")
async def reject_verdict(investigation_id: str, decision: ApprovalDecision = ApprovalDecision()):
    try:
        result = orchestrator.approval_gate.reject(
            investigation_id=investigation_id,
            analyst_id=decision.analyst_id,
            notes=decision.notes or ""
        )
        return result
    except KeyError:
        raise HTTPException(status_code=404, detail="Investigation not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


