import os
from typing import Dict, Any, List
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from engine.orchestrator import SOAROrchestrator

orchestrator = SOAROrchestrator()

app = FastAPI(title="Aegis-SOAR Incident Response Orchestrator", version="1.0.0")

static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

class WebhookAlert(BaseModel):
    playbook: str = "phishing_triage"  # "phishing_triage" or "bruteforce_containment"
    recipient_email: str = "user@apexfin.corp"
    sender_email: str = "unknown@external.com"
    sender_ip: str = "185.220.101.5"
    extracted_urls: List[str] = []
    attacker_ip: str = "194.26.29.66"
    attempt_count: int = 10
    service: str = "SSH Service"

@app.get("/", response_class=HTMLResponse)
async def index():
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Aegis-SOAR Orchestrator</h1><p>static/index.html missing.</p>"

@app.post("/api/v1/alerts/webhook")
async def receive_webhook(alert: WebhookAlert):
    try:
        record = orchestrator.run_playbook(alert.playbook, alert.model_dump())
        return record
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/executions")
async def get_executions():
    return orchestrator.execution_history
