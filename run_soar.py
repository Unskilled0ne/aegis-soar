#!/usr/bin/env python3
import argparse
import sys
import uvicorn
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from engine.orchestrator import SOAROrchestrator
from engine.server import app

console = Console()

def run_cli_simulations():
    orchestrator = SOAROrchestrator()

    console.print()
    console.print(Panel.fit(
        "[bold green]Aegis-SOAR Automated Incident Response Test Suite[/bold green]\n"
        "[dim]Orchestrating Security Triage, Threat Intel, Identity Revocation, and Firewall Containment[/dim]",
        border_style="green"
    ))

    
    console.print("[bold yellow][*] Executing Playbook 1: Phishing Credential Harvester Triage...[/bold yellow]")
    phish_alert = {
        "recipient_email": "v.tsiamouras@apexfin.corp",
        "sender_email": "security-alert@login-microsoft-verify.top",
        "sender_ip": "185.220.101.5",
        "extracted_urls": ["https://login-microsoft-verify.top/auth/session-token"]
    }
    r1 = orchestrator.run_playbook("phishing_triage", phish_alert)

    
    console.print("[bold yellow][*] Executing Playbook 2: ShadowPot Honeypot Attacker Auto-Isolation...[/bold yellow]")
    brute_alert = {
        "attacker_ip": "194.26.29.66",
        "attempt_count": 18,
        "service": "ShadowPot SSH Honeypot"
    }
    r2 = orchestrator.run_playbook("bruteforce_containment", brute_alert)

    
    console.print("[bold cyan][*] Executing Playbook 3: Benign Corporate Communication Triage...[/bold cyan]")
    benign_alert = {
        "recipient_email": "v.tsiamouras@apexfin.corp",
        "sender_email": "newsletter@partner-bank.com",
        "sender_ip": "54.240.8.10",
        "extracted_urls": ["https://partner-bank.com/insights/q3-report"]
    }
    r3 = orchestrator.run_playbook("phishing_triage", benign_alert)

    
    table = Table(title="SOAR Orchestration Execution Audit Trail", border_style="dim")
    table.add_column("Exec ID", style="bold cyan")
    table.add_column("Playbook", style="bold white")
    table.add_column("Verdict", justify="center")
    table.add_column("Latency", justify="center", style="yellow")
    table.add_column("Automated Actions Taken", style="dim")
    table.add_column("Case ID", justify="center", style="bold green")

    for r in [r1, r2, r3]:
        verdict_badge = f"[bold red]{r['verdict']}[/bold red]" if "CONTAINED" in r["verdict"] else f"[bold green]{r['verdict']}[/bold green]"
        table.add_row(
            r["execution_id"],
            r["playbook"],
            verdict_badge,
            f"{r['elapsed_ms']}ms",
            "; ".join(r["actions_taken"])[:55] + "...",
            r["case_id"] or "-"
        )

    console.print()
    console.print(table)
    console.print()

def main():
    parser = argparse.ArgumentParser(description="Aegis-SOAR Incident Response Platform")
    parser.add_argument("--test", action="store_true", help="Run automated CLI incident simulation test")
    parser.add_argument("--serve", action="store_true", help="Launch interactive web dashboard")
    parser.add_argument("--port", type=int, default=8082, help="Web dashboard port (default: 8082)")
    args = parser.parse_args()

    if args.test or not args.serve:
        run_cli_simulations()

    if args.serve:
        console.print(f"[bold green]Starting Aegis-SOAR Dashboard on http://0.0.0.0:{args.port}...[/bold green]")
        uvicorn.run(app, host="0.0.0.0", port=args.port, log_level="warning")

if __name__ == "__main__":
    main()
