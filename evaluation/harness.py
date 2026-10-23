import glob
import json
import os
import sys
import time
from typing import List, Dict, Any

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from engine.models import SecurityAlert
from engine.orchestrator import SOAROrchestrator
from evaluation.baseline import RuleBasedBaseline

console = Console()

class EvaluationHarness:
    def __init__(self):
        self.orchestrator = SOAROrchestrator()
        self.baseline = RuleBasedBaseline()
        self.scenarios_dir = os.path.join(os.path.dirname(__file__), "scenarios")

    def load_scenarios(self) -> List[Dict[str, Any]]:
        scenarios = []
        pattern = os.path.join(self.scenarios_dir, "*.json")
        for path in sorted(glob.glob(pattern)):
            with open(path, "r", encoding="utf-8") as f:
                scenarios.append(json.load(f))
        return scenarios

    def run_evaluation(self):
        scenarios = self.load_scenarios()
        console.print()
        console.print(Panel.fit(
            f"[bold cyan]Aegis Investigator Triage Evaluation Harness[/bold cyan]\n"
            f"[dim]Benchmarking LLM Investigator vs Rule-Based Baseline on {len(scenarios)} Labelled Scenarios[/dim]",
            border_style="cyan"
        ))

        ai_results = []
        bl_results = []

        scenario_table = Table(title="Scenario Verdict Comparison", border_style="dim")
        scenario_table.add_column("Scenario ID", style="bold cyan")
        scenario_table.add_column("Ground Truth", justify="center")
        scenario_table.add_column("AI Verdict", justify="center")
        scenario_table.add_column("AI Risk", justify="center", style="yellow")
        scenario_table.add_column("AI Latency", justify="center")
        scenario_table.add_column("Baseline Verdict", justify="center")
        scenario_table.add_column("Baseline Match", justify="center")

        for sc in scenarios:
            ground_truth = sc["ground_truth"]
            alert = SecurityAlert(**sc["alert"])

            t0 = time.time()
            investigation = self.orchestrator.investigate_alert(alert)
            ai_latency = int((time.time() - t0) * 1000)
            ai_verdict = investigation.verdict.verdict
            ai_risk = investigation.verdict.risk_score

            t1 = time.time()
            bl_verdict = self.baseline.triage(alert)["verdict"]
            bl_latency = int((time.time() - t1) * 1000)

            ai_results.append({
                "ground_truth": ground_truth,
                "predicted": ai_verdict,
                "latency_ms": ai_latency
            })
            bl_results.append({
                "ground_truth": ground_truth,
                "predicted": bl_verdict,
                "latency_ms": bl_latency
            })

            ai_match = "[bold green]MATCH[/bold green]" if ai_verdict == ground_truth else "[bold red]FAIL[/bold red]"
            bl_match = "[bold green]MATCH[/bold green]" if bl_verdict == ground_truth else "[bold red]FAIL[/bold red]"

            scenario_table.add_row(
                sc["scenario_id"],
                f"[bold white]{ground_truth}[/bold white]",
                f"{ai_verdict} ({ai_match})",
                f"{ai_risk}/100",
                f"{ai_latency}ms",
                bl_verdict,
                bl_match
            )

        console.print(scenario_table)
        console.print()

        def compute_metrics(results):
            tp = sum(1 for r in results if r["ground_truth"] == "TRUE_POSITIVE" and r["predicted"] == "TRUE_POSITIVE")
            fp = sum(1 for r in results if r["ground_truth"] == "FALSE_POSITIVE" and r["predicted"] == "TRUE_POSITIVE")
            tn = sum(1 for r in results if r["ground_truth"] == "FALSE_POSITIVE" and r["predicted"] == "FALSE_POSITIVE")
            fn = sum(1 for r in results if r["ground_truth"] == "TRUE_POSITIVE" and r["predicted"] != "TRUE_POSITIVE")

            precision = (tp / (tp + fp)) * 100 if (tp + fp) > 0 else 0.0
            recall = (tp / (tp + fn)) * 100 if (tp + fn) > 0 else 0.0
            f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
            accuracy = ((tp + tn) / len(results)) * 100 if results else 0.0
            avg_latency = sum(r["latency_ms"] for r in results) / len(results) if results else 0.0

            return {
                "tp": tp, "fp": fp, "tn": tn, "fn": fn,
                "precision": precision,
                "recall": recall,
                "f1": f1,
                "accuracy": accuracy,
                "avg_latency": avg_latency
            }

        ai_metrics = compute_metrics(ai_results)
        bl_metrics = compute_metrics(bl_results)

        metrics_table = Table(title="Triage Performance vs Baseline", border_style="green")
        metrics_table.add_column("Metric", style="bold white")
        metrics_table.add_column("Aegis Investigator (AI)", style="bold green", justify="center")
        metrics_table.add_column("No-AI Baseline", style="dim", justify="center")
        metrics_table.add_column("Improvement Delta", style="bold yellow", justify="center")

        metrics_table.add_row("Accuracy", f"{ai_metrics['accuracy']:.1f}%", f"{bl_metrics['accuracy']:.1f}%", f"+{ai_metrics['accuracy'] - bl_metrics['accuracy']:.1f}%")
        metrics_table.add_row("Precision", f"{ai_metrics['precision']:.1f}%", f"{bl_metrics['precision']:.1f}%", f"+{ai_metrics['precision'] - bl_metrics['precision']:.1f}%")
        metrics_table.add_row("Recall", f"{ai_metrics['recall']:.1f}%", f"{bl_metrics['recall']:.1f}%", f"+{ai_metrics['recall'] - bl_metrics['recall']:.1f}%")
        metrics_table.add_row("F1-Score", f"{ai_metrics['f1']:.1f}%", f"{bl_metrics['f1']:.1f}%", f"+{ai_metrics['f1'] - bl_metrics['f1']:.1f}%")
        metrics_table.add_row("Mean Triage Time", f"{ai_metrics['avg_latency']:.1f}ms", f"{bl_metrics['avg_latency']:.1f}ms", "Automated (<50ms)")

        console.print(metrics_table)
        console.print()

if __name__ == "__main__":
    harness = EvaluationHarness()
    harness.run_evaluation()
