"""Report generation for security scan results."""

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.markdown import Markdown
from rich.table import Table
from rich.markup import escape

from .fix_generator import FixProposal
from .scanner import Finding
from .triage import TriageResult


@dataclass
class ScanReport:
    """Complete security scan report."""

    scan_time: str
    target_path: str
    total_findings: int
    confirmed_vulnerabilities: int
    false_positives: int
    needs_review: int
    findings: list["ReportedFinding"]

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON export."""
        return {
            "scan_time": self.scan_time,
            "target_path": self.target_path,
            "summary": {
                "total_findings": self.total_findings,
                "confirmed_vulnerabilities": self.confirmed_vulnerabilities,
                "false_positives": self.false_positives,
                "needs_review": self.needs_review,
            },
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class ReportedFinding:
    """A finding with triage results and fix proposal."""

    finding: Finding
    triage: Optional[TriageResult] = None
    fix: Optional[FixProposal] = None

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        result = {
            "rule_id": self.finding.rule_id,
            "message": self.finding.message,
            "file": self.finding.file,
            "line": self.finding.line,
            "end_line": self.finding.end_line,
            "column": self.finding.column,
            "severity": self.finding.severity,
            "code_snippet": self.finding.code_snippet,
            "metadata": self.finding.metadata,
        }

        if self.triage:
            result["triage"] = {
                "decision": self.triage.decision.value,
                "confidence": self.triage.confidence,
                "explanation": self.triage.explanation,
                "exploit_scenario": self.triage.exploit_scenario,
                "recommended_action": self.triage.recommended_action,
            }

        if self.fix:
            result["fix"] = {
                "fixed_code": self.fix.fixed_code,
                "explanation": self.fix.explanation,
                "diff_summary": self.fix.diff_summary,
                "confidence": self.fix.confidence,
            }

        return result


class Reporter:
    """Generate security scan reports in various formats."""

    def __init__(self, console: Optional[Console] = None):
        """Initialize the reporter."""
        self.console = console or Console()

    def create_report(
        self,
        target_path: str,
        findings: list[Finding],
        triage_results: list[TriageResult],
        fixes: list[Optional[FixProposal]],
    ) -> ScanReport:
        """
        Create a complete scan report.

        Args:
            target_path: Path that was scanned
            findings: List of findings from Semgrep
            triage_results: List of triage results
            fixes: List of fix proposals (can be None for false positives)

        Returns:
            ScanReport object
        """
        reported_findings = []
        confirmed = 0
        false_pos = 0
        needs_review = 0

        for i, finding in enumerate(findings):
            triage = triage_results[i] if i < len(triage_results) else None
            fix = fixes[i] if i < len(fixes) else None

            reported_findings.append(
                ReportedFinding(finding=finding, triage=triage, fix=fix)
            )

            if triage:
                if triage.decision.value == "true_positive":
                    confirmed += 1
                elif triage.decision.value == "false_positive":
                    false_pos += 1
                else:
                    needs_review += 1

        return ScanReport(
            scan_time=datetime.now().isoformat(),
            target_path=str(target_path),
            total_findings=len(findings),
            confirmed_vulnerabilities=confirmed,
            false_positives=false_pos,
            needs_review=needs_review,
            findings=reported_findings,
        )

    def print_console(self, report: ScanReport) -> None:
        """Print a formatted report to the console."""
        self.console.print("\n[bold blue]" + "=" * 60 + "[/bold blue]")
        self.console.print("[bold white]AI SECURITY SCAN REPORT[/bold white]")
        self.console.print("[bold blue]" + "=" * 60 + "[/bold blue]\n")

        # Summary
        self.console.print(f"[dim]Scan Time:[/dim] {report.scan_time}")
        self.console.print(f"[dim]Target:[/dim] {report.target_path}\n")

        # Summary table
        table = Table(title="Summary", show_header=True)
        table.add_column("Metric", style="cyan")
        table.add_column("Count", justify="right")

        table.add_row("Total Findings", str(report.total_findings))

        if report.confirmed_vulnerabilities > 0:
            table.add_row(
                "Confirmed Vulnerabilities",
                str(report.confirmed_vulnerabilities),
                style="red",
            )
        if report.false_positives > 0:
            table.add_row("False Positives", str(report.false_positives), style="green")
        if report.needs_review > 0:
            table.add_row("Needs Review", str(report.needs_review), style="yellow")

        self.console.print(table)
        self.console.print()

        # Detailed findings
        if report.findings:
            self.console.print("[bold]Detailed Findings[/bold]\n")

            for i, finding in enumerate(report.findings, 1):
                self._print_finding(finding, i)

    def _print_finding(self, reported: ReportedFinding, index: int) -> None:
        """Print a single finding detail."""
        finding = reported.finding
        triage = reported.triage

        severity_color = {
            "CRITICAL": "red",
            "ERROR": "red",
            "WARNING": "yellow",
            "INFO": "blue",
        }.get(finding.severity.upper(), "white")

        self.console.print(
            f"[bold {severity_color}]#{index} [{finding.severity}] {escape(finding.rule_id)}[/bold {severity_color}]"
        )
        self.console.print(f"  [dim]File:[/dim] {escape(finding.file)}:{finding.line}")
        self.console.print(f"  [dim]Message:[/dim] {escape(finding.message)}\n")

        if triage:
            decision_emoji = {
                "true_positive": "X",
                "false_positive": "OK",
                "needs_review": "?",
            }.get(triage.decision.value, " ")

            self.console.print(
                f"  [{decision_emoji}] [bold]Triage:[/bold] {triage.decision.value.replace('_', ' ').title()}"
            )
            self.console.print(f"  [dim]Confidence:[/dim] {escape(triage.confidence)}")
            self.console.print(f"  [dim]Explanation:[/dim] {escape(triage.explanation)}\n")

            if triage.exploit_scenario and triage.exploit_scenario != "N/A":
                self.console.print(
                    f"  [bold red]Exploit:[/bold red] {escape(triage.exploit_scenario)}\n"
                )

            if reported.fix:
                self.console.print(
                    f"  [bold green]Fix:[/bold green] {escape(reported.fix.diff_summary)}"
                )
                self.console.print(
                    f"  [dim]{escape(reported.fix.fixed_code[:200])}...[/dim]\n"
                )

        self.console.print("[dim]" + "-" * 40 + "[/dim]\n")

    def export_markdown(self, report: ScanReport, output_path: str) -> str:
        """Export report to Markdown format."""
        md = f"""# AI Security Scan Report

**Scan Time**: {report.scan_time}
**Target**: {report.target_path}

## Summary

| Metric | Count |
|--------|-------|
| Total Findings | {report.total_findings} |
| Confirmed Vulnerabilities | {report.confirmed_vulnerabilities} |
| False Positives | {report.false_positives} |
| Needs Review | {report.needs_review} |

## Detailed Findings

"""

        for i, finding in enumerate(report.findings, 1):
            md += self._finding_to_markdown(finding, i)

        output_file = Path(output_path)
        output_file.write_text(md)
        return str(output_file)

    def _finding_to_markdown(self, reported: ReportedFinding, index: int) -> str:
        """Convert a finding to Markdown."""
        finding = reported.finding
        triage = reported.triage
        fix = reported.fix

        md = f"""### #{index} [{finding.severity}] {finding.rule_id}

**File**: `{finding.file}:{finding.line}`
**Message**: {finding.message}

"""

        if triage:
            md += f"""**Triage Decision**: {triage.decision.value.replace('_', ' ').title()}
**Confidence**: {triage.confidence}

**Explanation**:
{triage.explanation}

"""
            if triage.exploit_scenario and triage.exploit_scenario != "N/A":
                md += f"""**Exploit Scenario**:
{triage.exploit_scenario}

"""

        if fix:
            md += f"""**Recommended Fix**:
```
{fix.fixed_code}
```

**Fix Explanation**: {fix.explanation}

"""

        md += "---\n\n"
        return md

    def export_json(self, report: ScanReport, output_path: str) -> str:
        """Export report to JSON format."""
        output_file = Path(output_path)
        output_file.write_text(json.dumps(report.to_dict(), indent=2))
        return str(output_file)
