"""Command-line interface for the AI Security Scanner."""

import os
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console

from .fix_generator import FixGenerator
from .reporter import Reporter, ScanReport
from .scanner import Finding, FindingWithContext, SemgrepScanner
from .triage import TriageAgent, TriageDecision
from .web.dashboard import run_dashboard


console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="ai-security-scan")
def main():
    """AI Security Scanner - Combining Semgrep with LLM triage."""
    pass


@main.command()
@click.option("--host", "-h", default="127.0.0.1", help="Host to bind to")
@click.option("--port", "-p", default=5000, type=int, help="Port to bind to")
@click.option("--debug", is_flag=True, help="Enable debug mode")
def serve(host: str, port: int, debug: bool):
    """
    Start the web dashboard server.

    The dashboard provides a beautiful web interface for viewing scan results
    with interactive charts and detailed finding analysis.

    Examples:

        ai-security-scan serve

        ai-security-scan serve --host 0.0.0.0 --port 8080

        ai-security-scan serve --debug
    """
    console.print(f"[bold blue]Starting web dashboard...[/bold blue]")
    console.print(f"  Host: {host}")
    console.print(f"  Port: {port}")
    console.print(f"  Debug: {debug}")
    console.print(f"\n[green]Open http://{host}:{port} in your browser[/green]\n")
    run_dashboard(host=host, port=port, debug=debug)


@main.command()
@click.argument("target", type=click.Path(exists=True))
@click.option(
    "--output", "-o",
    type=click.Path(),
    help="Output file path for the report",
)
@click.option(
    "--format", "-f",
    type=click.Choice(["console", "markdown", "json"]),
    default="console",
    help="Output format",
)
@click.option(
    "--severity-threshold",
    type=click.Choice(["low", "medium", "high", "critical"]),
    default="high",
    help="Minimum severity to report",
)
@click.option(
    "--custom-rules",
    type=click.Path(exists=True),
    help="Path to custom Semgrep rules YAML",
)
@click.option(
    "--triage",
    is_flag=True,
    default=True,
    help="Enable LLM triage (default: enabled)",
)
@click.option(
    "--no-triage",
    is_flag=True,
    help="Disable LLM triage (raw Semgrep output only)",
)
@click.option(
    "--generate-fixes",
    is_flag=True,
    help="Generate AI-powered fix suggestions for confirmed vulnerabilities",
)
@click.option(
    "--fail-on",
    type=click.Choice(["critical", "high", "medium", "never"]),
    default="high",
    help="Exit code based on confirmed vulnerability severity",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    help="Enable verbose output",
)
def scan(
    target: str,
    output: Optional[str],
    format: str,
    severity_threshold: str,
    custom_rules: Optional[str],
    triage: bool,
    no_triage: bool,
    generate_fixes: bool,
    fail_on: str,
    verbose: bool,
):
    """
    Scan a codebase for security vulnerabilities.

    TARGET is the file or directory to scan.

    Examples:

        ai-security-scan scan ./myapp

        ai-security-scan scan ./src --format json --output report.json

        ai-security-scan scan ./api --generate-fixes --fail-on critical
    """
    # Determine if triage is enabled
    enable_triage = triage and not no_triage

    # Check for API key if triage is enabled
    if enable_triage and not os.environ.get("ANTHROPIC_API_KEY"):
        console.print(
            "[red]Error:[/red] ANTHROPIC_API_KEY environment variable required for LLM triage. "
            "Set it or use --no-triage for raw Semgrep output."
        )
        sys.exit(1)

    console.print(f"[bold blue]Scanning:[/bold blue] {target}\n")

    try:
        # Initialize scanner
        scanner = SemgrepScanner(
            config="auto",
            custom_rules_path=custom_rules,
            base_path=str(Path(target).parent),
        )

        # Run scan with context
        console.print("[dim]Running Semgrep analysis...[/dim]")
        findings_with_context = scanner.scan_with_context(target)

        if not findings_with_context:
            console.print("[green]No security issues found![/green]")
            sys.exit(0)

        console.print(f"[yellow]Found {len(findings_with_context)} potential issues[/yellow]\n")

        # Triage findings
        triage_results = []
        fixes = []

        if enable_triage:
            console.print("[dim]Analyzing findings with AI...[/dim]\n")
            triage_agent = TriageAgent()

            for i, finding_ctx in enumerate(findings_with_context, 1):
                if verbose:
                    console.print(
                        f"  [{i}/{len(findings_with_context)}] Triaging {finding_ctx.finding.rule_id}..."
                    )

                result = triage_agent.triage(finding_ctx)
                triage_results.append(result)

                # Generate fix if confirmed vulnerability
                if generate_fixes and result.is_confirmed_vulnerability():
                    fix_gen = FixGenerator()
                    fix = fix_gen.generate_fix(finding_ctx, result)
                    fixes.append(fix)
                else:
                    fixes.append(None)

                # Print triage result
                status = "X" if result.decision == TriageDecision.TRUE_POSITIVE else "OK"
                console.print(
                    f"  [{status}] {finding_ctx.finding.rule_id}: {result.decision.value} "
                    f"({result.confidence} confidence)"
                )
        else:
            # No triage - mark all as needs review
            from .triage import TriageResult
            for finding_ctx in findings_with_context:
                triage_results.append(
                    TriageResult(
                        decision=TriageDecision.NEEDS_REVIEW,
                        confidence="low",
                        explanation="Triage disabled - manual review required",
                    )
                )
                fixes.append(None)

        console.print()

        # Extract plain findings from context
        findings = [f.finding for f in findings_with_context]

        # Generate report
        reporter = Reporter(console)
        report = reporter.create_report(
            target_path=target,
            findings=findings,
            triage_results=triage_results,
            fixes=fixes,
        )

        # Output report
        if format == "console":
            reporter.print_console(report)
        elif format == "markdown":
            out_path = output or "security_report.md"
            reporter.export_markdown(report, out_path)
            console.print(f"[green]Report saved to:[/green] {out_path}")
        elif format == "json":
            out_path = output or "security_report.json"
            reporter.export_json(report, out_path)
            console.print(f"[green]Report saved to:[/green] {out_path}")

        # Determine exit code
        should_fail = _should_fail_build(report, fail_on)
        if should_fail:
            console.print("\n[bold red]Build failed due to confirmed vulnerabilities[/bold red]")
            sys.exit(1)
        else:
            console.print("\n[bold green]Scan completed successfully[/bold green]")
            sys.exit(0)

    except RuntimeError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted[/yellow]")
        sys.exit(130)


def _should_fail_build(report: ScanReport, fail_on: str) -> bool:
    """Determine if the build should fail based on findings."""
    if fail_on == "never":
        return False

    severity_order = {"critical": 3, "high": 2, "medium": 1, "low": 0}
    threshold = severity_order.get(fail_on, 2)

    for finding in report.findings:
        triage = finding.triage
        if not triage or not triage.is_confirmed_vulnerability():
            continue

        finding_severity = severity_order.get(finding.finding.severity.lower(), 0)
        if finding_severity >= threshold:
            return True

    return False


if __name__ == "__main__":
    main()
