"""Flask web dashboard for viewing security scan results."""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_cors import CORS

from ..reporter import ScanReport


def create_dashboard(static_folder: str = "static", template_folder: str = "templates"):
    """Create and configure the Flask dashboard application."""

    app = Flask(
        __name__,
        static_folder=static_folder,
        template_folder=template_folder,
    )
    app.config["SECRET_KEY"] = os.urandom(24).hex()

    CORS(app)

    # In-memory storage for scan results
    scan_results: Optional[ScanReport] = None
    scan_history: list[dict] = []

    @app.context_processor
    def inject_globals():
        """Inject global variables into templates."""
        return {
            "app_name": "AI Security Scanner",
            "version": "0.1.0",
        }

    @app.route("/login")
    def login():
        """Login page."""
        return render_template("login.html")

    @app.route("/")
    def index():
        """Dashboard home page."""
        return render_template(
            "index.html",
            scan=scan_results,
            history=scan_history[-10:],  # Last 10 scans
        )

    @app.route("/api/scan", methods=["POST"])
    def upload_scan():
        """Upload a scan result (JSON format)."""
        nonlocal scan_results

        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400

        data = request.json

        # Create ScanReport from JSON
        try:
            scan_results = _parse_scan_data(data)
            scan_history.append(
                {
                    "time": scan_results.scan_time,
                    "target": scan_results.target_path,
                    "total": scan_results.total_findings,
                    "confirmed": scan_results.confirmed_vulnerabilities,
                }
            )

            return jsonify(
                {
                    "success": True,
                    "message": f"Scan results loaded: {scan_results.total_findings} findings",
                }
            )
        except Exception as e:
            return jsonify({"error": str(e)}), 400

    @app.route("/api/scan/file", methods=["POST"])
    def upload_scan_file():
        """Upload a scan result file."""
        nonlocal scan_results

        if "file" not in request.files:
            return jsonify({"error": "No file provided"}), 400

        file = request.files["file"]
        if file.filename == "":
            return jsonify({"error": "No file selected"}), 400

        try:
            data = json.loads(file.read().decode("utf-8"))
            scan_results = _parse_scan_data(data)
            scan_history.append(
                {
                    "time": scan_results.scan_time,
                    "target": scan_results.target_path,
                    "total": scan_results.total_findings,
                    "confirmed": scan_results.confirmed_vulnerabilities,
                }
            )

            return jsonify(
                {
                    "success": True,
                    "message": f"Scan results loaded: {scan_results.total_findings} findings",
                }
            )
        except Exception as e:
            return jsonify({"error": str(e)}), 400

    @app.route("/api/scan/current")
    def get_current_scan():
        """Get current scan results."""
        if scan_results is None:
            return jsonify({"error": "No scan results loaded"}), 404
        return jsonify(scan_results.to_dict())

    @app.route("/api/scan/history")
    def get_scan_history():
        """Get scan history."""
        return jsonify(scan_history)

    @app.route("/api/scan/clear", methods=["POST"])
    def clear_scan():
        """Clear current scan results."""
        nonlocal scan_results
        scan_results = None
        return jsonify({"success": True, "message": "Scan results cleared"})

    @app.route("/findings/<int:index>")
    def view_finding(index: int):
        """View details of a specific finding."""
        if scan_results is None:
            return jsonify({"error": "No scan results loaded"}), 404

        if index < 0 or index >= len(scan_results.findings):
            return jsonify({"error": "Finding not found"}), 404

        return render_template(
            "finding.html",
            finding=scan_results.findings[index],
            index=index,
            total=len(scan_results.findings),
        )

    @app.route("/export/<format>")
    def export_report(format: str):
        """Export report in specified format."""
        if scan_results is None:
            return jsonify({"error": "No scan results loaded"}), 404

        if format == "json":
            return jsonify(scan_results.to_dict())

        return jsonify({"error": "Unsupported format"}), 400

    def _parse_scan_data(data: dict) -> ScanReport:
        """Parse scan data dictionary into ScanReport."""
        from ..reporter import ReportedFinding, ScanReport
        from ..scanner import Finding
        from ..triage import TriageResult, TriageDecision
        from ..fix_generator import FixProposal

        # Parse findings
        findings = []
        for f in data.get("findings", []):
            finding = Finding(
                rule_id=f.get("rule_id", "unknown"),
                message=f.get("message", ""),
                file=f.get("file", ""),
                line=f.get("line", 0),
                column=f.get("column", 0),
                severity=f.get("severity", "WARNING"),
                code_snippet=f.get("code_snippet", ""),
                metadata=f.get("metadata", {}),
            )

            triage = None
            if "triage" in f:
                t = f["triage"]
                triage = TriageResult(
                    decision=TriageDecision(t.get("decision", "needs_review")),
                    confidence=t.get("confidence", "medium"),
                    explanation=t.get("explanation", ""),
                    exploit_scenario=t.get("exploit_scenario"),
                    recommended_action=t.get("recommended_action"),
                )

            fix = None
            if "fix" in f:
                fx = f["fix"]
                fix = FixProposal(
                    original_code=fx.get("original_code", ""),
                    fixed_code=fx.get("fixed_code", ""),
                    explanation=fx.get("explanation", ""),
                    diff_summary=fx.get("diff_summary", ""),
                    confidence=fx.get("confidence", "medium"),
                )

            findings.append(
                ReportedFinding(finding=finding, triage=triage, fix=fix)
            )

        summary = data.get("summary", {})
        return ScanReport(
            scan_time=data.get("scan_time", datetime.now().isoformat()),
            target_path=data.get("target_path", ""),
            total_findings=summary.get("total_findings", len(findings)),
            confirmed_vulnerabilities=summary.get("confirmed_vulnerabilities", 0),
            false_positives=summary.get("false_positives", 0),
            needs_review=summary.get("needs_review", 0),
            findings=findings,
        )

    return app


def run_dashboard(host: str = "127.0.0.1", port: int = 5000, debug: bool = True):
    """Run the dashboard server."""
    # Get the directory containing this module
    base_dir = Path(__file__).parent
    app = create_dashboard(
        static_folder=str(base_dir / "static"),
        template_folder=str(base_dir / "templates"),
    )
    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    run_dashboard()
