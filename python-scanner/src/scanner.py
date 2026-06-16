"""Semgrep integration for running security scans."""

import os
import sys
os.environ["PYTHONUTF8"] = "1"
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class Finding:
    """Represents a security finding from Semgrep."""

    rule_id: str
    message: str
    file: str
    line: int
    end_line: int = 0
    column: int = 0
    severity: str = "WARNING"
    code_snippet: str = ""
    metadata: dict = field(default_factory=dict)

    @classmethod
    def from_semgrep_result(cls, result: dict, base_path: str = "") -> "Finding":
        """Create a Finding from a Semgrep JSON result."""
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})

        return cls(
            rule_id=result.get("check_id", "unknown"),
            message=extra.get("message", "Security issue detected"),
            file=cls._normalize_path(result.get("path", ""), base_path),
            line=extra.get("start", {}).get("line", 0),
            end_line=extra.get("end", {}).get("line", 0),
            column=extra.get("start", {}).get("col", 0),
            severity=extra.get("severity", "WARNING"),
            code_snippet=extra.get("lines", ""),
            metadata=metadata,
        )

    @staticmethod
    def _normalize_path(path: str, base_path: str) -> str:
        """Normalize path to be relative to base_path if possible."""
        if base_path and path.startswith(base_path):
            return path[len(base_path) :].lstrip("/")
        return path


class SemgrepScanner:
    """Wrapper around Semgrep CLI for security scanning."""

    def __init__(
        self,
        config: str = "auto",
        custom_rules_path: Optional[str] = None,
        base_path: str = "",
    ):
        """
        Initialize the Semgrep scanner.

        Args:
            config: Semgrep config to use (e.g., "auto", "p/security-audit")
            custom_rules_path: Path to custom rules YAML file
            base_path: Base path for normalizing file paths in results
        """
        self.config = config
        self.custom_rules_path = custom_rules_path
        self.base_path = base_path

    def scan(self, target_path: str) -> list[Finding]:
        """
        Run Semgrep scan on the target path.

        Args:
            target_path: Path to the file or directory to scan

        Returns:
            List of Finding objects
        """
        cmd = [
            "semgrep",
            "--json",
            "--quiet",
            "--no-error",
        ]

        # Add config
        if self.custom_rules_path:
            cmd.extend(["--config", self.custom_rules_path])
        cmd.extend(["--config", self.config])

        cmd.append(target_path)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                encoding='utf-8',
            )

            # Debug: print what Semgrep returned
            if not result.stdout.strip():
                if result.stderr:
                    print(f"Semgrep error output: {result.stderr}")
                print(f"Semgrep returned empty output. Command was: {' '.join(cmd)}")
                return []

            if result.returncode not in (0, 1):  # 1 = findings found
                # Semgrep returns 2+ for errors
                if result.stderr:
                    print(f"Semgrep warning: {result.stderr}")

            return self._parse_results(result.stdout, target_path)

        except FileNotFoundError:
            raise RuntimeError(
                "Semgrep not found. Install with: pip install semgrep"
            )
        except Exception as e:
            raise RuntimeError(f"Semgrep scan failed: {e}")

    def _parse_results(self, json_output: str, target_path: str) -> list[Finding]:
        """Parse Semgrep JSON output into Finding objects."""
        try:
            data = json.loads(json_output)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Failed to parse Semgrep JSON output: {e}")

        results = data.get("results", [])
        findings = []

        for result in results:
            finding = Finding.from_semgrep_result(result, self.base_path)
            findings.append(finding)

        return findings

    def scan_with_context(
        self, target_path: str, context_lines: int = 10
    ) -> list["FindingWithContext"]:
        """
        Run scan and extract surrounding code context for each finding.

        Args:
            target_path: Path to scan
            context_lines: Number of lines before/after to include

        Returns:
            List of FindingWithContext objects
        """
        findings = self.scan(target_path)
        results = []

        for finding in findings:
            context = self._extract_context(
                finding.file, finding.line, finding.end_line, context_lines
            )
            results.append(
                FindingWithContext(
                    finding=finding,
                    context_before=context["before"],
                    context_after=context["after"],
                    full_context=context["full"],
                )
            )

        return results

    def _extract_context(
        self, file_path: str, line_number: int, end_line: int, context_lines: int
    ) -> dict[str, str]:
        """Extract code context around a specific line."""
        try:
            # Handle absolute paths
            if not Path(file_path).is_absolute() and self.base_path:
                file_path = Path(self.base_path) / file_path

            if not Path(file_path).exists():
                return {"before": "", "after": "", "full": ""}

            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            if line_number <= 0:
                return {"before": "", "after": "".join(lines[:context_lines]), "full": "".join(lines[:context_lines])}

            start_idx = max(0, line_number - context_lines - 1)
            # end_line might be the same as line_number or larger
            end_idx = min(len(lines), (end_line or line_number) + context_lines)

            before = "".join(lines[start_idx : line_number - 1])
            # after should start from end_line
            after = "".join(lines[end_line or line_number : end_idx])
            full = "".join(lines[start_idx:end_idx])

            return {"before": before, "after": after, "full": full}

        except (FileNotFoundError, IOError):
            return {"before": "", "after": "", "full": ""}


@dataclass
class FindingWithContext:
    """A finding with surrounding code context for LLM analysis."""

    finding: Finding
    context_before: str
    context_after: str
    full_context: str

    def to_prompt_context(self) -> str:
        """Format the code context for LLM prompts."""
        return f"""
# Code Context (line {self.finding.line})

{self.context_before}[LINE {self.finding.line}]: {self.finding.code_snippet}[/LINE {self.finding.line}]
{self.context_after}
""".strip()
