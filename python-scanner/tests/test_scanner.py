"""Tests for the Semgrep scanner integration."""

import pytest
import tempfile
import os
from pathlib import Path

from src.scanner import SemgrepScanner, Finding, FindingWithContext


class TestSemgrepScanner:
    """Test cases for SemgrepScanner."""

    def test_scanner_initialization(self):
        """Test scanner can be initialized with default config."""
        scanner = SemgrepScanner()
        assert scanner.config == "auto"
        assert scanner.custom_rules_path is None

    def test_scanner_with_custom_rules(self, tmp_path):
        """Test scanner with custom rules path."""
        rules_file = tmp_path / "rules.yml"
        rules_file.write_text("rules: []")

        scanner = SemgrepScanner(custom_rules_path=str(rules_file))
        assert scanner.custom_rules_path == str(rules_file)

    def test_finding_from_semgrep_result(self):
        """Test parsing a Semgrep result into a Finding."""
        result = {
            "check_id": "python.lang.security.audit.dangerous-eval",
            "path": "/app/test.py",
            "extra": {
                "message": "Use of eval is dangerous",
                "severity": "ERROR",
                "start": {"line": 10, "col": 4},
                "lines": "result = eval(user_input)",
                "metadata": {
                    "owasp": "A03:2021 - Injection",
                    "cwe": "CWE-95: Improper Neutralization of Directives"
                }
            }
        }

        finding = Finding.from_semgrep_result(result, base_path="/app")

        assert finding.rule_id == "python.lang.security.audit.dangerous-eval"
        assert finding.message == "Use of eval is dangerous"
        assert finding.file == "test.py"
        assert finding.line == 10
        assert finding.severity == "ERROR"
        assert "owasp" in finding.metadata

    def test_finding_path_normalization(self):
        """Test that paths are normalized correctly."""
        result = {
            "check_id": "test-rule",
            "path": "/project/src/app.py",
            "extra": {
                "message": "Test",
                "severity": "WARNING",
                "start": {"line": 1, "col": 0},
                "lines": "code",
                "metadata": {}
            }
        }

        finding = Finding.from_semgrep_result(result, base_path="/project")
        assert finding.file == "src/app.py"

    def test_finding_without_base_path(self):
        """Test finding creation without base path."""
        result = {
            "check_id": "test-rule",
            "path": "src/app.py",
            "extra": {
                "message": "Test",
                "severity": "WARNING",
                "start": {"line": 1, "col": 0},
                "lines": "code",
                "metadata": {}
            }
        }

        finding = Finding.from_semgrep_result(result)
        assert finding.file == "src/app.py"


class TestFindingWithContext:
    """Test cases for FindingWithContext."""

    def test_to_prompt_context(self):
        """Test formatting context for LLM prompts."""
        from src.scanner import Finding

        finding = Finding(
            rule_id="test-rule",
            message="Test vulnerability",
            file="app.py",
            line=5,
            severity="ERROR",
            code_snippet="vulnerable_code()"
        )

        ctx = FindingWithContext(
            finding=finding,
            context_before="# Before code\n",
            context_after="# After code\n",
            full_context="# Full context\n"
        )

        prompt = ctx.to_prompt_context()
        assert "LINE 5" in prompt
        assert "vulnerable_code()" in prompt
        assert "# Before code" in prompt
        assert "# After code" in prompt


class TestSemgrepScannerIntegration:
    """Integration tests requiring Semgrep to be installed."""

    @pytest.fixture
    def vulnerable_code_file(self, tmp_path):
        """Create a file with intentionally vulnerable code."""
        code = '''
import pickle
import hashlib

# Hardcoded secret - should be flagged
API_KEY = "sk-1234567890abcdef"

# Weak hash - should be flagged
password_hash = hashlib.md5(password.encode()).hexdigest()

# Dangerous eval - should be flagged
def process(user_input):
    result = eval(user_input)
    return result

# Insecure deserialization - should be flagged
def load_data(data):
    return pickle.loads(data)
'''
        code_file = tmp_path / "vulnerable.py"
        code_file.write_text(code)
        return str(code_file)

    @pytest.mark.skipif(
        not os.system("which semgrep > /dev/null 2>&1") == 0,
        reason="Semgrep not installed"
    )
    def test_scan_finds_vulnerabilities(self, vulnerable_code_file):
        """Test that scanner finds known vulnerabilities."""
        scanner = SemgrepScanner(config="auto")
        findings = scanner.scan(vulnerable_code_file)

        # Should find at least some vulnerabilities
        assert len(findings) > 0

        # Check for specific vulnerability types
        rule_ids = [f.rule_id for f in findings]
        # Semgrep auto rules should catch at least one of these
        assert any(
            "pickle" in rid.lower() or
            "md5" in rid.lower() or
            "eval" in rid.lower() or
            "hardcoded" in rid.lower()
            for rid in rule_ids
        )

    def test_scan_with_context_extraction(self, vulnerable_code_file):
        """Test scanning with code context extraction."""
        scanner = SemgrepScanner(config="auto")
        findings = scanner.scan_with_context(vulnerable_code_file)

        for finding_ctx in findings:
            assert isinstance(finding_ctx, FindingWithContext)
            assert finding_ctx.finding is not None


class TestScannerErrorHandling:
    """Test error handling in scanner."""

    def test_scan_nonexistent_file(self):
        """Test handling of non-existent files."""
        scanner = SemgrepScanner()
        # Semgrep should handle this gracefully
        findings = scanner.scan("/nonexistent/path/file.py")
        # Should return empty list or handle gracefully
        assert isinstance(findings, list)

    def test_invalid_json_handling(self):
        """Test handling of invalid JSON from Semgrep."""
        scanner = SemgrepScanner()

        with pytest.raises(RuntimeError) as exc_info:
            scanner._parse_results("not valid json", "/tmp")

        assert "Failed to parse" in str(exc_info.value)
