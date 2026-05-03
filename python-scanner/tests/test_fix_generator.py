"""Tests for the fix generator module."""

import os
import pytest
from unittest.mock import Mock, patch

from src.fix_generator import FixGenerator, FixProposal
from src.scanner import Finding, FindingWithContext
from src.triage import TriageResult, TriageDecision


class TestFixProposal:
    """Test cases for FixProposal."""

    def test_to_unified_diff(self):
        """Test unified diff generation."""
        fix = FixProposal(
            original_code="result = eval(user_input)",
            fixed_code="result = ast.literal_eval(user_input)",
            explanation="Use safe evaluator",
            diff_summary="Replaced eval with ast.literal_eval",
            confidence="high"
        )

        finding = Finding(
            rule_id="dangerous-eval",
            message="eval is dangerous",
            file="app.py",
            line=10,
            severity="ERROR",
            code_snippet="result = eval(user_input)"
        )

        diff = fix.to_unified_diff("app.py", 10)

        assert "--- a/app.py" in diff
        assert "+++ b/app.py" in diff
        assert "-result = eval(user_input)" in diff
        assert "+result = ast.literal_eval(user_input)" in diff

    def test_fix_proposal_with_empty_fixed_code(self):
        """Test handling of empty fixed code."""
        fix = FixProposal(
            original_code="bad_code()",
            fixed_code="",
            explanation="Fix needed",
            diff_summary="TBD",
            confidence="low"
        )

        # Should still work with empty fixed code
        assert fix.original_code == "bad_code()"
        assert fix.fixed_code == ""


class TestFixGenerator:
    """Test cases for FixGenerator."""

    def test_initialization_with_api_key(self):
        """Test generator initializes with API key."""
        gen = FixGenerator(api_key="test-key")
        assert gen.api_key == "test-key"

    def test_initialization_without_api_key_raises(self):
        """Test generator raises without API key."""
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ValueError) as exc_info:
                FixGenerator()
            assert "API key required" in str(exc_info.value)

    def test_initialization_from_environment(self):
        """Test generator reads API key from environment."""
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "env-key"}):
            gen = FixGenerator()
            assert gen.api_key == "env-key"

    @pytest.fixture
    def sample_vulnerability(self):
        """Create a sample vulnerability for testing."""
        finding = FindingWithContext(
            finding=Finding(
                rule_id="python.lang.security.audit.dangerous-eval",
                message="Use of eval is dangerous",
                file="app.py",
                line=10,
                severity="ERROR",
                code_snippet="result = eval(user_input)",
                metadata={
                    "owasp": "A03:2021 - Injection",
                    "cwe": "CWE-95"
                }
            ),
            context_before="def process(user_input):\n",
            context_after="\n    return result",
            full_context="def process(user_input):\n    result = eval(user_input)\n    return result"
        )

        triage = TriageResult(
            decision=TriageDecision.TRUE_POSITIVE,
            confidence="high",
            explanation="Direct use of eval with user input allows code injection",
            exploit_scenario="Attacker sends '__import__(\"os\").system(\"rm -rf /\")' as input",
            recommended_action="Use ast.literal_eval() or a proper parser"
        )

        return finding, triage

    @patch('src.fix_generator.anthropic.Anthropic')
    def test_generate_fix_parses_response(self, mock_anthropic, sample_vulnerability):
        """Test fix generation parses Claude response correctly."""
        mock_client = Mock()
        mock_anthropic.return_value = mock_client

        mock_response = Mock()
        mock_response.content = [Mock(text="""
FIXED_CODE:
import ast

def process(user_input):
    result = ast.literal_eval(user_input)
    return result

EXPLANATION:
ast.literal_eval safely evaluates string literals without executing arbitrary code.

DIFF_SUMMARY:
Replaced eval() with ast.literal_eval() and added import.

CONFIDENCE: high
""")]
        mock_client.messages.create.return_value = mock_response

        gen = FixGenerator(api_key="test-key")
        finding, triage = sample_vulnerability
        fix = gen.generate_fix(finding, triage)

        assert "ast.literal_eval" in fix.fixed_code
        assert "ast.literal_eval" in fix.explanation
        assert fix.confidence == "high"

    @patch('src.fix_generator.anthropic.Anthropic')
    def test_generate_fix_handles_missing_sections(self, mock_anthropic, sample_vulnerability):
        """Test handling of responses with missing sections."""
        mock_client = Mock()
        mock_anthropic.return_value = mock_client

        mock_response = Mock()
        mock_response.content = [Mock(text="""
FIXED_CODE:
safe_code()

Some explanation without proper sections.
""")]
        mock_client.messages.create.return_value = mock_response

        gen = FixGenerator(api_key="test-key")
        finding, triage = sample_vulnerability
        fix = gen.generate_fix(finding, triage)

        assert fix.fixed_code == "safe_code()"
        assert fix.confidence == "medium"  # Default when not specified

    @patch('src.fix_generator.anthropic.Anthropic')
    def test_generate_fix_validates_confidence(self, mock_anthropic, sample_vulnerability):
        """Test that confidence is validated to valid values."""
        mock_client = Mock()
        mock_anthropic.return_value = mock_client

        mock_response = Mock()
        mock_response.content = [Mock(text="""
FIXED_CODE:
code()
EXPLANATION: fix
DIFF_SUMMARY: changed
CONFIDENCE: invalid_value
""")]
        mock_client.messages.create.return_value = mock_response

        gen = FixGenerator(api_key="test-key")
        finding, triage = sample_vulnerability
        fix = gen.generate_fix(finding, triage)

        assert fix.confidence == "medium"  # Defaulted from invalid


class TestExtractSection:
    """Test section extraction from responses."""

    @pytest.fixture
    def generator(self):
        """Create a fix generator for testing."""
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
            return FixGenerator()

    def test_extract_section_finds_marker(self, generator):
        """Test section extraction with valid marker."""
        text = """
FIXED_CODE:
some code here

EXPLANATION:
why this works
"""
        result = generator._extract_section(text, "FIXED_CODE:")
        assert result == "some code here"

    def test_extract_section_returns_empty_for_missing(self, generator):
        """Test section extraction returns empty for missing marker."""
        text = "No markers here"
        result = generator._extract_section(text, "FIXED_CODE:")
        assert result == ""

    def test_extract_section_handles_multiline(self, generator):
        """Test section extraction with multiline content."""
        text = """
FIXED_CODE:
line 1
line 2
line 3

EXPLANATION:
done
"""
        result = generator._extract_section(text, "FIXED_CODE:")
        assert "line 1" in result
        assert "line 2" in result
        assert "line 3" in result


class TestFixSummaryGeneration:
    """Test fix summary generation."""

    def test_generate_fix_summary(self):
        """Test human-readable fix summary."""
        from src.fix_generator import generate_fix_summary

        fix = FixProposal(
            original_code="eval(x)",
            fixed_code="ast.literal_eval(x)",
            explanation="Safer alternative",
            diff_summary="Use ast.literal_eval",
            confidence="high"
        )

        finding = Finding(
            rule_id="dangerous-eval",
            message="eval is dangerous",
            file="app.py",
            line=10,
            severity="ERROR",
            code_snippet="eval(x)"
        )

        ctx = FindingWithContext(
            finding=finding,
            context_before="",
            context_after="",
            full_context="eval(x)"
        )

        summary = generate_fix_summary(fix, ctx)

        assert "dangerous-eval" in summary
        assert "app.py:10" in summary
        assert "Safer alternative" in summary
        assert "eval(x)" in summary
        assert "ast.literal_eval(x)" in summary
