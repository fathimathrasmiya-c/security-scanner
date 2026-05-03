"""Tests for the LLM triage agent."""

import os
import pytest
from unittest.mock import Mock, patch

from src.triage import TriageAgent, TriageResult, TriageDecision
from src.scanner import Finding, FindingWithContext


class TestTriageResult:
    """Test cases for TriageResult."""

    def test_is_confirmed_vulnerability_true_positive(self):
        """Test confirmed vulnerability detection."""
        result = TriageResult(
            decision=TriageDecision.TRUE_POSITIVE,
            confidence="high",
            explanation="This is a real vulnerability"
        )
        assert result.is_confirmed_vulnerability() is True

    def test_is_confirmed_vulnerability_false_positive(self):
        """Test false positive is not confirmed."""
        result = TriageResult(
            decision=TriageDecision.FALSE_POSITIVE,
            confidence="high",
            explanation="This is a false positive"
        )
        assert result.is_confirmed_vulnerability() is False

    def test_should_block_build_true_positive_high_confidence(self):
        """Test build blocking on confirmed high confidence issues."""
        result = TriageResult(
            decision=TriageDecision.TRUE_POSITIVE,
            confidence="high",
            explanation="Confirmed vulnerability"
        )
        assert result.should_block_build() is True

    def test_should_block_build_true_positive_medium_confidence(self):
        """Test build blocking on medium confidence."""
        result = TriageResult(
            decision=TriageDecision.TRUE_POSITIVE,
            confidence="medium",
            explanation="Likely vulnerability"
        )
        assert result.should_block_build() is True

    def test_should_block_build_false_positive(self):
        """Test false positive doesn't block build."""
        result = TriageResult(
            decision=TriageDecision.FALSE_POSITIVE,
            confidence="high",
            explanation="Not a real issue"
        )
        assert result.should_block_build() is False

    def test_should_block_build_low_confidence(self):
        """Test low confidence doesn't block build."""
        result = TriageResult(
            decision=TriageDecision.TRUE_POSITIVE,
            confidence="low",
            explanation="Possible but uncertain"
        )
        assert result.should_block_build() is False


class TestTriageAgent:
    """Test cases for TriageAgent."""

    def test_initialization_with_api_key(self):
        """Test agent initializes with provided API key."""
        agent = TriageAgent(api_key="test-key")
        assert agent.api_key == "test-key"

    def test_initialization_without_api_key_raises(self):
        """Test agent raises error without API key."""
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ValueError) as exc_info:
                TriageAgent()
            assert "API key required" in str(exc_info.value)

    def test_initialization_from_environment(self):
        """Test agent reads API key from environment."""
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "env-key"}):
            agent = TriageAgent()
            assert agent.api_key == "env-key"

    @pytest.fixture
    def sample_finding(self):
        """Create a sample finding for testing."""
        return FindingWithContext(
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
            context_before="def process(input):\n",
            context_after="\n    return result",
            full_context="def process(input):\n    result = eval(user_input)\n    return result"
        )

    @patch('src.triage.anthropic.Anthropic')
    def test_triage_parses_response(self, mock_anthropic, sample_finding):
        """Test triage correctly parses Claude's response."""
        mock_client = Mock()
        mock_anthropic.return_value = mock_client

        mock_response = Mock()
        mock_response.content = [Mock(text="""
DECISION: TRUE_POSITIVE
CONFIDENCE: high
EXPLANATION: The code uses eval() with user input directly.
EXPLOIT: Attacker can send malicious Python code as input.
REMEDIATION: Use ast.literal_eval() or a safe parser instead.
""")]
        mock_client.messages.create.return_value = mock_response

        agent = TriageAgent(api_key="test-key")
        result = agent.triage(sample_finding)

        assert result.decision == TriageDecision.TRUE_POSITIVE
        assert result.confidence == "high"
        assert "eval" in result.explanation.lower()
        assert result.exploit_scenario is not None
        assert result.recommended_action is not None

    @patch('src.triage.anthropic.Anthropic')
    def test_triage_detects_false_positive(self, mock_anthropic):
        """Test triage correctly identifies false positives."""
        mock_client = Mock()
        mock_anthropic.return_value = mock_client

        mock_response = Mock()
        mock_response.content = [Mock(text="""
DECISION: FALSE_POSITIVE
CONFIDENCE: high
EXPLANATION: This is not exploitable because the input is sanitized elsewhere.
EXPLOIT: N/A
REMEDIATION: No change needed.
""")]
        mock_client.messages.create.return_value = mock_response

        agent = TriageAgent(api_key="test-key")
        finding = FindingWithContext(
            finding=Finding(
                rule_id="test-rule",
                message="Test",
                file="app.py",
                line=1,
                severity="WARNING",
                code_snippet="code"
            ),
            context_before="",
            context_after="",
            full_context="code"
        )

        result = agent.triage(finding)

        assert result.decision == TriageDecision.FALSE_POSITIVE
        assert not result.is_confirmed_vulnerability()


class TestTriagePromptBuilding:
    """Test prompt building for triage."""

    @pytest.fixture
    def agent(self):
        """Create a triage agent for testing."""
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
            return TriageAgent()

    def test_prompt_includes_finding_details(self, agent):
        """Test that prompt includes all finding details."""
        finding = FindingWithContext(
            finding=Finding(
                rule_id="test-rule-id",
                message="Test vulnerability message",
                file="test.py",
                line=42,
                severity="CRITICAL",
                code_snippet="vuln_code()",
                metadata={
                    "owasp": "A03:2021 - Injection",
                    "cwe": "CWE-89"
                }
            ),
            context_before="# Before\n",
            context_after="# After\n",
            full_context="# Full\n"
        )

        prompt = agent._build_triage_prompt(finding)

        assert "test-rule-id" in prompt
        assert "Test vulnerability message" in prompt
        assert "test.py" in prompt
        assert "42" in prompt
        assert "CRITICAL" in prompt
        assert "A03:2021" in prompt
        assert "CWE-89" in prompt


class TestResponseParsing:
    """Test robustness of response parsing."""

    @pytest.fixture
    def agent(self):
        """Create a triage agent for testing."""
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
            return TriageAgent()

    @pytest.fixture
    def sample_finding(self):
        """Create a minimal finding for parsing tests."""
        return FindingWithContext(
            finding=Finding(
                rule_id="test",
                message="test",
                file="test.py",
                line=1,
                severity="WARNING",
                code_snippet="code"
            ),
            context_before="",
            context_after="",
            full_context="code"
        )

    def test_parses_multiline_explanation(self, agent, sample_finding):
        """Test parsing of multi-line explanations."""
        response = """
DECISION: TRUE_POSITIVE
CONFIDENCE: medium
EXPLANATION: This is a vulnerability
because the input is not sanitized
and can be exploited.
EXPLOIT: Send malicious input
REMEDIATION: Add validation
"""
        result = agent._parse_response(response, sample_finding)

        assert result.decision == TriageDecision.TRUE_POSITIVE
        assert "vulnerability" in result.explanation.lower()

    def test_handles_missing_sections(self, agent, sample_finding):
        """Test handling of responses missing sections."""
        response = """
DECISION: FALSE_POSITIVE
CONFIDENCE: low
This doesn't look like a real issue based on my analysis.
"""
        result = agent._parse_response(response, sample_finding)

        assert result.decision == TriageDecision.FALSE_POSITIVE
        assert result.confidence == "low"

    def test_infers_decision_from_explanation(self, agent, sample_finding):
        """Test that decision can be inferred from explanation text."""
        response = """
CONFIDENCE: high
This is clearly a false positive because the framework handles sanitization.
No exploit is possible here.
"""
        result = agent._parse_response(response, sample_finding)

        assert result.decision == TriageDecision.FALSE_POSITIVE

    def test_infers_true_positive_from_keywords(self, agent, sample_finding):
        """Test inference of true positive from keywords."""
        response = """
CONFIDENCE: high
This is a vulnerability that could lead to data breach.
Attackers can exploit this easily.
"""
        result = agent._parse_response(response, sample_finding)

        assert result.decision == TriageDecision.TRUE_POSITIVE
