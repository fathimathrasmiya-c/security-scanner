"""LLM-powered triage agent for security findings."""

import os
from dataclasses import dataclass
from enum import Enum
from typing import Optional

import anthropic

from .scanner import FindingWithContext


class TriageDecision(Enum):
    """Possible triage outcomes."""

    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    NEEDS_REVIEW = "needs_review"


@dataclass
class TriageResult:
    """Result of LLM triage analysis."""

    decision: TriageDecision
    confidence: str  # "low", "medium", "high"
    explanation: str
    exploit_scenario: Optional[str] = None
    recommended_action: Optional[str] = None

    def is_confirmed_vulnerability(self) -> bool:
        """Check if this is a confirmed true positive."""
        return self.decision == TriageDecision.TRUE_POSITIVE

    def should_block_build(self) -> bool:
        """Check if this finding should fail the CI build."""
        if self.decision != TriageDecision.TRUE_POSITIVE:
            return False
        # Only block on high confidence + high/critical severity
        return self.confidence in ("medium", "high")


class TriageAgent:
    """Claude-powered agent for triaging security findings."""

    SYSTEM_PROMPT = """You are a security expert reviewing code for vulnerabilities.
Your role is to:
1. Determine if a reported security issue is a true vulnerability or false positive
2. Explain the security implications in clear terms
3. Describe how an attacker could exploit this (if applicable)
4. Recommend specific remediation steps

Be precise and avoid false alarms. Consider the code context carefully."""

    def __init__(self, api_key: Optional[str] = None, model: str = "claude-sonnet-4-6"):
        """
        Initialize the triage agent.

        Args:
            api_key: Anthropic API key (or set ANTHROPIC_API_KEY env var)
            model: Claude model to use
        """
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise ValueError(
                "Anthropic API key required. Set ANTHROPIC_API_KEY or pass api_key."
            )
        self.client = anthropic.Anthropic(api_key=self.api_key)
        self.model = model

    def triage(self, finding: FindingWithContext) -> TriageResult:
        """
        Analyze a security finding using Claude.

        Args:
            finding: The finding with code context

        Returns:
            TriageResult with decision and explanation
        """
        prompt = self._build_triage_prompt(finding)

        response = self.client.messages.create(
            model=self.model,
            max_tokens=1024,
            system=self.SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )

        return self._parse_response(response.content[0].text, finding)

    def _build_triage_prompt(self, finding: FindingWithContext) -> str:
        """Build the prompt for triage analysis."""
        severity = finding.finding.severity
        rule_id = finding.finding.rule_id
        message = finding.finding.message
        owasp = finding.finding.metadata.get("owasp", "Not specified")
        cwe = finding.finding.metadata.get("cwe", "Not specified")

        return f"""
Analyze this security finding:

## Finding Details
- **Rule**: {rule_id}
- **Severity**: {severity}
- **Message**: {message}
- **OWASP**: {owasp}
- **CWE**: {cwe}
- **File**: {finding.finding.file}
- **Line**: {finding.finding.line}

## Code Context
{finding.to_prompt_context()}

## Your Task
Answer these questions:

1. **Is this a true vulnerability?** Answer TRUE POSITIVE or FALSE POSITIVE.
2. **Confidence level:** low, medium, or high
3. **Explanation:** Why is this (or isn't this) a security issue?
4. **Exploit scenario:** If vulnerable, how could an attacker exploit this?
5. **Remediation:** What specific fix do you recommend?

Format your response as:
```
DECISION: TRUE_POSITIVE or FALSE_POSITIVE
CONFIDENCE: low/medium/high
EXPLANATION: Your explanation here
EXPLOIT: How to exploit (or "N/A" if false positive)
REMEDIATION: Specific fix recommendation
```
"""

    def _parse_response(
        self, response_text: str, finding: FindingWithContext
    ) -> TriageResult:
        """Parse Claude's response into a TriageResult."""
        lines = response_text.strip().split("\n")

        decision = TriageDecision.NEEDS_REVIEW
        confidence = "medium"
        explanation_lines = []
        exploit_lines = []
        remediation_lines = []

        current_section = "explanation"  # Default section

        for line in lines:
            line_stripped = line.strip()

            if line_stripped.startswith("DECISION:"):
                decision_value = line_stripped.replace("DECISION:", "").strip().upper()
                if "TRUE" in decision_value and "POSITIVE" in decision_value:
                    decision = TriageDecision.TRUE_POSITIVE
                elif "FALSE" in decision_value and "POSITIVE" in decision_value:
                    decision = TriageDecision.FALSE_POSITIVE
                else:
                    decision = TriageDecision.NEEDS_REVIEW
            elif line_stripped.startswith("CONFIDENCE:"):
                confidence = (
                    line_stripped.replace("CONFIDENCE:", "").strip().lower()
                )
            elif line_stripped.startswith("EXPLANATION:"):
                current_section = "explanation"
                content = line_stripped.replace("EXPLANATION:", "").strip()
                if content:
                    explanation_lines.append(content)
            elif line_stripped.startswith("EXPLOIT:"):
                current_section = "exploit"
                content = line_stripped.replace("EXPLOIT:", "").strip()
                if content:
                    exploit_lines.append(content)
            elif line_stripped.startswith("REMEDIATION:"):
                current_section = "remediation"
                content = line_stripped.replace("REMEDIATION:", "").strip()
                if content:
                    remediation_lines.append(content)
            else:  # Preserve empty lines as well
                if current_section == "explanation":
                    explanation_lines.append(line)
                elif current_section == "exploit":
                    exploit_lines.append(line)
                elif current_section == "remediation":
                    remediation_lines.append(line)

        explanation = "\n".join(explanation_lines).strip()
        exploit_scenario = "\n".join(exploit_lines).strip() or None
        recommended_action = "\n".join(remediation_lines).strip() or None

        # If we didn't get a clear decision, use the explanation to infer
        if decision == TriageDecision.NEEDS_REVIEW:
            expl_lower = explanation.lower()
            # Check for negative qualifiers first
            is_fp_hint = "false positive" in expl_lower or "not a vulnerability" in expl_lower or "not vulnerable" in expl_lower
            is_tp_hint = "vulnerability" in expl_lower or "exploit" in expl_lower or "true positive" in expl_lower

            if is_fp_hint and not ("not a false positive" in expl_lower) and not ("true positive" in expl_lower):
                decision = TriageDecision.FALSE_POSITIVE
            elif is_tp_hint:
                decision = TriageDecision.TRUE_POSITIVE

        return TriageResult(
            decision=decision,
            confidence=confidence,
            explanation=explanation,
            exploit_scenario=exploit_scenario,
            recommended_action=recommended_action,
        )

    async def triage_batch(
        self, findings: list[FindingWithContext]
    ) -> list[TriageResult]:
        """
        Triage multiple findings in parallel.

        Args:
            findings: List of findings to triage

        Returns:
            List of TriageResult objects
        """
        # Note: Anthropic doesn't support batch API in the same way
        # This is a sequential implementation for now
        results = []
        for finding in findings:
            result = self.triage(finding)
            results.append(result)
        return results
