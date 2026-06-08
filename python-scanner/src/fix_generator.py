"""Code fix generation using LLM."""

import os
from dataclasses import dataclass
from typing import Optional

import anthropic

from .scanner import FindingWithContext
from .triage import TriageResult


@dataclass
class FixProposal:
    """A proposed fix for a security vulnerability."""

    original_code: str
    fixed_code: str
    explanation: str
    diff_summary: str
    confidence: str  # "low", "medium", "high"

    def to_unified_diff(self, filename: str, line_number: int) -> str:
        """Generate a unified diff format."""
        orig_lines = self.original_code.splitlines()
        fixed_lines = self.fixed_code.splitlines()

        orig_count = len(orig_lines)
        fixed_count = len(fixed_lines)

        orig_formatted = "\n".join([f"-{line}" for line in orig_lines])
        fixed_formatted = "\n".join([f"+{line}" for line in fixed_lines])

        return f"""--- a/{filename}
+++ b/{filename}
@@ -{line_number},{orig_count} +{line_number},{fixed_count} @@
{orig_formatted}
{fixed_formatted}

{self.diff_summary}
"""


class FixGenerator:
    """Generate secure code fixes using Claude."""

    SYSTEM_PROMPT = """You are a security engineer specializing in secure code remediation.
Your role is to:
1. Analyze vulnerable code patterns
2. Generate secure, production-ready fixes
3. Explain why the fix addresses the vulnerability
4. Follow language-specific best practices and frameworks

Always provide fixes that:
- Use established security libraries and patterns
- Maintain code functionality while improving security
- Are minimal and focused on the specific vulnerability
- Include any necessary imports or dependencies"""

    def __init__(self, api_key: Optional[str] = None, model: str = "claude-sonnet-4-6"):
        """
        Initialize the fix generator.

        Args:
            api_key: Anthropic API key
            model: Claude model to use
        """
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise ValueError(
                "Anthropic API key required. Set ANTHROPIC_API_KEY or pass api_key."
            )
        self.client = anthropic.Anthropic(api_key=self.api_key)
        self.model = model

    def generate_fix(
        self, finding: FindingWithContext, triage: TriageResult
    ) -> FixProposal:
        """
        Generate a code fix for a confirmed vulnerability.

        Args:
            finding: The security finding with code context
            triage: The triage result confirming this is a true positive

        Returns:
            FixProposal with the fixed code and explanation
        """
        prompt = self._build_fix_prompt(finding, triage)

        response = self.client.messages.create(
            model=self.model,
            max_tokens=1024,
            system=self.SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )

        return self._parse_response(response.content[0].text, finding)

    def _build_fix_prompt(
        self, finding: FindingWithContext, triage: TriageResult
    ) -> str:
        """Build the prompt for fix generation."""
        rule_id = finding.finding.rule_id
        severity = finding.finding.severity
        owasp = finding.finding.metadata.get("owasp", "Unknown")

        return f"""
Generate a secure fix for this vulnerability:

## Vulnerability Details
- **Rule**: {rule_id}
- **Severity**: {severity}
- **OWASP Category**: {owasp}
- **File**: {finding.finding.file}:{finding.finding.line}

## Why This Is Vulnerable
{triage.explanation}

**Exploit Scenario**: {triage.exploit_scenario or "N/A"}

## Vulnerable Code Context
{finding.to_prompt_context()}

## Your Task
Generate a secure fix that:
1. Eliminates the vulnerability completely
2. Uses best practices for this type of issue
3. Maintains the intended functionality
4. Is minimal and focused

Format your response as:
```
FIXED_CODE:
[Your fixed code here]

EXPLANATION:
[Why this fix works]

DIFF_SUMMARY:
[Brief summary of changes]

CONFIDENCE: low/medium/high
```
"""

    def _parse_response(
        self, response_text: str, finding: FindingWithContext
    ) -> FixProposal:
        """Parse Claude's response into a FixProposal."""
        original_code = finding.finding.code_snippet.strip()

        lines = response_text.strip().split("\n")
        fixed_code_lines = []
        explanation_lines = []
        diff_summary_lines = []
        confidence = "medium"

        current_section = None

        for line in lines:
            line_stripped = line.strip()

            if line_stripped.startswith("FIXED_CODE:"):
                current_section = "fixed_code"
                content = line_stripped.replace("FIXED_CODE:", "").strip()
                if content:
                    fixed_code_lines.append(content)
            elif line_stripped.startswith("EXPLANATION:"):
                current_section = "explanation"
                content = line_stripped.replace("EXPLANATION:", "").strip()
                if content:
                    explanation_lines.append(content)
            elif line_stripped.startswith("DIFF_SUMMARY:"):
                current_section = "diff_summary"
                content = line_stripped.replace("DIFF_SUMMARY:", "").strip()
                if content:
                    diff_summary_lines.append(content)
            elif line_stripped.startswith("CONFIDENCE:"):
                confidence = (
                    line_stripped.replace("CONFIDENCE:", "").strip().lower()
                )
            elif current_section == "fixed_code":
                fixed_code_lines.append(line)
            elif current_section == "explanation":
                explanation_lines.append(line)
            elif current_section == "diff_summary":
                diff_summary_lines.append(line)
            elif line_stripped and current_section is None:
                # If we have content before any section, assume it's part of the explanation
                current_section = "explanation"
                explanation_lines.append(line)

        fixed_code = "\n".join(fixed_code_lines).strip() or original_code
        explanation = "\n".join(explanation_lines).strip()
        diff_summary = "\n".join(diff_summary_lines).strip() or "Code remediation"

        # Heuristic: if explanation is empty but fixed_code contains a double newline,
        # it might be an implicit explanation.
        if not explanation and "\n\n" in fixed_code:
            parts = fixed_code.split("\n\n", 1)
            second_part = parts[1].strip()
            if second_part and second_part[0].isupper() and not any(c in second_part.split('\n')[0] for c in '()[]{}='):
                fixed_code = parts[0].strip()
                explanation = second_part

        explanation = explanation or "Fix generated by AI"

        # Validate confidence value
        if confidence not in ("low", "medium", "high"):
            confidence = "medium"

        return FixProposal(
            original_code=original_code,
            fixed_code=fixed_code,
            explanation=explanation,
            diff_summary=diff_summary,
            confidence=confidence,
        )

    def _extract_section(self, text: str, marker: str) -> str:
        """Extract a section from the response text."""
        if marker not in text:
            return ""

        start_idx = text.find(marker) + len(marker)
        remaining = text[start_idx:]

        # Find the next section marker or end of text
        next_marker_idx = len(remaining)
        for potential_marker in [
            "FIXED_CODE:",
            "EXPLANATION:",
            "DIFF_SUMMARY:",
            "CONFIDENCE:",
        ]:
            if potential_marker in remaining and potential_marker != marker:
                idx = remaining.find(potential_marker)
                if idx < next_marker_idx:
                    next_marker_idx = idx

        return remaining[:next_marker_idx].strip()


def generate_fix_summary(fix: FixProposal, finding: FindingWithContext) -> str:
    """Generate a human-readable fix summary."""
    return f"""
## Security Fix for {finding.finding.rule_id}

**File**: {finding.finding.file}:{finding.finding.line}
**Severity**: {finding.finding.severity}

### The Problem
{fix.explanation}

### The Fix
```diff
{fix.to_unified_diff(finding.finding.file, finding.finding.line)}
```

### Confidence: {fix.confidence}
"""
