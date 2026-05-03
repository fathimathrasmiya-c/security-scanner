# AI Security Scanner

A Python-based security scanner that combines the speed of static analysis with the reasoning power of LLMs to identify and fix vulnerabilities in code.

## Features

- **Semgrep Integration**: Fast, accurate static analysis using industry-standard rules
- **AI Triage**: Claude-powered analysis to distinguish real vulnerabilities from false positives
- **Contextual Explanations**: Understand *why* something is vulnerable in your specific context
- **Auto-Fix Suggestions**: Get secure, production-ready code fixes
- **Web Dashboard**: Beautiful Flask-based UI with interactive charts
- **CI/CD Ready**: GitHub Actions integration for automated security scanning
- **Multiple Output Formats**: Console, Markdown, JSON reports

## What It Detects

### OWASP Top 10 Vulnerabilities
- SQL Injection (A03)
- Cryptographic Failures - weak hashes like MD5/SHA1 (A02)
- Insecure Deserialization - pickle, YAML (A08)
- Security Misconfiguration - debug mode, CORS (A05)
- SSRF - Server-Side Request Forgery (A010)
- Broken Access Control (A01)
- Authentication Failures (A07)
- Logging Failures (A09)

### Secrets Detection
- Hardcoded API keys
- AWS credentials
- Private keys
- Database passwords
- Generic tokens

## Installation

```bash
cd python-scanner
pip install -r requirements.txt
```

### Install as Package

```bash
pip install -e .
```

## Usage

### Basic Scan

```bash
# Scan a directory
python -m src.cli scan ./myapp

# Scan with AI triage and fix suggestions
python -m src.cli scan ./src --generate-fixes --verbose
```

### Output Options

```bash
# Console output (default)
python -m src.cli scan ./app

# Save as Markdown report
python -m src.cli scan ./app --format markdown --output report.md

# Save as JSON report
python -m src.cli scan ./app --format json --output report.json
```

### CI/CD Integration

```bash
# Fail build on high severity vulnerabilities
python -m src.cli scan ./app --fail-on high

# Fail only on critical
python -m src.cli scan ./app --fail-on critical
```

### Disable AI Triage

```bash
# Run Semgrep only (no API key needed)
python -m src.cli scan ./app --no-triage
```

### Web Dashboard

```bash
# Start the web dashboard
python -m src.cli serve

# Dashboard will be available at http://127.0.0.1:5000

# Custom host/port
python -m src.cli serve --host 0.0.0.0 --port 8080

# Debug mode
python -m src.cli serve --debug
```

The dashboard provides:
- Interactive charts (severity distribution, triage results)
- Detailed finding views with AI explanations
- Fix suggestions with before/after code comparison
- Scan history tracking
- JSON export functionality

## Configuration

### Environment Variables

| Variable | Description |
|----------|-------------|
| `ANTHROPIC_API_KEY` | Required for AI triage and fix generation |

### CLI Options

| Option | Description |
|--------|-------------|
| `--output, -o` | Output file path |
| `--format, -f` | Output format: console, markdown, json |
| `--severity-threshold` | Minimum severity to report |
| `--custom-rules` | Path to custom Semgrep rules YAML |
| `--triage` | Enable LLM triage (default) |
| `--no-triage` | Disable LLM triage |
| `--generate-fixes` | Generate AI fix suggestions |
| `--fail-on` | Exit code: critical, high, medium, never |
| `--verbose, -v` | Verbose output |

## Project Structure

```
python-scanner/
├── src/
│   ├── __init__.py          # Package initialization
│   ├── scanner.py           # Semgrep integration
│   ├── triage.py            # Claude LLM triage agent
│   ├── fix_generator.py     # AI-powered fix generation
│   ├── reporter.py          # Report generation
│   ├── cli.py               # CLI entry point
│   └── web/                 # Web dashboard
│       ├── __init__.py
│       ├── dashboard.py     # Flask application
│       ├── templates/       # HTML templates
│       │   ├── base.html
│       │   ├── index.html
│       │   └── finding.html
│       └── static/
│           ├── css/style.css
│           └── js/main.js
├── rules/
│   └── custom_rules.yml     # Custom Semgrep rules
├── tests/
│   ├── test_scanner.py
│   ├── test_triage.py
│   ├── test_fix_generator.py
│   └── fixtures/
│       └── vulnerable_app.py
├── .github/workflows/
│   └── security_scan.yml    # CI/CD pipeline
├── requirements.txt
├── pyproject.toml
└── README.md
```

## GitHub Actions Setup

Add to your repository:

1. Add Anthropic API key as secret:
   ```
   Settings > Secrets and variables > Actions > New secret
   Name: ANTHROPIC_API_KEY
   ```

2. The workflow automatically:
   - Runs on PR and push to main
   - Scans for vulnerabilities
   - Comments PR with results
   - Fails build on confirmed High/Critical issues

## Example Output

```
============================================================
AI SECURITY SCAN REPORT
============================================================

Scan Time: 2026-04-15T10:30:00
Target: ./myapp

Summary
┌─────────────────────────────┬───────┐
│ Metric                      │ Count │
├─────────────────────────────┼───────┤
│ Total Findings              │    12 │
│ Confirmed Vulnerabilities   │     4 │
│ False Positives             │     7 │
│ Needs Review                │     1 │
└─────────────────────────────┴───────┘

Detailed Findings

#1 [ERROR] python.lang.security.audit.dangerous-eval
  File: myapp/utils.py:45
  Message: Use of eval is dangerous

  [X] Triage: True Positive
  [dim]Confidence:[/dim] high
  [dim]Explanation:[/dim] The code uses eval() with user input directly...
  Exploit: Attacker can send malicious Python code as input.

  Fix: Replace eval with ast.literal_eval
  import ast; result = ast.literal_eval(user_input)...

────────────────────────────────────────
```

## How It Works

1. **Semgrep Analysis**: Scans code using 100+ built-in security rules
2. **Context Extraction**: Grabs surrounding code for each finding
3. **AI Triage**: Claude analyzes if it's a real vulnerability
4. **Fix Generation**: For confirmed issues, generates secure fixes
5. **Report**: Produces actionable security report

## Why This Tool?

Traditional scanners produce noise - hundreds of "potential" issues. This tool:

- **Reduces False Positives**: AI verifies each finding
- **Explains the Risk**: Context-aware explanations
- **Provides Fixes**: Not just problems, but solutions
- **Saves Time**: Focus on what actually matters

## License

MIT

## Contributing

Contributions welcome! Please read CONTRIBUTING.md first.
