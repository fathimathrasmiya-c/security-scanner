# Security Scan Dashboard

A modern, professional React-based dashboard for viewing security scan results.

## Features

- **Summary Cards**: Total issues, High/Medium/Low severity counts
- **Interactive Charts**: Severity distribution and AI triage results (Pie charts)
- **Filtering**: Filter findings by severity level
- **Search**: Search by file name, issue message, or rule ID
- **Responsive Design**: Works on desktop and mobile
- **Dark Theme**: Professional dark UI similar to SonarQube/Snyk

## Installation

```bash
cd react-dashboard
npm install
```

## Running the Dashboard

### Option 1: Standalone (with uploaded JSON)

```bash
npm run dev
# Open http://localhost:3000
```

### Option 2: Connected to Python Backend

```bash
# Start the Python Flask backend first
cd ../python-scanner
python -m src.web.dashboard

# Then start React dev server
cd ../react-dashboard
npm run dev
```

## Usage

1. **Upload Scan Results**: Click "Upload Scan" and select your `report.json` file
2. **View Summary**: See total issues and breakdown by severity
3. **Analyze Charts**: View pie charts for severity distribution and triage results
4. **Filter & Search**: Use the dropdown and search box to find specific issues
5. **Clear Results**: Click "Clear" to reset the dashboard

## Data Format

The dashboard accepts scan results in this format:

```json
{
  "scan_time": "2026-04-15T10:30:00",
  "target_path": "./myapp",
  "summary": {
    "total_findings": 12,
    "confirmed_vulnerabilities": 4,
    "false_positives": 7,
    "needs_review": 1
  },
  "findings": [
    {
      "rule_id": "python.lang.security.audit.dangerous-eval",
      "message": "Use of eval is dangerous",
      "file": "app.py",
      "line": 10,
      "severity": "ERROR",
      "code_snippet": "result = eval(user_input)"
    }
  ]
}
```

## Tech Stack

- **React 18** - UI framework
- **Vite** - Build tool and dev server
- **Recharts** - Charts library
- **Lucide React** - Icons
- **CSS3** - Custom styling with Inter font
