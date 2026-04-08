# Cybersecurity Log Triage Agent

An AI-powered security log analyser built on **Google ADK** (Agent Development Kit) and **Gemini 2.5 Flash**, deployed on **Google Cloud Run**.

Feed it raw log entries and receive a structured JSON security report with per-log analysis, severity ratings, and actionable remediation advice.

---

## Problem Statement

Modern organizations generate thousands of log entries per hour across web servers, firewalls, authentication systems, and cloud infrastructure. Security Operations Center (SOC) teams face a critical bottleneck: manual log analysis is too slow, too inconsistent, and too expensive to keep pace with the modern threat landscape.

- **Volume overload** — analysts can review only a fraction of logs; attackers exploit this gap
- **Delayed detection** — average time to identify a breach is 204 days (IBM 2023)
- **Skill shortage** — 3.4 million cybersecurity professional shortfall globally (ISC² 2023)
- **Inconsistent analysis** — same logs reviewed by different analysts yield different conclusions

This agent automates first-pass triage, reducing analysis time from hours to seconds.

---

## Features

- **Multi-log batch processing** — accepts 1 to 1,000 logs per request with no entries skipped
- **Automatic log type classification** — HTTP access, authentication, firewall, database, DNS, application logs
- **8-category threat detection** — SQL injection, XSS, RCE, brute-force, directory traversal, command injection, privilege escalation, denial of service
- **Severity assignment** — Low / Medium / High / Critical based on detected indicators
- **Plain-English explanations** — every log gets a human-readable description
- **Vulnerability identification** — maps attacks to specific weaknesses
- **Actionable remediation** — concrete fix suggestions per finding
- **Structured JSON output** — deterministic, null-free reports for SIEM/ticketing integration
- **Executive summary** — aggregated risk overview with severity breakdown
- **Cloud Run deployment** — serverless, scalable, accessible via ADK web interface

---

## Architecture

```
┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│  ADK Web UI │  │     CLI     │  │ API Clients │
└──────┬──────┘  └──────┬──────┘  └──────┬──────┘
       │                │                │
       └────────────────┼────────────────┘
                        │
       ┌────────────────▼─────────────────────┐
       │      Agent Layer (Cloud Run)         │
       │  ┌─────────────┐  ┌───────────────┐  │
       │  │ root_agent  │→ │   tools.py    │  │
       │  │ Gemini 2.5  │  │ analyze_logs  │  │
       │  │   Flash     │  │ gen_summary   │  │
       │  └─────────────┘  └───────────────┘  │
       │  ┌─────────────────────────────────┐  │
       │  │ prompts.py — detection rules    │  │
       │  └─────────────────────────────────┘  │
       └────────────────┬─────────────────────┘
                        │
       ┌────────────────▼────────────────┐
       │     Google Cloud Services       │
       │  Cloud Run │ Gemini API │ Logs  │
       └────────────────┬────────────────┘
                        │
              ┌─────────▼─────────┐
              │  JSON Security    │
              │  Reports (SIEM)   │
              └───────────────────┘
```

---

## Project Structure

```
logs_triage_agent/
├── __init__.py      # Package init — exports root_agent
├── agent.py         # ADK Agent definition (model, tools, prompt)
├── tools.py         # Tool functions: analyze_logs, generate_summary
├── prompts.py       # System prompt for the LLM
└── .env             # API key configuration
```

---

## Tech Stack

| Technology | Purpose |
|---|---|
| Google ADK | Agent framework — tool registration, LLM orchestration, web UI |
| Gemini 2.5 Flash | LLM backbone — contextual analysis and natural language generation |
| Google Cloud Run | Serverless container hosting with auto-scaling |
| Google Cloud Logging | Agent health monitoring and debugging |
| Python 3.11+ | Runtime environment |

---

## Prerequisites

- Python 3.11 or higher
- Google Cloud account with billing enabled
- Google AI API key (or Vertex AI credentials)
- Google ADK installed (`pip install google-adk`)

---

## Setup

### 1. Clone the project

```bash
git clone <your-repo-url>
cd logs_triage_agent
```

### 2. Install dependencies

```bash
pip install google-adk google-genai
```

### 3. Configure API key

Create a `.env` file inside the `logs_triage_agent/` directory:

```env
GOOGLE_API_KEY=your-api-key-here
```

### 4. Run locally with ADK

```bash
adk web
```

Then open `http://localhost:8000` in your browser and select `logs_triage_agent`.

---

## Usage

### ADK Web UI

1. Open the ADK web interface
2. Select `logs_triage_agent` from the app list
3. Paste log entries into the chat input
4. Receive a structured JSON security report

**Example input:**
```
Analyze these logs:
192.168.1.100 - - "GET /search?q=1 OR 1=1-- HTTP/1.1" 200 2326
Failed password for invalid user admin from 10.0.0.5 port 22 ssh2
10.0.0.99 - - "GET /../../etc/passwd HTTP/1.1" 403 274
```

### CLI Mode

```bash
python main.py --file sample_logs.txt
```

Or pass logs directly:

```bash
python main.py \
  '192.168.1.100 - - "GET /search?q=1 OR 1=1-- HTTP/1.1" 200 2326' \
  'Failed password for invalid user admin from 10.0.0.5 port 22 ssh2'
```

Pipe output to `jq` for filtering:

```bash
python main.py --file logs.txt | jq '.overall_risk'
```

---

## Example Output

```json
{
  "analysis": [
    {
      "log_index": 0,
      "raw_log": "192.168.1.100 - - \"GET /search?q=1 OR 1=1-- HTTP/1.1\" 200 2326",
      "log_type": "HTTP Access Log",
      "explanation": "GET request from 192.168.1.100 with SQL injection payload OR 1=1--",
      "is_suspicious": true,
      "attack_type": "SQL Injection (SQLi)",
      "vulnerabilities": [
        "Unparameterised SQL queries or missing input validation"
      ],
      "severity": "Critical",
      "remediation": "Use parameterised queries. Deploy WAF rules. Sanitise all user input."
    },
    {
      "log_index": 1,
      "raw_log": "Failed password for invalid user admin from 10.0.0.5 port 22 ssh2",
      "log_type": "Authentication Log",
      "explanation": "SSH login attempt for non-existent user admin from 10.0.0.5 failed.",
      "is_suspicious": true,
      "attack_type": "Brute-Force / Credential Stuffing",
      "vulnerabilities": [
        "No account-lockout or rate-limiting policy"
      ],
      "severity": "Medium",
      "remediation": "Enable fail2ban. Use SSH key-based authentication. Restrict SSH by IP."
    }
  ],
  "overall_summary": "Analysed 2 logs. Suspicious: 2/2. Overall risk: Critical. IMMEDIATE ACTION REQUIRED.",
  "overall_risk": "Critical",
  "recommendations": [
    "Use parameterised queries for all database access",
    "Deploy a Web Application Firewall (WAF)",
    "Enable SSH brute-force protection (fail2ban)",
    "Enforce SSH key-based authentication"
  ]
}
```

---

## Threat Detection Categories

| Category | Examples Detected |
|---|---|
| SQL Injection (SQLi) | `UNION SELECT`, `OR 1=1`, single-quote probing, `DROP TABLE` |
| Cross-Site Scripting (XSS) | `<script>`, `onerror=`, `javascript:` |
| Remote Code Execution (RCE) | `/etc/passwd`, `cmd.exe`, `powershell`, `/bin/sh` |
| Directory Traversal | `../`, `%2e%2e%2f` |
| Command Injection | `;`, `&&`, pipe chains, backtick execution |
| Brute-Force | Repeated failed logins, invalid user attempts |
| Privilege Escalation | Unexpected `sudo`, `su root`, role changes |
| Denial of Service (DoS) | SYN flood, rate limit exceeded |

---

## Deploying to Cloud Run

### 1. Build and deploy

```bash
gcloud run deploy logs-triage-guide \
  --source . \
  --region us-central1 \
  --allow-unauthenticated
```

### 2. Set environment variables

```bash
gcloud run services update logs-triage-guide \
  --set-env-vars GOOGLE_API_KEY=your-api-key-here \
  --region us-central1
```

### 3. Verify deployment

```bash
gcloud logging read \
  "resource.type=cloud_run_revision AND resource.labels.service_name=logs-triage-guide" \
  --limit 10 \
  --format="value(textPayload)"
```

Look for: `Found root_agent in logs_triage_agent.agent` without any errors.

---

## Type Safety

All tool function parameters use `str` defaults of `""` — **never `None`** — ensuring full compatibility with Google ADK's strict type validation at tool registration time.

```python
# Correct
def generate_summary(resource: str = "") -> str:

# Wrong — causes ValueError at startup
def generate_summary(resource: str = None) -> str:
```

---

## Troubleshooting

| Error | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError: No module named 'logs_triage_agent.tools'` | `tools.py` missing from deployed folder | Ensure all 4 files exist in `logs_triage_agent/` |
| `ValueError: Default value None of parameter resource: str = None` | String param defaulting to `None` | Change default to `""` |
| `from .agent import cybersec_agent` fails | `__init__.py` exports wrong name | Change to `from .agent import root_agent` |
| Agent loads but doesn't respond | Gemini API key not set | Add `GOOGLE_API_KEY` to `.env` file |

---

## License

MIT
