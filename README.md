# ThreatDefender Operations Suite

**eGroup Enabling Technologies | ThreatHunter MSSP Team**

A comprehensive web-based security operations platform built by defenders, for defenders. Streamlines investigation, response, and handoff workflows across Microsoft Sentinel and the Defender stack.

---

## Overview

**ThreatDefender Operations Suite** consolidates 7 essential SOC tools into a unified platform, reducing tab-switching and accelerating threat response. Powered by AI and integrated with 8+ threat intelligence sources, it enables security analysts to work smarter, not harder.

**Key Highlights:**
- 7 integrated security tools in one platform
- 8+ threat intelligence sources queried in parallel
- AI-powered analysis using Azure OpenAI (GPT-4) and Claude
- Full audit trail for compliance
- Mobile-responsive with dark/light mode support

---

## Features

### Threat Intelligence Lookup
Real-time IOC enrichment from 8+ sources in parallel:
- **VirusTotal** - File, URL, IP, domain reputation
- **AlienVault OTX** - IOC enrichment and threat pulses
- **AbuseIPDB** - IP abuse reports and confidence scores
- **GreyNoise** - IP classification (benign scanner vs malicious)
- **Shodan** - Internet-wide scanning and exposure data
- **URLScan** - URL and domain behavioral analysis
- **MXToolbox** - Email and DNS record analysis
- **Hybrid Analysis** - Malware sandbox behavioral analysis
- **ARIN RDAP** - IP ownership and allocation (always available)

Auto-detects indicator type and returns consolidated results in 3-5 seconds.

---

### Alert Triage & IR Playbook Generator
AI-powered incident response playbook generation aligned with NIST framework:
- 16+ incident categories (Phishing, Ransomware, Credential Theft, etc.)
- 5 severity levels with MITRE ATT&CK tactic mapping
- Environment-specific KQL queries for Sentinel, MDE, MDI, MDO
- IOC extraction with defanging/refanging support
- Containment and recovery recommendations
- Configurable AI temperature for focused or creative outputs

Generates comprehensive playbooks in ~30 seconds.

---

### KQL Diff Viewer & Analyzer
Compare and analyze KQL detection rule changes before production deployment:
- Side-by-side Monaco Editor with syntax highlighting
- Line-level diff visualization (added/removed/changed)
- Whitespace and case-insensitive comparison modes
- AI-powered security impact analysis:
  - Change overview and purpose
  - Security implications
  - Performance considerations
  - False positive risk assessment
- Shareable URLs for team collaboration
- Keyboard shortcuts (Ctrl+Enter to compare)

---

### Prompt Gallery
Centralized library of reusable AI prompts for security workflows:
- **Browse & Search** - Filter by category, tags, or full-text search
- **Dynamic Variables** - Define inputs ({{username}}, {{ip_address}}, etc.)
- **Execute & Export** - Run prompts with context and copy formatted output
- **Create Custom Prompts** - Markdown support, variable definitions, model settings
- **Full Audit Trail** - Track executions, token usage, and user attribution

Standardize team workflows and maintain compliance with execution logging.

---

### Email Security Tools

**Email Posture Check:**
- Domain-based security posture analysis
- Protocol checks: SPF, DMARC, DKIM, MX, MTA-STS, BIMI
- Pass/Warn/Fail status indicators with actionable guidance
- Optional MXToolbox enrichment
- 5-minute result caching

**Email Header Analyzer:**
- Raw email header parsing and validation
- Authentication result analysis (SPF, DKIM, DMARC)
- Phishing indicator detection
- Hop-by-hop routing analysis

---

### SOC Shift Handoff Tool
Structured shift-to-shift communication for 24/7 SOC operations:
- Incident tracking (ID, severity, status, next actions)
- Task management with priority and due dates
- Escalation documentation
- System health notes
- HTML export for handoff reports
- Fully offline capable (browser localStorage)

---

### AI Triage Chat
Interactive follow-up chat for Microsoft Sentinel incidents:
- **Session Persistence** - Cosmos DB storage with 7-day TTL
- **Initial Analysis** - AI-generated summary, severity, MITRE techniques
- **Dynamic Quick Actions** by incident type:
  - Email: Check clicked links, mailbox logs, forwarding rules
  - Identity: Verify travel/VPN, sign-in history, CA policy hits
  - Malware: Device isolation, process tree, lateral movement
  - Data Protection: Access review, DLP alerts, revoke access
- **Copy Code Blocks** - One-click KQL query copying
- Accessible via Teams notification links

---

## Quick Start

### Prerequisites
- Node.js 18+
- Azure Functions Core Tools v4
- Azure subscription (for full functionality)

### Local Development

```bash
# Install dependencies
npm install
cd api && npm install && cd ..

# Start backend (Terminal 1)
cd api && npm start

# Start frontend (Terminal 2)
npm start
```

Frontend: http://localhost:3000
Backend API: http://localhost:7071

### Configuration

See [DEV_SETUP.md](DEV_SETUP.md) for detailed local setup instructions.

---

## Documentation

| Document | Description |
|----------|-------------|
| [FEATURES_OVERVIEW.md](FEATURES_OVERVIEW.md) | Quick reference for all features |
| [SECURITY_ANALYST_GUIDE.md](SECURITY_ANALYST_GUIDE.md) | User guide for SOC analysts |
| [DEV_SETUP.md](DEV_SETUP.md) | Local development setup |
| [ARCHITECTURE_SUMMARY.md](ARCHITECTURE_SUMMARY.md) | Technical architecture deep-dive |
| [API_REFERENCE.md](API_REFERENCE.md) | Complete API documentation |
| [AZURE_CONFIG.md](AZURE_CONFIG.md) | Environment variables reference |
| [PROMPT_GALLERY_SETUP.md](PROMPT_GALLERY_SETUP.md) | Prompt Gallery configuration |
| [AI_TRIAGE_CHAT_SETUP.md](AI_TRIAGE_CHAT_SETUP.md) | AI Triage Chat setup guide |
| [THREAT_INTEL_SETUP.md](THREAT_INTEL_SETUP.md) | Threat intel API configuration |
| [TROUBLESHOOTING_PROMPTS.md](TROUBLESHOOTING_PROMPTS.md) | Common issues and solutions |

---

## Tech Stack

| Layer | Technology |
|-------|-------------|
| Frontend | React 19.2, React Router 7.9, Tailwind CSS, Framer Motion |
| Backend | Azure Functions v4, Node.js 18+ |
| Code Editor | Monaco Editor |
| Storage | Azure Table Storage, Azure Cosmos DB |
| AI | Azure OpenAI (GPT-4), Claude AI via Azure AI Foundry |
| Integration | Microsoft Sentinel, Defender APIs, 8+ Threat Intel APIs |
| Hosting | Azure Static Web Apps |

---

## License

This project is maintained by eGroup Enabling Technologies - ThreatDefender MSSP Team.
Copyright 2026. All Rights Reserved.
