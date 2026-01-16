# ThreatDefender Operations Suite - Features Overview

Quick reference guide for all features in the Operations Suite.

---

## Feature Summary

| Feature | Purpose | Backend Required | Primary Technology |
|---------|---------|------------------|-------------------|
| [Threat Intel Lookup](#threat-intel-lookup) | IOC enrichment | Yes | 8+ TI APIs |
| [Alert Triage](#alert-triage--ir-playbook-generator) | Playbook generation | Yes | Azure OpenAI |
| [KQL Diff Viewer](#kql-diff-viewer--analyzer) | Rule comparison | Yes (for AI) | Monaco Editor |
| [Prompt Gallery](#prompt-gallery) | AI prompt library | Yes | Azure OpenAI + Table Storage |
| [Email Posture Check](#email-posture-check) | Domain security | Yes | DNS + MXToolbox |
| [Email Header Analyzer](#email-header-analyzer) | Header parsing | Yes | Node.js |
| [SOC Handoff](#soc-shift-handoff) | Shift communication | No | localStorage |
| [AI Triage Chat](#ai-triage-chat) | Incident follow-up | Yes | Claude AI + Cosmos DB |

---

## Threat Intel Lookup

**Path:** `/threat-intel`

**Purpose:** Query multiple threat intelligence sources simultaneously for IOC enrichment.

**Supported Indicators:**
| Type | Example | Sources Queried |
|------|---------|-----------------|
| IPv4/IPv6 | `8.8.8.8` | VT, AbuseIPDB, GreyNoise, Shodan, OTX, ARIN |
| Domain | `example.com` | VT, OTX, URLScan |
| URL | `https://malicious.com/path` | VT, URLScan, Hybrid Analysis |
| MD5 Hash | `d41d8cd98f00b204e9800998ecf8427e` | VT, OTX, Hybrid Analysis |
| SHA1 Hash | `da39a3ee5e6b4b0d3255bfef95601890afd80709` | VT, OTX, Hybrid Analysis |
| SHA256 Hash | `e3b0c44298fc1c149afbf4c8996fb924...` | VT, OTX, Hybrid Analysis |
| Email | `user@example.com` | MXToolbox |

**Key Features:**
- Auto-detects indicator type
- Parallel queries for speed (3-5 seconds)
- Color-coded severity (Green=benign, Yellow=suspicious, Red=malicious)
- Graceful degradation when sources unavailable
- One-click links to source details
- Copy results to clipboard

**API Endpoint:** `POST /api/ThreatIntelLookup`

---

## Alert Triage & IR Playbook Generator

**Path:** `/alert-triage`

**Purpose:** Generate AI-powered incident response playbooks aligned with NIST framework.

**Incident Categories (16+):**
- Phishing / Business Email Compromise
- Credential Theft / Account Compromise
- Ransomware / Malware / Cryptominer
- Data Exfiltration / Insider Threat
- Lateral Movement / Privilege Escalation
- Denial of Service / Network Intrusion
- Suspicious Login / Impossible Travel
- Policy Violation / Compliance Alert

**Severity Levels:**
| Level | Description | Typical Response |
|-------|-------------|------------------|
| Informational | Low-risk event | Monitor, document |
| Low | Minor issue | Standard triage |
| Medium | Notable concern | Investigate within SLA |
| High | Significant threat | Priority investigation |
| Critical | Active breach | Immediate response |

**Output Sections:**
1. Executive Summary
2. Initial Triage Steps
3. Investigation Procedures
4. KQL Queries (tailored to environment)
5. Containment Actions
6. Eradication Procedures
7. Recovery Steps
8. Post-Incident Actions

**Key Features:**
- MITRE ATT&CK tactic mapping with JSON schema validation
- IOC extraction with defanging support
- Environment toggles (Sentinel, MDE, MDI, MDO)
- Temperature control (0.2-0.8)
- Per-section copy buttons

**API Endpoint:** `POST /api/AlertTriage`

---

## KQL Diff Viewer & Analyzer

**Path:** `/kql-diff`

**Purpose:** Compare KQL detection rule versions and analyze security impact.

**Key Features:**
- Side-by-side Monaco Editor with syntax highlighting
- Line-level diff highlighting
- Comparison modes:
  - Standard diff
  - Ignore whitespace
  - Case insensitive
- AI-powered analysis:
  - Change overview
  - Security impact assessment
  - Performance implications
  - False positive risk
  - Recommendations
- Shareable URLs via query parameters
- Preference persistence (localStorage)

**Keyboard Shortcuts:**
| Shortcut | Action |
|----------|--------|
| `Ctrl+Enter` | Run comparison |
| `Escape` | Close/reset |
| `Ctrl+H` | Go home |

**API Endpoint:** `POST /api/kqlanalyzer`

---

## Prompt Gallery

**Paths:**
- `/prompts` - Browse gallery
- `/prompts/:id` - View/execute prompt
- `/prompts/new` - Create prompt
- `/prompts/:id/edit` - Edit prompt
- `/prompts/admin` - Audit console

**Purpose:** Centralized library of reusable AI prompts for security workflows.

**Prompt Structure:**
```
Title: Short descriptive name
Description: What the prompt does
Category: Triage | Analysis | Communication | Forensics | Other
Tags: Comma-separated keywords
Collection: Optional grouping

System Guidance: Instructions for AI behavior
User Instructions: Main prompt template with {{variables}}

Variables: Array of input definitions
  - name, type, required, default, description

Model Settings:
  - Temperature (0-1)
  - Max Tokens (100-4000)
```

**Variable Syntax:**
- `{{variable_name}}` - Double curly braces
- `{variable_name}` - Single curly braces
- `[variable_name]` - Square brackets

**Key Features:**
- Search and filter by category/tags
- Dynamic variable substitution
- Markdown rendering for output
- Full audit trail (who, when, tokens used)
- Token usage tracking for billing
- Soft deletes for compliance

**API Endpoints:**
- `GET /api/prompts` - List prompts
- `POST /api/prompts` - Create prompt
- `GET /api/prompts/:id` - Get prompt details
- `PUT /api/prompts/:id` - Update prompt
- `DELETE /api/prompts/:id` - Soft delete
- `POST /api/prompts/:id/run` - Execute prompt

---

## Email Posture Check

**Path:** `/email-posture`

**Purpose:** Analyze email security configuration for a domain.

**Protocols Checked:**

| Protocol | Purpose | Status Indicators |
|----------|---------|-------------------|
| **SPF** | Sender Policy Framework - authorized mail servers | Pass/Warn/Fail |
| **DMARC** | Domain-based Message Authentication | Pass/Warn/Fail |
| **DKIM** | DomainKeys Identified Mail signatures | Pass/Fail/Not Found |
| **MX** | Mail Exchange records | Pass/Fail |
| **MTA-STS** | SMTP TLS enforcement policy | Pass/Not Configured |
| **BIMI** | Brand Indicators for Message Identification | Pass/Not Configured |

**Key Features:**
- Custom DKIM selector support
- Auto-tries common selectors: `default`, `google`, `k1`, `s1`, `s2`, `dkim`, `mail`, `smtp`, `email`
- 5-minute result caching
- Auto-expand sections with issues
- Optional MXToolbox enrichment (requires API key)
- Export to Markdown

**API Endpoint:** `POST /api/EmailPosture`

---

## Email Header Analyzer

**Path:** `/email-header`

**Purpose:** Parse and analyze raw email headers for security assessment.

**Analysis Includes:**
- Authentication results (SPF, DKIM, DMARC)
- Hop-by-hop routing analysis
- Delay detection between hops
- Header validation
- Phishing indicators:
  - Spoofed sender addresses
  - Suspicious routing
  - Failed authentication
  - Unusual headers

**Key Features:**
- Paste raw headers for instant analysis
- Color-coded pass/fail for auth results
- Timeline view of email routing
- Suspicious indicator highlighting

**API Endpoint:** `POST /api/EmailHeaderAnalyzer`

---

## SOC Shift Handoff

**Path:** `/soc-handoff`

**Purpose:** Structured shift-to-shift communication for SOC teams.

**Data Tracked:**

| Section | Fields |
|---------|--------|
| **Shift Info** | Current analyst, next analyst, shift times |
| **Incidents** | ID, title, severity, status, next actions, assignee |
| **Tasks** | Description, priority, due date, assignee |
| **Escalations** | Type, escalated to, reason |
| **System Health** | Infrastructure/tool status notes |
| **General Notes** | Free-form shift notes |

**Severity/Priority Levels:**
- Critical (P1)
- High (P2)
- Medium (P3)
- Low (P4)

**Key Features:**
- Fully offline capable (browser localStorage)
- No backend required
- Auto-save on changes
- HTML export for handoff reports
- Print-friendly output

---

## AI Triage Chat

**Path:** `/triage/:sessionId`

**Purpose:** Interactive follow-up chat for Microsoft Sentinel incidents.

**Session Flow:**
1. Sentinel incident triggers Logic App
2. Logic App creates session via API
3. Teams notification includes chat link
4. Analyst clicks link to continue conversation

**Initial Analysis Display:**
- Incident summary
- Severity assessment
- MITRE techniques identified
- Recommended actions

**Dynamic Quick Actions:**

| Incident Type | Keywords Detected | Quick Actions |
|---------------|-------------------|---------------|
| **Email** | phishing, spam, BEC, malicious email | Check clicked links, pull mailbox logs, check forwarding |
| **Identity** | sign-in, impossible travel, MFA | Verify travel/VPN, recent sign-ins, CA policy hits |
| **Malware** | malware, ransomware, EDR | Device isolation, process tree, lateral movement |
| **Data Protection** | exfiltration, DLP, sensitive | Data accessed, user authorized, revoke access |
| **General** | (fallback) | Critical steps, TP/FP assessment, executive summary |

**Key Features:**
- 7-day session persistence (Cosmos DB TTL)
- Full incident context maintained
- One-click KQL query copying
- Dark theme UI
- Powered by Claude AI

**API Endpoint:** `GET/POST /api/TriageSession`

---

## Feature Dependencies

```
                    ┌─────────────────┐
                    │  Azure OpenAI   │
                    └────────┬────────┘
                             │
        ┌────────────────────┼────────────────────┐
        │                    │                    │
        ▼                    ▼                    ▼
┌───────────────┐  ┌─────────────────┐  ┌─────────────────┐
│ KQL Analyzer  │  │  Alert Triage   │  │ Prompt Gallery  │
└───────────────┘  └─────────────────┘  │   (Execute)     │
                                        └────────┬────────┘
                                                 │
                                        ┌────────▼────────┐
                                        │ Azure Storage   │
                                        │ (Prompts Table) │
                                        └─────────────────┘

┌─────────────────┐     ┌─────────────────┐
│  Claude AI      │────▶│  AI Triage Chat │
└─────────────────┘     └────────┬────────┘
                                 │
                        ┌────────▼────────┐
                        │  Cosmos DB      │
                        │  (Sessions)     │
                        └─────────────────┘

┌─────────────────┐
│  8+ TI APIs     │────▶  Threat Intel Lookup
└─────────────────┘

┌─────────────────┐
│  DNS + MXToolbox│────▶  Email Posture Check
└─────────────────┘

┌─────────────────┐
│  localStorage   │────▶  SOC Handoff (Offline)
└─────────────────┘
```

---

## Keyboard Shortcuts (Global)

| Shortcut | Action |
|----------|--------|
| `Ctrl+H` | Navigate to home |
| `Ctrl+Enter` | Execute primary action |
| `Escape` | Cancel/close/exit |

---

## Related Documentation

- [SECURITY_ANALYST_GUIDE.md](SECURITY_ANALYST_GUIDE.md) - Detailed usage guide
- [ARCHITECTURE_SUMMARY.md](ARCHITECTURE_SUMMARY.md) - Technical deep-dive
- [API_REFERENCE.md](API_REFERENCE.md) - API endpoint details
- [AZURE_CONFIG.md](AZURE_CONFIG.md) - Configuration reference
