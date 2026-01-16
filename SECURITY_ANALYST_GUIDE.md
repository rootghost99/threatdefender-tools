# ThreatDefender Operations Suite - Security Analyst Quick Start Guide

**Version 1.0** | **Target Audience:** SOC Analysts, Incident Responders, Security Operations

---

## Overview

ThreatDefender is a web-based security operations platform that consolidates 7 essential tools into one interface. Access at your deployment URL and navigate using the top menu bar.

**Quick Navigation Shortcuts:**
- `Ctrl+H` - Return to home
- `Ctrl+Enter` - Execute action in current tool
- `Escape` - Exit/cancel operation

---

## 1. Threat Intel Lookup

**Purpose:** Instantly enrich IOCs (IPs, domains, URLs, hashes, emails) across 8+ threat intelligence sources.

**When to Use:**
- Alert triage - is this indicator malicious?
- Phishing investigation - check sender domain/IP reputation
- Malware analysis - hash reputation lookup
- Quick IOC validation before escalation

**How to Use:**
1. Paste your indicator (IP, domain, hash, URL, or email) into the search box
2. System auto-detects the indicator type
3. Results appear from VirusTotal, AlienVault OTX, AbuseIPDB, Greynoise, Shodan, URLScan, MXToolbox, and Hybrid Analysis
4. Review threat scores and color-coded severity
5. Click "Copy" to grab individual results or "View in VirusTotal" for deeper analysis

**Pro Tips:**
- Green = benign, Yellow = suspicious, Red = malicious
- If one source is down, others still provide data (graceful degradation)
- Results load in parallel for speed (~3-5 seconds)

---

## 2. IR Playbook Generator

**Purpose:** Generate structured, NIST-aligned incident response playbooks using AI in ~30 seconds.

**When to Use:**
- Major incident declared - need immediate response plan
- Unfamiliar attack type - get guidance on investigation steps
- Need KQL queries for Sentinel/MDE investigation
- Client-facing incident requiring documented procedures

**How to Use:**
1. Select **Incident Category** (Phishing, Ransomware, Credential Theft, etc. - 16 types available)
2. Choose **Severity Level** (Informational → Critical)
3. Specify your **Environment** (toggle Sentinel, MDE, MDI, MDO)
4. Fill in **Incident Details** (affected users, IPs, systems, description)
5. Adjust **Temperature** (0.3 = focused/deterministic, 0.7 = creative/exploratory)
6. Click **Generate Playbook**
7. Review sections: Triage → Investigation → KQL Queries → Containment → Eradication → Recovery
8. Use "Copy" buttons to grab KQL queries or procedures

**Pro Tips:**
- Lower temperature (0.2-0.4) for standard incidents following best practices
- Higher temperature (0.6-0.8) for unique/complex scenarios requiring creative approaches
- KQL queries are tailored to your environment toggles
- MITRE ATT&CK tactics auto-mapped for threat classification
- Each section is independently copyable for ticket updates

---

## 3. KQL Diff Viewer & Analyzer

**Purpose:** Compare detection rule changes and analyze security/performance impact before deploying to production.

**When to Use:**
- Tuning detection rules to reduce false positives
- Peer review of KQL query modifications
- Understanding security impact of proposed changes
- Validating syntax before deploying to Sentinel

**How to Use:**
1. Paste **Original KQL** in left editor
2. Paste **Updated KQL** in right editor
3. Click **Compare** (or press `Ctrl+Enter`)
4. Review visual diff with highlighted changes (green = added, red = removed)
5. (Optional) Click **Run AI Analysis** for security/performance assessment
6. AI provides: change overview, security impact, performance implications, false positive risk, recommendations
7. Share URL with team for collaborative review

**Pro Tips:**
- Real-time syntax validation catches errors (unmatched parentheses, typos, missing pipes)
- Toggle "Ignore Whitespace" for cleaner diffs
- Warnings appear for expensive operations (joins, unions)
- Settings persist in browser (view mode, whitespace preferences)
- Use AI analysis before production deployment

---

## 4. Prompt Gallery

**Purpose:** Library of reusable AI prompts for standardizing security analysis tasks with full audit trail.

**When to Use:**
- Repetitive analysis tasks (alert triage, log analysis, client comms)
- Need standardized output format for reports
- Training new analysts on consistent procedures
- Tracking AI usage for compliance/billing

**How to Use:**
1. **Browse:** Navigate gallery or use search/filters to find relevant prompt
2. **Review:** Click prompt card to see description, variables, and expected output
3. **Execute:**
   - Fill required variables (e.g., IP address, alert ID, user email)
   - Add optional context in "Additional Context" box
   - Click **Run Prompt**
4. **Review Output:** Formatted results appear (supports Markdown)
5. **Copy:** Grab output for tickets, emails, or documentation

**Admin Features (if authorized):**
- **Create Prompts:** Define reusable templates with variables
- **Audit Console:** View all executions (who, when, token usage)
- **Track Costs:** Monitor token consumption for billing

**Pro Tips:**
- Variables use {{var}}, {var}, or [var] format
- All executions logged (user, timestamp, input/output, tokens)
- Prompts can have default values for faster execution
- Use collections to group related prompts (e.g., "Phishing Analysis")

---

## 5. Email Security Posture Check

**Purpose:** Comprehensive email authentication analysis (SPF, DMARC, DKIM, MX, MTA-STS, BIMI).

**When to Use:**
- Phishing investigation - validate sender domain authenticity
- Client onboarding - assess email security posture
- Incident response - determine if email could be spoofed
- Security assessments - identify misconfigured domains

**How to Use:**
1. Enter **Domain** to check (e.g., `example.com`)
2. (Optional) Specify **DKIM Selectors** if known (comma-separated: `selector1,selector2`)
3. Click **Check Email Posture**
4. Review results by protocol:
   - ✅ **Pass** - Properly configured
   - ⚠️ **Warn** - Configured but has issues
   - ❌ **Fail** - Misconfigured or vulnerable
   - ⭕ **Not Configured** - Missing protection
5. Sections with issues auto-expand for quick review
6. Click **Export to Markdown** for client reports

**What Each Protocol Means:**
- **SPF** - Prevents email spoofing (lists authorized mail servers)
- **DMARC** - Policy for handling authentication failures (reject/quarantine)
- **DKIM** - Cryptographic signature validates email integrity
- **MX** - Mail server configuration
- **MTA-STS** - Enforces TLS encryption for email transmission
- **BIMI** - Brand logo display (requires DMARC enforcement)

**Pro Tips:**
- Results cached for 5 minutes (faster repeat checks)
- Common selectors tried automatically: `default`, `google`, `k1`, `s1`, `s2`, `dkim`, `mail`, `smtp`, `email`
- Use during phishing investigations to check if domain can be spoofed
- Export to Markdown for documentation/client reports

---

## 6. SOC Shift Handoff

**Purpose:** Structured shift-to-shift communication to ensure continuity in 24/7 SOC operations.

**When to Use:**
- End of your shift - document ongoing work
- Critical incidents spanning multiple shifts
- Task tracking across the team
- Escalation documentation

**How to Use:**
1. **Setup Shift Info:**
   - Your name (Current Analyst)
   - Next shift analyst name
   - Shift start/end times
2. **Add Incidents:**
   - ID, Title, Severity (Critical → Low)
   - Status (Open, In Progress, Escalated, Resolved)
   - Next Actions, Assigned Analyst
3. **Add Tasks:**
   - Description, Priority (High → Low)
   - Due Date, Assignee
4. **Document Escalations:**
   - Type (Management, Security Team, Engineering, Client)
   - Who it was escalated to, Reason
5. **System Health Notes:** Infrastructure/tool status
6. **General Notes:** Additional context
7. Click **Generate Handoff Report** to create HTML export
8. Print or save for incoming analyst

**Pro Tips:**
- Data auto-saves in browser (survives page refresh)
- Use Severity levels consistently (Critical = P1, High = P2, etc.)
- Document "Next Actions" clearly for incoming analyst
- Export before shift end in case of browser issues
- HTML export is print-friendly for physical handoff

---

## 7. AI Triage Chat

**Purpose:** Interactive follow-up chat for Microsoft Sentinel incidents, accessible from Teams notifications.

**When to Use:**
- After receiving initial AI triage notification in Teams
- Need follow-up questions about an incident
- Want KQL queries specific to incident context
- Need to assess true positive vs false positive
- Generating executive summaries or documentation

**How to Access:**
1. Receive Teams notification from Sentinel incident with "Continue Chat" link
2. Click the link to open the AI Triage Chat interface
3. View initial AI analysis (summary, severity, MITRE techniques, recommendations)
4. Use quick action buttons or type custom questions
5. AI maintains full incident context throughout conversation

**Quick Action Buttons (Dynamic by Incident Type):**

📧 **Email Threats** (phishing, spam, BEC):
- Check clicked links
- Pull mailbox logs
- Check forwarding
- List recipients
- Draft notification

🔐 **Identity Threats** (sign-in, impossible travel, MFA):
- Verify travel/VPN
- Recent sign-ins
- Other risky sign-ins
- Password reset?
- CA policy hits

🦠 **Malware** (ransomware, EDR, suspicious process):
- Device isolated?
- Process tree
- Lateral movement
- Other devices
- Run full scan?

📊 **Data Protection** (exfiltration, DLP, sensitive data):
- What data?
- User authorized?
- Other DLP alerts
- Revoke access?
- Draft report

🔍 **General** (fallback for other incident types):
- Critical steps
- TP/FP assessment
- Log recommendations
- Executive summary

**Pro Tips:**
- Sessions persist for 7 days - bookmark the URL to return later
- Click "Copy" button on code blocks to grab KQL queries
- AI has full incident context - reference specific details in your questions
- Quick actions send pre-crafted expert questions
- Initial analysis card is collapsible if you need more space

---

## Typical Incident Response Workflow

**Scenario:** Phishing alert triggered for suspicious email

1. **Triage (Threat Intel Lookup):**
   - Check sender IP reputation → **Threat Intel Lookup**
   - Check sender domain authentication → **Email Posture Check**
   - Check attachment hash (if applicable) → **Threat Intel Lookup**

2. **Response Plan (IR Playbook Generator):**
   - Category: Phishing, Severity: Medium/High
   - Generate playbook with KQL queries
   - Follow investigation steps

3. **Investigation (KQL Diff Viewer):**
   - Run KQL queries from playbook in Sentinel
   - Tune queries to reduce noise
   - Use Diff Viewer to validate changes before saving

4. **Standardized Analysis (Prompt Gallery):**
   - Use "Phishing Email Analysis" prompt
   - Input: email headers, sender, subject, body
   - Output: structured analysis for ticket/email

5. **Follow-up Questions (AI Triage Chat):**
   - Click "Continue Chat" link from Teams notification
   - Use quick action buttons for email-specific questions
   - Ask for mailbox logs, forwarding rules, recipient lists
   - Copy KQL queries directly from responses

6. **Documentation (SOC Handoff):**
   - Add incident to handoff if unresolved
   - Document next actions for incoming shift

---

## Best Practices

### Think, Don't Copy
- All tools emphasize **understanding** over blind execution
- Read splash screens and guidance messages
- Validate AI-generated outputs before production use
- Question results that seem incorrect

### Keyboard Efficiency
- Learn shortcuts: `Ctrl+H` (home), `Ctrl+Enter` (execute), `Escape` (cancel)
- Use copy buttons instead of manual selection
- Bookmark frequently-used tools

### Audit & Compliance
- Prompt Gallery tracks all AI usage (who, when, what)
- Export important results for case files
- Use structured outputs for consistency

### Performance
- Results cache where applicable (Email Posture: 5 min)
- Parallel queries run automatically (Threat Intel)
- Use browser dark mode toggle for eye strain reduction

---

## Support & Troubleshooting

**Common Issues:**

1. **API Keys Missing:** Some features require API configuration (VirusTotal, Shodan, etc.). Contact your admin.
2. **Slow Loading:** Check network connection. APIs run in parallel but depend on third-party services.
3. **Syntax Errors in KQL:** Use Diff Viewer's real-time validation before running in Sentinel.
4. **Prompt Gallery Not Loading:** Verify Azure Table Storage connection (backend dependency).

**Need Help?**
- Check project README and ARCHITECTURE_SUMMARY for technical details
- Review TROUBLESHOOTING_PROMPTS.md for common issues
- Contact your platform administrator for API key or access issues

---

## Quick Reference Card

| Tool | Use Case | Key Input | Output | Speed |
|------|----------|-----------|--------|-------|
| **Threat Intel Lookup** | IOC enrichment | IP/Domain/Hash/URL | Reputation scores from 8+ sources | 3-5 sec |
| **IR Playbook Generator** | Response planning | Incident type, severity, environment | NIST playbook + KQL queries | ~30 sec |
| **KQL Diff Viewer** | Rule validation | Old/New KQL queries | Visual diff + AI security analysis | Instant/15 sec |
| **Prompt Gallery** | Standardized analysis | Prompt + variables | AI-generated structured output | 10-30 sec |
| **Email Posture Check** | Domain authentication | Domain name | SPF/DMARC/DKIM/MX/MTA-STS/BIMI status | 5-10 sec |
| **SOC Handoff** | Shift continuity | Incidents/Tasks/Notes | HTML handoff report | Instant |
| **AI Triage Chat** | Incident follow-up | Teams link / Session ID | Interactive AI analysis + KQL queries | 5-15 sec |

---

**End of Guide** | For technical architecture details, see ARCHITECTURE_SUMMARY.md | For development setup, see DEV_SETUP.md
