# ThreatDefender Operations Suite - Technical Architecture Document

**Version:** 1.2
**Date:** January 2026
**Last Updated:** 2026-01-16
**Purpose:** High-level architecture documentation for executive overview generation

---

## 1. EXECUTIVE SUMMARY

ThreatDefender Operations Suite is a modern web-based security operations platform built for MSSP teams. It integrates threat intelligence, incident response automation, and SOC workflow tools into a unified interface, leveraging Azure cloud services and AI-powered analysis to accelerate security operations.

**Key Statistics:**
- **7 major tools/modules** integrated into single platform
- **8+ threat intelligence sources** queried in parallel
- **Serverless architecture** for scalability and cost efficiency
- **AI-powered analysis** using Azure OpenAI GPT-4 and Claude AI
- **Mobile-responsive** design with dark/light modes
- **AI Triage Chat** for interactive Sentinel incident follow-up

---

## 2. SYSTEM ARCHITECTURE

### 2.1 Technology Stack

**Frontend:**
- React 19.2.0 with React Router for navigation
- Tailwind CSS for responsive design
- Framer Motion for smooth animations
- Monaco Editor for code editing/diff viewing
- Lazy loading for optimal performance

**Backend:**
- Azure Functions v4 (Node.js 18+)
- Serverless architecture (auto-scaling, pay-per-use)
- REST API pattern avoiding SDK crypto issues
- Azure Table Storage for data persistence
- Azure Cosmos DB for chat session storage

**AI/ML:**
- Azure OpenAI (GPT-4) primary
- Claude AI via Azure AI Foundry (AI Triage Chat)
- OpenAI API fallback
- Configurable temperature/token controls

**Infrastructure:**
- Azure Static Web Apps (hosting + CI/CD)
- Azure Table Storage (Prompts, PromptRuns)
- Azure Cosmos DB (TriageDB/Sessions)
- Cloudflare DNS resolver (email posture checks)
- Azure Active Directory (optional authentication)
- Azure Logic Apps (Sentinel incident triggers)

### 2.2 Integration Points

**Threat Intelligence Sources (8+):**
1. **VirusTotal** - File/URL/IP/Domain reputation
2. **AlienVault OTX** - IOC enrichment and threat pulses
3. **AbuseIPDB** - IP abuse reports
4. **Greynoise** - IP classification (benign vs malicious)
5. **Shodan** - Internet-wide scanning data
6. **URLScan** - URL/Domain behavioral analysis
7. **MXToolbox** - Email/DNS records
8. **Hybrid Analysis** - Malware sandbox analysis
9. **ARIN RDAP** - IP ownership/allocation (always available, no auth)

**AI Integration:**
- Azure OpenAI REST API (2024-08-01-preview)
- GPT-4 deployment for query analysis, playbook generation, prompt execution
- Token usage tracking and billing attribution

---

## 3. CORE MODULES & FEATURES

### 3.1 Threat Intelligence Lookup
**Purpose:** Multi-source IOC enrichment for rapid threat assessment

**Capabilities:**
- Automatic indicator type detection (IP, domain, URL, hash, email)
- Parallel queries to 8+ intelligence sources
- Hybrid Analysis malware lookups
- ARIN RDAP ownership data
- Real-time aggregated results display
- No manual API selection required

**Technical Details:**
- Backend: `/api/ThreatIntelLookup`, `/api/HybridAnalysisLookup`
- Frontend: `ThreatIntelLookup.jsx`
- Performance: Parallel async queries for speed
- Error handling: Graceful degradation if sources unavailable

**Business Value:** Reduces analyst research time from minutes to seconds by consolidating 8+ threat intelligence sources into a single query.

---

### 3.2 KQL Diff Viewer & Analyzer
**Purpose:** Compare and analyze changes to KQL (Kusto Query Language) detection rules

**Capabilities:**
- Side-by-side query comparison with Monaco Editor
- Line-level diff highlighting
- Whitespace & case-insensitive comparison modes
- AI-powered change analysis:
  - Overview of modifications
  - Security impact assessment
  - Performance implications
  - False positive risk detection
  - Actionable recommendations
- Shareable URLs with query parameters
- Global keyboard shortcuts (Ctrl+Enter, Escape)
- Preference persistence (localStorage)

**Technical Details:**
- Backend: `/api/kqlanalyzer` (Azure OpenAI REST API)
- Frontend: `KQLDiffViewer.jsx` with Monaco Editor
- Share functionality: URL query params for collaboration

**Business Value:** Ensures detection rule changes are peer-reviewed and understood before deployment, reducing false positives and missed detections.

---

### 3.3 IR Playbook Generator
**Purpose:** Generate structured incident response playbooks aligned with NIST framework

**Capabilities:**
- 16+ incident categories (Phishing, Credential Theft, Ransomware, etc.)
- 5 severity levels (Informational → Critical)
- Environment configuration (Sentinel, MDE, MDI, MDO)
- MITRE ATT&CK tactic auto-mapping
- Temperature control (creative vs deterministic)
- Generates comprehensive playbooks including:
  - Executive Summary
  - Initial Triage steps
  - Investigation procedures
  - KQL queries (detection validation, lateral movement, timeline)
  - Containment actions
  - Eradication procedures
  - Recovery steps
  - Post-incident actions
- One-click copy to clipboard per section

**Technical Details:**
- Backend: `/api/IRPlaybook` with JSON schema validation
- Frontend: `IRPlaybookGenerator.jsx`
- MITRE mapping: Category → Tactic → ID lookup
- Model: Azure OpenAI GPT-4

**Business Value:** Standardizes incident response across team, ensures NIST/MITRE alignment, reduces playbook creation time from hours to seconds.

---

### 3.4 Prompt Gallery (AI Automation Library)
**Purpose:** Centralized repository of reusable AI prompts for security analysis

**Capabilities:**
- Browse/search/filter prompt library
- Create custom prompts with:
  - Markdown-supported system guidance
  - Variable definitions (name, type, required, default value)
  - Category/tags/collection organization
  - Temperature and token limits
- Variable substitution engine (supports `{{var}}`, `{var}`, `[var]`)
- Execute prompts with context-aware inputs
- Audit trail (PromptRuns table)
- Token usage tracking per execution
- Edit/delete with unsaved changes detection
- Admin console for bulk management

**Technical Details:**
- Backend: `/api/prompts/*` (REST CRUD operations)
- Storage: Azure Table Storage (Prompts, PromptRuns tables)
- Frontend: `PromptGallery.jsx`, `PromptDetail.jsx`, `PromptEditor.jsx`, `PromptAdmin.jsx`
- Authentication: User attribution via `x-ms-client-principal` header

**Business Value:** Enables team to codify security analysis workflows, share best practices, and automate repetitive tasks while maintaining full audit compliance.

---

### 3.5 Email Security Posture Check
**Purpose:** Comprehensive email authentication & security configuration analysis

**Capabilities:**
- Domain-based security posture analysis
- Custom DKIM selector support
- Protocol checks:
  - **SPF** (Sender Policy Framework)
  - **DMARC** (Domain-based Message Authentication)
  - **DKIM** (DomainKeys Identified Mail)
  - **MX** (Mail Exchange records)
  - **MTA-STS** (SMTP TLS enforcement)
  - **BIMI** (Brand Indicators for Message Identification)
- Status indicators (Pass/Warn/Fail/Not Configured)
- Actionable guidance per protocol
- Auto-expand sections with issues
- Optional MXToolbox enrichment
- 5-minute result caching

**Technical Details:**
- Backend: `/api/EmailPosture` with Cloudflare DNS resolver
- Frontend: `EmailPostureCheck.jsx`
- Cache: In-memory, 5-minute TTL

**Business Value:** Enables rapid email security assessments for clients, identifies misconfigurations that could lead to phishing/spoofing attacks.

---

### 3.6 SOC Shift Handoff Tool
**Purpose:** Structured shift-to-shift communication for SOC teams

**Capabilities:**
- Incident tracking (ID, severity, status, next actions)
- Task management (priority, due dates, assignees)
- Escalation tracking
- System health notes
- General shift notes
- Analyst assignment
- Shift time tracking
- localStorage persistence (no backend required)
- Export/document generation

**Technical Details:**
- Frontend only: `SOCHandoffTool.jsx`
- Storage: Browser localStorage
- No API calls (fully offline capable)

**Business Value:** Ensures critical information is passed between shifts, reduces duplicate work, maintains operational continuity.

---

### 3.7 AI Triage Chat
**Purpose:** Interactive follow-up chat for Microsoft Sentinel incidents with persistent session storage

**Capabilities:**
- Session creation via Logic App integration
- Persistent chat sessions in Cosmos DB (7-day TTL)
- Initial AI analysis display (summary, severity, MITRE techniques, recommendations)
- Dynamic quick action buttons based on incident type:
  - Email threats: Check clicked links, pull mailbox logs, check forwarding, list recipients
  - Identity threats: Verify travel/VPN, recent sign-ins, risky sign-ins, CA policy hits
  - Malware: Device isolation, process tree, lateral movement, IOC spread
  - Data protection: Data accessed, user authorization, DLP alerts, revoke access
  - General: Critical steps, TP/FP assessment, log recommendations, executive summary
- Incident type auto-detection from title keywords
- One-click copy for KQL queries and code blocks
- Conversation history persistence
- Dark theme UI consistent with Ops Suite

**Technical Details:**
- Backend: `/api/TriageSession` (Cosmos DB REST API)
- Frontend: `TriageChat.jsx` with React Router
- Storage: Azure Cosmos DB (TriageDB database, Sessions container)
- AI: Claude API via Azure AI Foundry
- Integration: Sentinel Logic Apps create sessions, Teams notifications link to chat

**Business Value:** Enables analysts to continue investigation conversations from Teams notifications, maintains context across sessions, provides contextual quick actions for faster triage.

---

## 4. API ARCHITECTURE

All endpoints support CORS with `*` origin and follow REST conventions.

### 4.1 API Endpoint Summary

| Endpoint | Method | Purpose | Authentication |
|----------|--------|---------|----------------|
| `/api/prompts` | GET | List all active prompts | Optional AAD |
| `/api/prompts` | POST | Create new prompt | Optional AAD |
| `/api/prompts/{id}` | GET | Get prompt details | Optional AAD |
| `/api/prompts/{id}` | PUT | Update prompt | Optional AAD |
| `/api/prompts/{id}` | DELETE | Soft delete prompt | Optional AAD |
| `/api/prompts/{id}/run` | POST | Execute prompt | Optional AAD |
| `/api/kqlanalyzer` | POST | Analyze KQL differences | Anonymous |
| `/api/IRPlaybook` | POST | Generate IR playbook | Anonymous |
| `/api/ThreatIntelLookup` | POST | Query threat intel sources | Anonymous |
| `/api/HybridAnalysisLookup` | POST | Query Hybrid Analysis | Anonymous |
| `/api/EmailPosture` | POST | Analyze email security | Anonymous |
| `/api/TriageSession` | GET | Get triage chat session | Anonymous |
| `/api/TriageSession` | POST | Create session or send message | Anonymous |
| `/api/HealthCheck` | GET | System health status | Anonymous |

### 4.2 Data Models

**Prompts Table Schema:**
```
- PartitionKey: "PROMPT"
- RowKey: Unique ID (timestamp + random)
- title, description, category, tags, collection
- variables (JSON array of definitions)
- systemGuidance, userInstructions (Markdown)
- modelSettings (temperature, maxTokens)
- status ("active" | "deleted")
- createdBy, createdAt, updatedBy, updatedAt
- isDeleted (soft delete flag)
```

**PromptRuns Table Schema:**
```
- PartitionKey: "PROMPT_RUN"
- RowKey: Unique run ID
- promptId, promptTitle
- submittedBy, submittedAt
- contextSummary, variables (JSON)
- provider, deployment, output
- promptTokens, completionTokens, totalTokens
- status ("completed" | "failed")
- temperature, maxTokens
```

**Triage Sessions (Cosmos DB) Schema:**
```
- id: Session UUID
- incidentId: Sentinel incident ID (partition key)
- incidentTitle, incidentSeverity, tenantName
- systemPrompt: AI context prompt
- incidentContext: Raw incident JSON
- initialAnalysis: { summary, severity, confidence, mitreTechniques, recommendedActions }
- conversationHistory: [{ role, content }]
- createdAt, lastUpdated
- messageCount
- ttl: 604800 (7 days)
```

---

## 5. SECURITY & COMPLIANCE

### 5.1 Authentication & Authorization
- **Azure Active Directory** integration (optional)
- Client principal header (`x-ms-client-principal`) for user attribution
- SAS token authentication for Azure Storage (time-limited, 1 hour expiry)
- Anonymous API access (configurable per route)

### 5.2 Data Protection
- **Soft deletes**: Logical deletion with `isDeleted` flag (audit compliance)
- **User attribution**: All create/update operations tracked to user
- **Audit trails**: PromptRuns table maintains execution history
- **Token usage tracking**: Billing attribution per user/prompt

### 5.3 API Key Management
- Environment variable-based configuration
- No hardcoded credentials
- Supports graceful degradation if keys unavailable

### 5.4 CORS Policy
- Current: Open (`*` origin) for development
- Production recommendation: Restrict to known domains

---

## 6. USER EXPERIENCE FEATURES

### 6.1 Accessibility
- Skip-to-main-content link for screen readers
- Keyboard navigation shortcuts:
  - `Ctrl+H`: Home
  - `Ctrl+Enter`: Compare (KQL Diff)
  - `Escape`: Exit/close menus
- Dark/Light mode toggle (entire app)
- Mobile-responsive design

### 6.2 Performance Optimizations
- Lazy loading of route components (React.lazy)
- Parallel API queries (threat intel lookup)
- In-memory caching (Email Posture, 5-minute TTL)
- localStorage for preferences (KQL Diff settings, SOC Handoff data)
- Monaco Editor code splitting

### 6.3 User Guidance
- Splash screens with "No blind Copypasta here!" reminder (3.5s)
  - IR Playbook Generator
  - Prompt Gallery
- Loading states with spinners
- Error messages with actionable guidance
- Expandable/collapsible sections (Email Posture)
- Auto-expand sections with issues

---

## 7. OPERATIONAL METRICS & INSIGHTS

### 7.1 Tracked Metrics (PromptRuns Table)
- **Prompt execution count** per user
- **Token usage** (prompt, completion, total)
- **Execution timestamps** (usage patterns)
- **Context summary** (first 500 chars)
- **Model settings** (temperature, maxTokens)
- **Output length** (first 10K chars stored)

### 7.2 Performance Indicators
- API response times (parallel queries)
- Cache hit rates (Email Posture)
- Error rates per endpoint
- User attribution for billing

---

## 8. DEPLOYMENT & INFRASTRUCTURE

### 8.1 Development Workflow
```bash
# Frontend (localhost:3000)
npm install && npm start

# Backend (localhost:7071)
cd api && npm install && npm start
```

**Dev proxy:** `/api/*` routes proxied to localhost:7071

### 8.2 Production Deployment
- **Platform:** Azure Static Web Apps
- **CI/CD:** GitHub Actions (implied)
- **Build command:** `npm run build`
- **Output:** `/build` directory
- **API:** Azure Functions automatically deployed with SWA

### 8.3 Environment Variables Required

**Frontend:** (None, uses backend proxy)

**Backend:** (local.settings.json / Azure App Settings)
```
FUNCTIONS_WORKER_RUNTIME=node
AZURE_STORAGE_ACCOUNT_NAME=...
AZURE_STORAGE_ACCOUNT_KEY=...
PROMPTS_TABLE_NAME=Prompts
PROMPT_RUNS_TABLE_NAME=PromptRuns
AZURE_OPENAI_ENDPOINT=...
AZURE_OPENAI_API_KEY=...
AZURE_OPENAI_DEPLOYMENT=gpt-4
COSMOS_CONNECTION=AccountEndpoint=...;AccountKey=...
CLAUDE_API_KEY=...
CLAUDE_API_ENDPOINT=https://...services.ai.azure.com/anthropic/v1/messages
CLAUDE_MODEL=claude-sonnet-4-20250514
VIRUSTOTAL_API_KEY=...
ABUSEIPDB_API_KEY=...
GREYNOISE_API_KEY=...
SHODAN_API_KEY=...
ALIENVAULT_OTX_API_KEY=...
URLSCAN_API_KEY=...
MXTOOLBOX_API_KEY=...
HYBRID_ANALYSIS_API_KEY=...
```

---

## 9. FUTURE ENHANCEMENTS (Potential Roadmap)

### 9.1 Feature Expansion
- **Advanced Prompt Admin**: Versioning, rollback, approval workflows
- **Collaborative Features**: Real-time shared KQL Diff sessions
- **Dashboard**: SOC metrics, incident trends, token usage analytics
- **SOAR Integration**: Automated playbook execution (PagerDuty, ServiceNow)
- **Case Management**: Link prompts/playbooks to incident tickets

### 9.2 Technical Improvements
- **GraphQL API**: Replace REST for more efficient queries
- **WebSocket**: Real-time updates for collaborative features
- **Advanced Caching**: Redis for distributed cache
- **Rate Limiting**: Protect against API abuse
- **Multi-tenant**: Partition data by organization

### 9.3 Intelligence Enhancements
- **Custom threat feeds**: User-uploaded IOC lists
- **Threat hunting queries**: Library of KQL templates
- **IOC enrichment pipeline**: Background batch processing
- **Historical trending**: Track IOC reputation over time

---

## 10. BUSINESS VALUE PROPOSITION

### 10.1 Time Savings
- **Threat Intel Lookup**: 5 minutes → 10 seconds (IOC research)
- **IR Playbook Generation**: 2 hours → 30 seconds (playbook creation)
- **KQL Diff Analysis**: 30 minutes → 2 minutes (peer review)
- **Email Posture Check**: 15 minutes → 1 minute (security assessment)

### 10.2 Quality Improvements
- **Standardized playbooks** aligned with NIST/MITRE
- **Reduced false positives** via AI-powered KQL analysis
- **Audit compliance** with full execution history
- **Knowledge sharing** via centralized prompt library

### 10.3 Cost Efficiency
- **Serverless architecture**: Pay only for actual usage
- **Consolidated tooling**: Single platform vs multiple subscriptions
- **AI automation**: Reduced manual analysis time
- **Scalability**: Auto-scaling handles load spikes

### 10.4 Team Enablement
- **Onboarding**: New analysts access institutional knowledge via prompts
- **Consistency**: Standardized workflows across shifts
- **Collaboration**: Shareable KQL diffs, prompt templates
- **Documentation**: Self-documenting playbooks and prompts

---

## 11. TECHNICAL CHALLENGES & SOLUTIONS

### 11.1 Challenge: Node.js Crypto Module Issues
**Problem:** Azure Functions SDK has crypto module compatibility issues

**Solution:**
- Migrated to REST API calls instead of SDKs
- Direct Azure OpenAI REST API (2024-08-01-preview)
- SAS token-based Azure Storage authentication
- Comprehensive try-catch error handling

### 11.2 Challenge: Performance with Multiple Threat Intel Sources
**Problem:** Serial API calls would be slow

**Solution:**
- Parallel async queries using `Promise.all()`
- Graceful degradation if sources timeout
- ARIN RDAP as always-available fallback

### 11.3 Challenge: AI Cost Management
**Problem:** Uncontrolled AI usage could lead to high costs

**Solution:**
- Token usage tracking per execution
- User attribution for billing
- Configurable temperature/maxTokens limits
- PromptRuns audit trail for accountability

---

## 12. COMPETITIVE DIFFERENTIATORS

| Feature | ThreatDefender Suite | Typical MSSP Tooling |
|---------|----------------------|---------------------|
| **Multi-source TI** | 8+ sources, 1 query | Manual per-source lookup |
| **AI-powered KQL analysis** | Automated risk assessment | Manual peer review |
| **IR playbook automation** | 30 seconds | 2+ hours |
| **Prompt automation** | Codified workflows | Ad-hoc scripts |
| **Unified platform** | Single interface | Disconnected tools |
| **Cost model** | Pay-per-use serverless | Fixed licensing |
| **Customization** | Open prompt library | Vendor-locked templates |
| **Audit compliance** | Full execution history | Minimal tracking |

---

## 13. SYSTEM REQUIREMENTS

### 13.1 Client (End User)
- **Browser:** Modern browser (Chrome, Edge, Firefox, Safari)
- **JavaScript:** Enabled
- **Internet:** Stable connection
- **Resolution:** Responsive (mobile to desktop)

### 13.2 Infrastructure
- **Azure subscription** (Static Web Apps, Functions, Storage, OpenAI)
- **Domain:** Optional custom domain
- **SSL/TLS:** Provided by Azure Static Web Apps
- **Monitoring:** Application Insights (included)

### 13.3 API Keys (Optional but Recommended)
- Threat intel sources (8 providers)
- Azure OpenAI (required)
- MXToolbox (optional enrichment)

---

## 14. SUPPORT & MAINTENANCE

### 14.1 Monitoring
- **Application Insights:** Request tracing, error tracking
- **Health checks:** `/api/HealthCheck` endpoint
- **Diagnostics:** Dedicated diagnostic endpoints for troubleshooting

### 14.2 Updates & Patches
- **Dependencies:** Managed via npm (frontend + backend)
- **Security patches:** Automated Dependabot alerts
- **Feature releases:** GitHub-based version control

### 14.3 Backup & Recovery
- **Azure Table Storage:** Geo-redundant by default
- **Soft deletes:** Data recovery possible (30-day window configurable)
- **Configuration:** Infrastructure as code (ARM templates possible)

---

## 15. CONCLUSION

The ThreatDefender Operations Suite represents a modern, AI-powered approach to security operations. By consolidating threat intelligence, incident response, and workflow automation into a unified, serverless platform, it enables MSSP teams to respond faster, more consistently, and with greater insight than traditional tooling allows.

**Key Achievements:**
✅ **7 integrated tools** replacing disconnected solutions
✅ **8+ threat intelligence sources** in single query
✅ **AI-powered analysis** reducing manual effort by 80%+
✅ **Serverless architecture** for cost efficiency and scalability
✅ **Full audit compliance** with execution tracking
✅ **Team enablement** through knowledge codification
✅ **AI Triage Chat** for interactive incident follow-up from Teams

**Built for:** eGroup Enabling Technologies ThreatDefender MSSP Team
**Architecture:** Modern, cloud-native, AI-enhanced
**Status:** Production-ready with continuous enhancement roadmap

---

## APPENDIX A: Technology Dependency Matrix

| Layer | Component | Version | Purpose |
|-------|-----------|---------|---------|
| **Frontend** | React | 19.2.0 | UI framework |
| | React Router | 7.9.5 | Navigation |
| | Tailwind CSS | Latest | Styling |
| | Framer Motion | 12.23.24 | Animations |
| | Monaco Editor | 4.7.0 | Code editing |
| | React Markdown | 10.1.0 | Markdown rendering |
| **Backend** | Node.js | 18+ | Runtime |
| | Azure Functions | v4 | Serverless compute |
| | Axios | 1.6.0 | HTTP client |
| | AJV | 8.17.1 | JSON validation |
| **Storage** | Azure Tables | SDK 13.2.2 | NoSQL storage |
| | Azure Blobs | SDK 12.29.1 | Object storage |
| | Azure Cosmos DB | REST API | Chat session storage |
| **AI** | Azure OpenAI | API 2024-08-01 | GPT-4 inference |
| | Claude AI | Anthropic API | Triage chat inference |
| **Infra** | Azure SWA | Platform | Hosting + CI/CD |
| | Azure Logic Apps | Platform | Sentinel integration |

---

## APPENDIX B: API Request/Response Examples

### B.1 Threat Intel Lookup Request
```json
POST /api/ThreatIntelLookup
{
  "indicator": "8.8.8.8"
}
```

### B.2 IR Playbook Request
```json
POST /api/IRPlaybook
{
  "category": "Credential Theft",
  "severity": "High",
  "incidentDetails": "Multiple failed login attempts detected",
  "environment": {
    "sentinel": true,
    "mde": true,
    "mdi": true,
    "mdo": false
  },
  "temperature": 0.25
}
```

### B.3 Prompt Execution Request
```json
POST /api/prompts/{id}/run
{
  "variables": {
    "indicator": "malicious.com",
    "severity": "High"
  },
  "context": "User reported phishing email from malicious.com"
}
```

---

## APPENDIX C: Related Documentation

| Document | Purpose |
|----------|---------|
| [README.md](README.md) | Project overview and quick start |
| [FEATURES_OVERVIEW.md](FEATURES_OVERVIEW.md) | Quick feature reference guide |
| [SECURITY_ANALYST_GUIDE.md](SECURITY_ANALYST_GUIDE.md) | End-user guide for SOC analysts |
| [DEV_SETUP.md](DEV_SETUP.md) | Local development environment setup |
| [API_REFERENCE.md](API_REFERENCE.md) | Complete API endpoint documentation |
| [AZURE_CONFIG.md](AZURE_CONFIG.md) | Environment variables reference |
| [PROMPT_GALLERY_SETUP.md](PROMPT_GALLERY_SETUP.md) | Prompt Gallery configuration |
| [AI_TRIAGE_CHAT_SETUP.md](AI_TRIAGE_CHAT_SETUP.md) | AI Triage Chat setup |
| [THREAT_INTEL_SETUP.md](THREAT_INTEL_SETUP.md) | Threat intelligence API configuration |
| [TROUBLESHOOTING_PROMPTS.md](TROUBLESHOOTING_PROMPTS.md) | Common issues and solutions |

---

**End of Architecture Document**

*This document provides comprehensive technical context for generating executive-level overviews, business cases, and stakeholder presentations.*
