# ThreatDefender Operations Suite - API Reference

Complete API documentation for all backend endpoints.

---

## Base URLs

| Environment | URL |
|-------------|-----|
| Local Development | `http://localhost:7071/api` |
| Production | `https://your-app.azurestaticapps.net/api` |

---

## API Overview

| Endpoint | Method | Purpose | Auth |
|----------|--------|---------|------|
| `/prompts` | GET | List all prompts | Optional |
| `/prompts` | POST | Create prompt | Optional |
| `/prompts/:id` | GET | Get prompt details | Optional |
| `/prompts/:id` | PUT | Update prompt | Optional |
| `/prompts/:id` | DELETE | Soft delete prompt | Optional |
| `/prompts/:id/run` | POST | Execute prompt | Optional |
| `/ThreatIntelLookup` | POST | Query threat intel | Anonymous |
| `/HybridAnalysisLookup` | POST | Query Hybrid Analysis | Anonymous |
| `/kqlanalyzer` | POST | Analyze KQL diff | Anonymous |
| `/AlertTriage` | POST | Generate IR playbook | Anonymous |
| `/EmailPosture` | POST | Check email security | Anonymous |
| `/EmailHeaderAnalyzer` | POST | Analyze email headers | Anonymous |
| `/TriageSession` | GET | Get triage session | Anonymous |
| `/TriageSession` | POST | Create/update session | Anonymous |
| `/HealthCheck` | GET | System health | Anonymous |

---

## Authentication

All endpoints support optional Azure Active Directory authentication via the `x-ms-client-principal` header. When authenticated, user information is used for audit logging.

**Header Format:**
```
x-ms-client-principal: <base64-encoded-principal>
```

---

## Prompts API

### List Prompts

```http
GET /api/prompts
```

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `category` | string | Filter by category |
| `tag` | string | Filter by tag |
| `search` | string | Full-text search |

**Response:**
```json
{
  "prompts": [
    {
      "id": "1704067200000-abc123",
      "title": "Phishing Analysis",
      "description": "Analyze suspected phishing email",
      "category": "Triage",
      "tags": ["phishing", "email", "analysis"],
      "collection": "Email Security",
      "createdAt": "2026-01-01T00:00:00.000Z",
      "createdBy": "user@example.com"
    }
  ],
  "count": 1
}
```

---

### Create Prompt

```http
POST /api/prompts
Content-Type: application/json
```

**Request Body:**
```json
{
  "title": "Phishing Analysis",
  "description": "Analyze suspected phishing email for indicators",
  "category": "Triage",
  "tags": ["phishing", "email"],
  "collection": "Email Security",
  "systemGuidance": "You are a security analyst...",
  "userInstructions": "Analyze this email:\n\n{{email_content}}",
  "variables": [
    {
      "name": "email_content",
      "type": "text",
      "required": true,
      "description": "Raw email content to analyze"
    },
    {
      "name": "severity",
      "type": "enum",
      "required": false,
      "default": "Medium",
      "options": ["Low", "Medium", "High", "Critical"]
    }
  ],
  "modelSettings": {
    "temperature": 0.3,
    "maxTokens": 2000
  }
}
```

**Response:**
```json
{
  "id": "1704067200000-abc123",
  "message": "Prompt created successfully"
}
```

---

### Get Prompt

```http
GET /api/prompts/:id
```

**Response:**
```json
{
  "id": "1704067200000-abc123",
  "title": "Phishing Analysis",
  "description": "Analyze suspected phishing email",
  "category": "Triage",
  "tags": ["phishing", "email"],
  "collection": "Email Security",
  "systemGuidance": "You are a security analyst...",
  "userInstructions": "Analyze this email:\n\n{{email_content}}",
  "variables": [...],
  "modelSettings": {
    "temperature": 0.3,
    "maxTokens": 2000
  },
  "createdAt": "2026-01-01T00:00:00.000Z",
  "createdBy": "user@example.com",
  "updatedAt": "2026-01-02T00:00:00.000Z",
  "updatedBy": "user@example.com"
}
```

---

### Update Prompt

```http
PUT /api/prompts/:id
Content-Type: application/json
```

**Request Body:** Same as Create Prompt

**Response:**
```json
{
  "message": "Prompt updated successfully"
}
```

---

### Delete Prompt

```http
DELETE /api/prompts/:id
```

Performs soft delete (sets `isDeleted: true`).

**Response:**
```json
{
  "message": "Prompt deleted successfully"
}
```

---

### Execute Prompt

```http
POST /api/prompts/:id/run
Content-Type: application/json
```

**Request Body:**
```json
{
  "variables": {
    "email_content": "From: suspicious@example.com\nSubject: Urgent...",
    "severity": "High"
  },
  "context": "User reported this email as suspicious"
}
```

**Response:**
```json
{
  "output": "## Analysis Results\n\nThis email shows multiple phishing indicators...",
  "usage": {
    "promptTokens": 450,
    "completionTokens": 320,
    "totalTokens": 770
  },
  "runId": "run-1704067200000-xyz789"
}
```

---

## Threat Intelligence API

### Threat Intel Lookup

```http
POST /api/ThreatIntelLookup
Content-Type: application/json
```

**Request Body:**
```json
{
  "indicator": "8.8.8.8"
}
```

**Response:**
```json
{
  "indicator": "8.8.8.8",
  "type": "ipv4",
  "results": {
    "virustotal": {
      "status": "success",
      "data": {
        "reputation": 0,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 85,
        "country": "US",
        "asn": 15169,
        "asOwner": "GOOGLE"
      }
    },
    "abuseipdb": {
      "status": "success",
      "data": {
        "abuseConfidenceScore": 0,
        "totalReports": 0,
        "countryCode": "US",
        "isp": "Google LLC"
      }
    },
    "greynoise": {
      "status": "success",
      "data": {
        "seen": true,
        "classification": "benign",
        "name": "Google Public DNS"
      }
    },
    "shodan": {
      "status": "success",
      "data": {
        "ports": [53, 443],
        "hostnames": ["dns.google"],
        "org": "Google LLC"
      }
    },
    "alienvault": {
      "status": "success",
      "data": {
        "pulseCount": 0,
        "reputation": 0
      }
    },
    "arin": {
      "status": "success",
      "data": {
        "name": "GOOGLE",
        "handle": "NET-8-8-8-0-2",
        "startAddress": "8.8.8.0",
        "endAddress": "8.8.8.255"
      }
    }
  },
  "queriedAt": "2026-01-16T12:00:00.000Z"
}
```

---

### Hybrid Analysis Lookup

```http
POST /api/HybridAnalysisLookup
Content-Type: application/json
```

**Request Body:**
```json
{
  "indicator": "44d88612fea8a8f36de82e1278abb02f"
}
```

**Response:**
```json
{
  "indicator": "44d88612fea8a8f36de82e1278abb02f",
  "type": "md5",
  "results": {
    "verdict": "malicious",
    "threatScore": 100,
    "families": ["Emotet"],
    "mitreTechniques": [
      {"id": "T1059.001", "name": "PowerShell"}
    ],
    "networkIndicators": {
      "domains": ["malicious.com"],
      "hosts": ["192.168.1.100"]
    },
    "processTree": [...],
    "extractedFiles": [...],
    "analysisDate": "2026-01-15T00:00:00.000Z",
    "environment": "Windows 10 64-bit",
    "reportUrl": "https://hybrid-analysis.com/sample/..."
  }
}
```

---

## KQL Analyzer API

### Analyze KQL Diff

```http
POST /api/kqlanalyzer
Content-Type: application/json
```

**Request Body:**
```json
{
  "originalQuery": "SecurityEvent\n| where EventID == 4625\n| project TimeGenerated, Account",
  "modifiedQuery": "SecurityEvent\n| where EventID == 4625\n| where Account !contains \"$\"\n| project TimeGenerated, Account, IPAddress"
}
```

**Response:**
```json
{
  "analysis": {
    "overview": "The modified query adds filtering for non-machine accounts and includes IP address in output.",
    "securityImpact": "Positive - Reduces noise from expected machine account failures while adding attribution capability.",
    "performanceImpact": "Minimal - Additional where clause adds negligible overhead.",
    "falsePositiveRisk": "Low - Filtering machine accounts typically reduces false positives.",
    "recommendations": [
      "Consider adding time window filter for performance",
      "Add TargetAccount field for complete audit trail"
    ]
  },
  "tokensUsed": {
    "prompt": 250,
    "completion": 180,
    "total": 430
  }
}
```

---

## Alert Triage API

### Generate IR Playbook

```http
POST /api/AlertTriage
Content-Type: application/json
```

**Request Body:**
```json
{
  "category": "Phishing",
  "severity": "High",
  "incidentDetails": "User reported suspicious email with attachment. User may have clicked link.",
  "environment": {
    "sentinel": true,
    "mde": true,
    "mdi": false,
    "mdo": true
  },
  "temperature": 0.3
}
```

**Response:**
```json
{
  "playbook": {
    "executiveSummary": "High severity phishing incident requiring immediate investigation...",
    "incidentClassification": {
      "category": "Phishing",
      "severity": "High",
      "mitreTactic": "Initial Access",
      "mitreTechnique": "T1566.001"
    },
    "initialTriage": [
      "Isolate affected user account",
      "Preserve email evidence",
      "Check for credential compromise"
    ],
    "investigation": [
      "Review email headers for sender analysis",
      "Check if link was clicked using MDO telemetry",
      "Search for similar emails across organization"
    ],
    "kqlQueries": {
      "emailTrace": "EmailEvents\n| where RecipientEmailAddress == 'user@company.com'\n| where TimeGenerated > ago(24h)",
      "clickEvents": "UrlClickEvents\n| where AccountUpn == 'user@company.com'\n| where TimeGenerated > ago(24h)"
    },
    "containment": [
      "Block sender domain",
      "Purge email from all mailboxes",
      "Reset user credentials if compromise suspected"
    ],
    "eradication": [...],
    "recovery": [...],
    "postIncident": [...]
  },
  "extractedIOCs": [
    {"type": "domain", "value": "malicious.com"},
    {"type": "url", "value": "https://malicious.com/payload"}
  ],
  "tokensUsed": {
    "prompt": 800,
    "completion": 1200,
    "total": 2000
  }
}
```

---

## Email Security APIs

### Email Posture Check

```http
POST /api/EmailPosture
Content-Type: application/json
```

**Request Body:**
```json
{
  "domain": "example.com",
  "dkimSelectors": ["selector1", "google"]
}
```

**Response:**
```json
{
  "domain": "example.com",
  "protocols": {
    "spf": {
      "status": "pass",
      "record": "v=spf1 include:_spf.google.com ~all",
      "details": "Valid SPF record found"
    },
    "dmarc": {
      "status": "pass",
      "record": "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
      "policy": "reject",
      "details": "Strong DMARC policy configured"
    },
    "dkim": {
      "status": "pass",
      "selectors": {
        "google": {
          "found": true,
          "keyLength": 2048
        }
      }
    },
    "mx": {
      "status": "pass",
      "records": [
        {"preference": 10, "host": "mail.example.com"}
      ]
    },
    "mtaSts": {
      "status": "pass",
      "mode": "enforce"
    },
    "bimi": {
      "status": "not_configured",
      "details": "No BIMI record found"
    }
  },
  "mxtoolbox": {
    "emailHealthScore": 85,
    "issues": []
  },
  "checkedAt": "2026-01-16T12:00:00.000Z",
  "cached": false
}
```

---

### Email Header Analyzer

```http
POST /api/EmailHeaderAnalyzer
Content-Type: application/json
```

**Request Body:**
```json
{
  "headers": "Received: from mail.example.com (192.168.1.1)...\nFrom: sender@example.com\nTo: recipient@company.com\nSubject: Test Email\n..."
}
```

**Response:**
```json
{
  "parsed": {
    "from": "sender@example.com",
    "to": "recipient@company.com",
    "subject": "Test Email",
    "date": "2026-01-16T10:00:00.000Z",
    "messageId": "<abc123@example.com>"
  },
  "authentication": {
    "spf": {
      "result": "pass",
      "domain": "example.com"
    },
    "dkim": {
      "result": "pass",
      "domain": "example.com",
      "selector": "google"
    },
    "dmarc": {
      "result": "pass",
      "policy": "reject"
    }
  },
  "routing": [
    {
      "hop": 1,
      "from": "mail.example.com",
      "by": "mx.company.com",
      "timestamp": "2026-01-16T10:00:05.000Z",
      "delay": "0s"
    },
    {
      "hop": 2,
      "from": "mx.company.com",
      "by": "internal.company.com",
      "timestamp": "2026-01-16T10:00:06.000Z",
      "delay": "1s"
    }
  ],
  "suspiciousIndicators": [],
  "verdict": "clean"
}
```

---

## AI Triage Chat API

### Get Triage Session

```http
GET /api/TriageSession?sessionId=abc123
```

**Response:**
```json
{
  "id": "abc123",
  "incidentId": "INC-001",
  "incidentTitle": "Suspicious login from unusual location",
  "incidentSeverity": "High",
  "tenantName": "Contoso",
  "initialAnalysis": {
    "summary": "User account accessed from IP in different country...",
    "severity": "High",
    "confidence": 0.85,
    "mitreTechniques": ["T1078"],
    "recommendedActions": [
      "Verify with user if travel is legitimate",
      "Check for concurrent sessions",
      "Review recent sign-in activity"
    ]
  },
  "conversationHistory": [
    {
      "role": "assistant",
      "content": "I've analyzed the incident..."
    },
    {
      "role": "user",
      "content": "Can you provide KQL to check other sign-ins?"
    },
    {
      "role": "assistant",
      "content": "Here's a KQL query:\n```kql\nSigninLogs\n| where UserPrincipalName == 'user@contoso.com'..."
    }
  ],
  "messageCount": 3,
  "createdAt": "2026-01-16T10:00:00.000Z",
  "lastUpdated": "2026-01-16T10:05:00.000Z"
}
```

---

### Create/Send Message to Session

```http
POST /api/TriageSession
Content-Type: application/json
```

**Create New Session:**
```json
{
  "action": "create",
  "incidentId": "INC-001",
  "incidentTitle": "Suspicious login from unusual location",
  "incidentSeverity": "High",
  "tenantName": "Contoso",
  "incidentContext": {
    "userPrincipalName": "user@contoso.com",
    "ipAddress": "203.0.113.50",
    "location": "Unknown Country"
  },
  "systemPrompt": "You are a security analyst assistant..."
}
```

**Send Message to Existing Session:**
```json
{
  "action": "message",
  "sessionId": "abc123",
  "message": "What KQL query can I use to check for lateral movement?"
}
```

**Response:**
```json
{
  "sessionId": "abc123",
  "response": "Here's a KQL query to detect potential lateral movement:\n\n```kql\nSecurityEvent\n| where EventID == 4624\n| where LogonType == 3\n...",
  "messageCount": 4
}
```

---

## Health Check API

### System Health

```http
GET /api/HealthCheck
```

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2026-01-16T12:00:00.000Z",
  "services": {
    "azureOpenAI": "configured",
    "azureStorage": "configured",
    "cosmosDB": "configured",
    "claudeAI": "configured"
  },
  "version": "1.0.0"
}
```

---

## Error Responses

All endpoints return consistent error format:

```json
{
  "error": "Error message description",
  "code": "ERROR_CODE",
  "details": "Additional context if available"
}
```

**Common Error Codes:**

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `INVALID_REQUEST` | 400 | Malformed request body |
| `NOT_FOUND` | 404 | Resource not found |
| `CREDENTIALS_NOT_CONFIGURED` | 500 | Missing API keys |
| `EXTERNAL_API_ERROR` | 502 | Third-party API failure |
| `RATE_LIMITED` | 429 | Too many requests |

---

## Rate Limits

| Endpoint | Limit | Window |
|----------|-------|--------|
| Threat Intel APIs | Varies by source | Per-source limits apply |
| Azure OpenAI | Per deployment | Check Azure portal |
| Prompt Execution | No internal limit | OpenAI limits apply |

---

## CORS

All endpoints support CORS with:
- `Access-Control-Allow-Origin: *`
- `Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS`
- `Access-Control-Allow-Headers: Content-Type, x-ms-client-principal`

---

## Related Documentation

- [AZURE_CONFIG.md](AZURE_CONFIG.md) - Environment variables
- [ARCHITECTURE_SUMMARY.md](ARCHITECTURE_SUMMARY.md) - Technical architecture
- [DEV_SETUP.md](DEV_SETUP.md) - Local development
