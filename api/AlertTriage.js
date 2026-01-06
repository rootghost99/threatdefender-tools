// /api/AlertTriage.js
// Azure Functions (v4, Node 18+) - Alert Triage Assistant API
// Analyzes raw alerts, classifies severity, maps MITRE ATT&CK tactics, and provides investigation steps

const { app } = require('@azure/functions');
const Ajv = require('ajv');

// ----- JSON Schema the model must return -----
const TRIAGE_SCHEMA = {
  type: 'object',
  properties: {
    severity: {
      type: 'string',
      enum: ['Informational', 'Low', 'Medium', 'High', 'Critical']
    },
    category: {
      type: 'string',
      enum: [
        'Phishing', 'Credential Theft', 'Malware', 'Ransomware',
        'Data Exfiltration', 'Lateral Movement', 'Command & Control',
        'Reconnaissance', 'Insider Threat', 'Business Email Compromise',
        'Supply Chain Attack', 'Denial of Service', 'Web Attack',
        'Policy Violation', 'Suspicious Activity', 'Unknown'
      ]
    },
    confidence: { type: 'number', minimum: 0, maximum: 100 },
    summary: { type: 'string' },
    mitreTactics: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          name: { type: 'string' },
          techniques: {
            type: 'array',
            items: { type: 'string' }
          }
        },
        required: ['id', 'name']
      }
    },
    investigationSteps: {
      type: 'array',
      items: { type: 'string' }
    },
    kqlQueries: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          purpose: { type: 'string' },
          query: { type: 'string' }
        },
        required: ['purpose', 'query']
      }
    },
    containmentRecommendations: {
      type: 'array',
      items: { type: 'string' }
    },
    iocRiskAssessment: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          indicator: { type: 'string' },
          type: { type: 'string' },
          risk: { type: 'string', enum: ['Low', 'Medium', 'High', 'Critical'] },
          reason: { type: 'string' }
        },
        required: ['indicator', 'risk', 'reason']
      }
    },
    falsePositiveIndicators: {
      type: 'array',
      items: { type: 'string' }
    }
  },
  required: ['severity', 'category', 'confidence', 'summary', 'investigationSteps']
};

const ajv = new Ajv({ allErrors: true, strict: false });
const validateTriage = ajv.compile(TRIAGE_SCHEMA);

// ----- LLM call helper (same pattern as IRPlaybook.js) -----
async function callLLM(messages, { useAzure, temperature = 0.2 }) {
  const maxTokens = 3000;

  if (useAzure) {
    const endpoint = String(process.env.AZURE_OPENAI_ENDPOINT || '').trim().replace(/\/+$/, '');
    const deployment = String(process.env.AZURE_OPENAI_DEPLOYMENT || '').trim();
    const apiVersion = '2024-08-01-preview';
    if (!endpoint || !deployment || !process.env.AZURE_OPENAI_API_KEY) {
      throw new Error('Azure OpenAI settings missing. Check endpoint, deployment, and key.');
    }
    const url = `${endpoint}/openai/deployments/${encodeURIComponent(deployment)}/chat/completions?api-version=${apiVersion}`;
    const resp = await fetch(url, {
      method: 'POST',
      headers: { 'api-key': process.env.AZURE_OPENAI_API_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify({ temperature, max_tokens: maxTokens, messages })
    });
    const text = await resp.text();
    if (!resp.ok) throw new Error(`LLM error ${resp.status}: ${text}`);
    const data = JSON.parse(text);
    return data.choices?.[0]?.message?.content ?? '';
  }

  // OpenAI fallback
  const model = process.env.OPENAI_MODEL || 'gpt-4o-mini';
  if (!process.env.OPENAI_API_KEY) throw new Error('OPENAI_API_KEY missing.');
  const resp = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: { Authorization: `Bearer ${process.env.OPENAI_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ model, temperature, max_tokens: maxTokens, messages })
  });
  const text = await resp.text();
  if (!resp.ok) throw new Error(`LLM error ${resp.status}: ${text}`);
  const data = JSON.parse(text);
  return data.choices?.[0]?.message?.content ?? '';
}

// ----- HTTP function -----
app.http('AlertTriage', {
  methods: ['POST', 'OPTIONS'],
  authLevel: 'anonymous',
  handler: async (request, context) => {
    context.log('Alert Triage function triggered');

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return {
        status: 200,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type'
        }
      };
    }

    try {
      const body = await request.json().catch(() => ({}));
      const {
        alertContent = '',
        extractedIOCs = {},
        enrichmentSummary = {},
        temperature: clientTemp
      } = body || {};

      if (!alertContent && Object.values(extractedIOCs).every(arr => !arr || arr.length === 0)) {
        return {
          status: 400,
          headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
          jsonBody: { error: 'Missing alertContent or extractedIOCs' }
        };
      }

      // Clamp and default temperature
      const temperature = Math.min(1, Math.max(0, Number.isFinite(clientTemp) ? Number(clientTemp) : 0.2));

      const systemPrompt = `You are a senior SOC analyst performing alert triage for a Microsoft security environment (Sentinel, Defender for Endpoint, Defender for Office 365, Defender for Identity).

CONTEXT:
- You are analyzing a raw security alert with extracted IOCs and optional threat intelligence enrichment data
- Sources may include VirusTotal, AbuseIPDB, GreyNoise, Shodan, AlienVault OTX, and Hybrid Analysis
- Your classification will be used to prioritize analyst response and generate IR playbooks

TASK:
1. Analyze the raw alert content for context, affected users/hosts, and timeline
2. Review the extracted IOCs and their enrichment data for threat indicators
3. Classify the alert with severity, category, and confidence score (0-100)
4. Map identified techniques to MITRE ATT&CK framework (use official tactic IDs like TA0001-TA0043)
5. Provide 5-7 specific, actionable investigation steps
6. Generate 2-3 relevant KQL queries for Microsoft Sentinel/Defender
7. Recommend immediate containment actions if severity is High or Critical
8. Assess risk level for each IOC based on enrichment data
9. Note any indicators that suggest this could be a false positive

SEVERITY GUIDELINES:
- Critical: Active breach, ransomware deployment, data exfiltration in progress, confirmed APT activity
- High: Confirmed malicious activity, compromised credentials, active C2 communication, lateral movement detected
- Medium: Suspicious activity requiring investigation, potential policy violations, unconfirmed malicious indicators
- Low: Low-confidence alerts, reconnaissance activity, known scanner IPs, minor policy violations
- Informational: Confirmed false positive indicators, benign scan activity, test/internal traffic

OUTPUT FORMAT: Valid JSON only matching the provided schema. No markdown formatting, no code blocks, no extra text.`;

      const userContent = {
        alertContent,
        extractedIOCs,
        enrichmentSummary,
        schema: TRIAGE_SCHEMA
      };

      const useAzure = !!process.env.AZURE_OPENAI_ENDPOINT;
      context.log('Calling LLM for triage analysis, provider:', useAzure ? 'Azure' : 'OpenAI');

      const content = await callLLM(
        [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: JSON.stringify(userContent) }
        ],
        { useAzure, temperature }
      );

      // Parse and validate
      let triage;
      try {
        // Clean potential markdown code blocks
        let cleanContent = content.trim();
        if (cleanContent.startsWith('```json')) {
          cleanContent = cleanContent.slice(7);
        } else if (cleanContent.startsWith('```')) {
          cleanContent = cleanContent.slice(3);
        }
        if (cleanContent.endsWith('```')) {
          cleanContent = cleanContent.slice(0, -3);
        }
        triage = JSON.parse(cleanContent.trim());
      } catch (parseErr) {
        context.log.error('JSON parse error:', parseErr.message);
        context.log.error('Raw content:', content.substring(0, 500));
        return {
          status: 502,
          headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' },
          jsonBody: { error: 'Model did not return valid JSON.', raw: content.substring(0, 200) }
        };
      }

      const valid = validateTriage(triage);
      if (!valid) {
        context.log.error('Schema validation failed:', validateTriage.errors);
        return {
          status: 422,
          headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' },
          jsonBody: {
            error: 'Response failed schema validation.',
            details: validateTriage.errors
          }
        };
      }

      context.log('Triage analysis complete, severity:', triage.severity);

      return {
        status: 200,
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Access-Control-Allow-Origin': '*',
          'Cache-Control': 'no-store'
        },
        jsonBody: {
          triage,
          meta: {
            provider: useAzure ? 'azure' : 'openai',
            temperature,
            iocCount: Object.values(extractedIOCs).flat().length,
            hasEnrichment: Object.keys(enrichmentSummary).length > 0
          }
        }
      };
    } catch (err) {
      context.log.error('Alert Triage error:', err.message);
      return {
        status: 500,
        headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' },
        jsonBody: { error: String(err.message || err) }
      };
    }
  }
});
