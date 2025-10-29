// /api/IRPlaybook.js
// Azure Functions (v4, Node 18+) — streams an IR playbook section-by-section via NDJSON.
//
// Notes:
// - Uses global fetch (no node-fetch).
// - Azure OpenAI is used when AZURE_OPENAI_ENDPOINT is set; else falls back to OpenAI.
// - API version defaults to 2024-08-01-preview if AZURE_OPENAI_API_VERSION is missing/incorrect.
// - Emits NDJSON events: {type:"meta"| "section"| "error"| "done", ...}

const { app } = require('@azure/functions');
const { PassThrough } = require('stream');

/* ------------------------- LLM call wrapper ------------------------- */
async function completeText({ system, user, modelHints = {} }) {
  const useAzure = !!process.env.AZURE_OPENAI_ENDPOINT;
  const temperature = modelHints.temperature ?? 0.2;
  const maxTokens = modelHints.maxTokens ?? 700;

  if (useAzure) {
    // AZURE settings
    const endpoint = String(process.env.AZURE_OPENAI_ENDPOINT || '').replace(/\/+$/, '');
    const deployment = String(process.env.AZURE_OPENAI_DEPLOYMENT || '').trim();
    // IMPORTANT: Use a valid REST API version, not the model version shown in Studio
    const apiVersion = String(process.env.AZURE_OPENAI_API_VERSION || '2024-08-01-preview').trim();

    if (!endpoint || !deployment || !process.env.AZURE_OPENAI_API_KEY) {
      throw new Error('Azure OpenAI is selected but endpoint, deployment, or API key is missing.');
    }

    const url =
      `${endpoint}/openai/deployments/${encodeURIComponent(deployment)}` +
      `/chat/completions?api-version=${encodeURIComponent(apiVersion)}`;

    const resp = await fetch(url, {
      method: 'POST',
      headers: {
        'api-key': process.env.AZURE_OPENAI_API_KEY,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        temperature,
        max_tokens: maxTokens,
        stream: false,
        messages: [
          { role: 'system', content: system },
          { role: 'user', content: user }
        ]
      })
    });

    const text = await resp.text(); // capture server error body for clarity
    if (!resp.ok) {
      // Typical errors: 401 invalid key, 404 deployment not found, 400 invalid api-version
      throw new Error(`LLM error ${resp.status}: ${text}`);
    }
    const data = JSON.parse(text);
    return data.choices?.[0]?.message?.content?.trim() ?? '';
  }

  // OpenAI (non-Azure) fallback
  const model = process.env.OPENAI_MODEL || 'gpt-4o-mini';
  if (!process.env.OPENAI_API_KEY) {
    throw new Error('OpenAI path selected but OPENAI_API_KEY is missing.');
  }

  const resp = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      model,
      temperature,
      max_tokens: maxTokens,
      messages: [
        { role: 'system', content: system },
        { role: 'user', content: user }
      ]
    })
  });

  const text = await resp.text();
  if (!resp.ok) {
    throw new Error(`LLM error ${resp.status}: ${text}`);
  }
  const data = JSON.parse(text);
  return data.choices?.[0]?.message?.content?.trim() ?? '';
}

function writeNdjson(stream, obj) {
  stream.write(JSON.stringify(obj) + '\n');
}

/* ---------------------------- HTTP Function ---------------------------- */
app.http('IRPlaybook', {
  methods: ['POST', 'OPTIONS'],
  authLevel: 'anonymous',
  handler: async (request, context) => {
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

    const stream = new PassThrough();

    (async () => {
      try {
        const body = await request.json().catch(() => ({}));
        const {
          category = 'Credential Theft',
          incidentDetails = '',
          environment = { sentinel: true, mde: true, mdi: true, mdo: true },
          severity = 'High'
        } = body || {};

        const system = [
          'You are a senior IR analyst specialized in Microsoft Sentinel and Defender.',
          'Write concise, actionable guidance for a SOC runbook.',
          'Use markdown for lists and code blocks for KQL.',
          'Never include em dashes; prefer short sentences.',
          'Audience: security engineers and analysts.'
        ].join(' ');

        const sections = [
          {
            key: 'executiveSummary',
            title: 'Executive Summary',
            prompt:
              `Create a 4–6 sentence executive summary for an incident of type "${category}". ` +
              `Assume severity ${severity}. Include scope, likely impact, and immediate actions taken.`
          },
          {
            key: 'initialTriage',
            title: 'Initial Triage',
            prompt:
              'List 6–10 initial triage actions as bullet points specific to Microsoft 365 Defender and Sentinel. ' +
              'Add console paths in parentheses.'
          },
          {
            key: 'investigationSteps',
            title: 'Investigation Steps',
            prompt:
              'Provide a numbered list of deep-dive investigation steps. Mention artifacts to collect, timelines, and pivots.'
          },
          {
            key: 'kqlValidateDetection',
            title: 'KQL: Validate Detection',
            prompt:
              'Return a fenced ```kql code block``` to validate the detection in Microsoft Sentinel. ' +
              'Use comments. Prefer SecurityAlert, SecurityIncident, SigninLogs, IdentityInfo, DeviceInfo.'
          },
          {
            key: 'kqlLateralMovement',
            title: 'KQL: Lateral Movement',
            prompt:
              'Return a fenced ```kql code block``` to identify lateral movement across hosts and identities. Use comments.'
          },
          {
            key: 'kqlTimeline',
            title: 'KQL: Timeline',
            prompt:
              'Return a fenced ```kql code block``` to build a chronological timeline (timestamp, actor, target, action, source).'
          },
          {
            key: 'containment',
            title: 'Containment',
            prompt:
              'List 5–8 containment actions. Include SaaS vs on-prem variants and tool paths/commands.'
          },
          {
            key: 'eradication',
            title: 'Eradication',
            prompt:
              'List 4–6 eradication steps with checks to verify persistence removal.'
          },
          {
            key: 'recovery',
            title: 'Recovery',
            prompt:
              'List 4–6 recovery actions, including validation criteria, comms, and monitored metrics for 72 hours.'
          },
          {
            key: 'postIncident',
            title: 'Post-Incident',
            prompt:
              'Checklist for lessons learned, control gaps, detections to add, and KPIs to track.'
          },
          {
            key: 'mitreTactics',
            title: 'MITRE ATT&CK',
            prompt:
              'List relevant MITRE ATT&CK tactics and techniques (ID:Name) as bullets.'
          },
          {
            key: 'severityGuidance',
            title: 'Severity Guidance',
            prompt:
              `Explain why this case is ${severity} severity, with escalation criteria and SLA targets in minutes.`
          }
        ];

        // Meta event
        writeNdjson(stream, { type: 'meta', category, severity, environment });

        // Generate each section sequentially and stream it
        for (const s of sections) {
          const user = [
            `Category: ${category}`,
            `Severity: ${severity}`,
            `Environment: ${JSON.stringify(environment)}`,
            `Details:\n${incidentDetails || 'N/A'}`,
            '',
            `Write ONLY the ${s.title} content.`
          ].join('\n');

          const content = await completeText({
            system,
            user,
            modelHints: { temperature: 0.25, maxTokens: 800 }
          });

          writeNdjson(stream, { type: 'section', key: s.key, title: s.title, content });
        }

        writeNdjson(stream, { type: 'done' });
      } catch (err) {
        writeNdjson(stream, { type: 'error', message: err?.message || 'Unknown error' });
      } finally {
        stream.end();
      }
    })();

    return {
      status: 200,
      headers: {
        'Content-Type': 'application/x-ndjson; charset=utf-8',
        'Cache-Control': 'no-store',
        'Access-Control-Allow-Origin': '*'
      },
      body: stream
    };
  }
});
