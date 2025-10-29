// /api/IRPlaybook.js
// Azure Functions (v4) HTTP trigger that streams an IR playbook in sections via NDJSON.

const { app } = require('@azure/functions');
const { PassThrough } = require('stream');

// ---- LLM wrapper (uses global fetch on Node 18+) ----
async function completeText({ system, user, modelHints = {} }) {
  const useAzure = !!process.env.AZURE_OPENAI_ENDPOINT;
  const temperature = modelHints.temperature ?? 0.2;
  const maxTokens = modelHints.maxTokens ?? 700;

  if (useAzure) {
    const endpoint = process.env.AZURE_OPENAI_ENDPOINT.replace(/\/+$/, '');
    const deployment = process.env.AZURE_OPENAI_DEPLOYMENT;
    const url = `${endpoint}/openai/deployments/${deployment}/chat/completions?api-version=2024-02-15-preview`;

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

    if (!resp.ok) throw new Error(`LLM error ${resp.status}`);
    const data = await resp.json();
    return data.choices?.[0]?.message?.content?.trim() ?? '';
  }

  // OpenAI fallback
  const model = process.env.OPENAI_MODEL || 'gpt-4o-mini';
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

  if (!resp.ok) throw new Error(`LLM error ${resp.status}`);
  const data = await resp.json();
  return data.choices?.[0]?.message?.content?.trim() ?? '';
}

function writeNdjson(stream, obj) {
  stream.write(JSON.stringify(obj) + '\n');
}

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
          { key: 'executiveSummary', title: 'Executive Summary',
            prompt: `Create a 4–6 sentence executive summary for an incident of type "${category}". Assume severity ${severity}. Include scope, likely impact, and immediate actions taken.` },
          { key: 'initialTriage', title: 'Initial Triage',
            prompt: 'List 6–10 initial triage actions as bullet points specific to Microsoft 365 Defender and Sentinel.' },
          { key: 'investigationSteps', title: 'Investigation Steps',
            prompt: 'Provide a numbered list of deep-dive investigation steps. Mention artifacts, timelines, and pivots.' },
          { key: 'kqlValidateDetection', title: 'KQL: Validate Detection',
            prompt: 'Return a fenced ```kql code block``` to validate the detection in Microsoft Sentinel. Add comments.' },
          { key: 'kqlLateralMovement', title: 'KQL: Lateral Movement',
            prompt: 'Return a fenced ```kql code block``` to identify lateral movement. Add comments.' },
          { key: 'kqlTimeline', title: 'KQL: Timeline',
            prompt: 'Return a fenced ```kql code block``` to build a chronological timeline. Avoid smart quotes.' },
          { key: 'containment', title: 'Containment',
            prompt: 'List 5–8 containment actions. Include SaaS vs on-prem variants and tool paths.' },
          { key: 'eradication', title: 'Eradication',
            prompt: 'List 4–6 eradication steps. Include hunting queries to verify removal.' },
          { key: 'recovery', title: 'Recovery',
            prompt: 'List 4–6 recovery actions with validation criteria and monitored metrics for 72 hours.' },
          { key: 'postIncident', title: 'Post-Incident',
            prompt: 'Checklist for lessons learned, control gaps, detections to add, and KPIs to track.' },
          { key: 'mitreTactics', title: 'MITRE ATT&CK',
            prompt: 'List relevant MITRE ATT&CK tactics and techniques (ID:Name) as bullets.' },
          { key: 'severityGuidance', title: 'Severity Guidance',
            prompt: `Explain why this is ${severity} severity, with escalation criteria and SLA targets in minutes.` }
        ];

        writeNdjson(stream, { type: 'meta', category, severity, environment });

        for (const s of sections) {
          const user = [
            `Category: ${category}`,
            `Severity: ${severity}`,
            `Environment: ${JSON.stringify(environment)}`,
            `Details:\n${incidentDetails || 'N/A'}`,
            '',
            `Write ONLY the ${s.title} content.`,
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
