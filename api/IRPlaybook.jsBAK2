// /api/IRPlaybook.js
// Azure Functions (v4, Node 18+) — streams IR playbook via SSE so SWA won't buffer.
// Supports GET (SSE) with a base64 payload in ?q= and POST (will up-convert to SSE internally).

const { app } = require('@azure/functions');
const { PassThrough } = require('stream');

/* ---------------- LLM wrapper ---------------- */
async function completeText({ system, user, modelHints = {} }) {
  const useAzure = !!process.env.AZURE_OPENAI_ENDPOINT;
  const temperature = modelHints.temperature ?? 0.2;
  const maxTokens = modelHints.maxTokens ?? 700;

  if (useAzure) {
    const endpoint = String(process.env.AZURE_OPENAI_ENDPOINT || '').trim().replace(/\/+$/, '');
    const deployment = String(process.env.AZURE_OPENAI_DEPLOYMENT || '').trim();
    const apiVersion = '2024-08-01-preview';
    if (!endpoint || !deployment || !process.env.AZURE_OPENAI_API_KEY) {
      throw new Error('Azure OpenAI settings missing.');
    }
    const url = `${endpoint}/openai/deployments/${encodeURIComponent(deployment)}/chat/completions?api-version=${apiVersion}`;
    const resp = await fetch(url, {
      method: 'POST',
      headers: { 'api-key': process.env.AZURE_OPENAI_API_KEY, 'Content-Type': 'application/json' },
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
    const text = await resp.text();
    if (!resp.ok) throw new Error(`LLM error ${resp.status}: ${text}\nURL:${url}`);
    const data = JSON.parse(text);
    return data.choices?.[0]?.message?.content?.trim() ?? '';
  }

  // OpenAI fallback
  const model = process.env.OPENAI_MODEL || 'gpt-4o-mini';
  if (!process.env.OPENAI_API_KEY) throw new Error('OPENAI_API_KEY missing.');
  const url = 'https://api.openai.com/v1/chat/completions';
  const resp = await fetch(url, {
    method: 'POST',
    headers: { Authorization: `Bearer ${process.env.OPENAI_API_KEY}`, 'Content-Type': 'application/json' },
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
  if (!resp.ok) throw new Error(`LLM error ${resp.status}: ${text}\nURL:${url}`);
  const data = JSON.parse(text);
  return data.choices?.[0]?.message?.content?.trim() ?? '';
}

/* ---------------- Helpers ---------------- */
function sse(stream, event, data) {
  stream.write(`event: ${event}\n`);
  stream.write(`data: ${JSON.stringify(data)}\n\n`);
}
function keepAlive(stream) {
  stream.write(`: ping\n\n`);
}

/* ---------------- HTTP Function ---------------- */
app.http('IRPlaybook', {
  methods: ['GET', 'POST', 'OPTIONS'],
  authLevel: 'anonymous',
  handler: async (request, context) => {
    if (request.method === 'OPTIONS') {
      return {
        status: 200,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type'
        }
      };
    }

    // Parse payload:
    let payload;
    if (request.method === 'GET') {
      const q = new URL(request.url).searchParams.get('q') || '';
      try {
        // base64url safe decode
        const norm = q.replace(/-/g, '+').replace(/_/g, '/');
        payload = JSON.parse(Buffer.from(norm, 'base64').toString('utf8'));
      } catch {
        payload = {};
      }
    } else {
      payload = await request.json().catch(() => ({}));
    }

    const {
      category = 'Credential Theft',
      incidentDetails = '',
      environment = { sentinel: true, mde: true, mdi: true, mdo: true },
      severity = 'High'
    } = payload || {};

    const system = [
      'You are a senior IR analyst specialized in Microsoft Sentinel and Defender.',
      'Write concise, actionable guidance for a SOC runbook.',
      'Use markdown for lists and code blocks for KQL.',
      'Never include em dashes; prefer short sentences.',
      'Audience: security engineers and analysts.'
    ].join(' ');

    const sections = [
      { key: 'executiveSummary', title: 'Executive Summary',
        prompt: `Create a 4–6 sentence executive summary for "${category}", severity ${severity}. Include scope, impact, immediate actions.` },
      { key: 'initialTriage', title: 'Initial Triage',
        prompt: 'List 6–10 initial triage actions for Microsoft 365 Defender and Sentinel with console paths.' },
      { key: 'investigationSteps', title: 'Investigation Steps',
        prompt: 'Numbered deep-dive investigation steps. Artifacts, timelines, pivots.' },
      { key: 'kqlValidateDetection', title: 'KQL: Validate Detection',
        prompt: 'Fenced ```kql``` to validate detection in Sentinel with comments. Prefer SecurityAlert/SecurityIncident/SigninLogs.' },
      { key: 'kqlLateralMovement', title: 'KQL: Lateral Movement',
        prompt: 'Fenced ```kql``` to detect lateral movement across hosts and identities. With comments.' },
      { key: 'kqlTimeline', title: 'KQL: Timeline',
        prompt: 'Fenced ```kql``` to build a chronological timeline (timestamp, actor, target, action, source).' },
      { key: 'containment', title: 'Containment',
        prompt: '5–8 containment actions. Include SaaS vs on-prem, tool paths/commands.' },
      { key: 'eradication', title: 'Eradication',
        prompt: '4–6 eradication steps with checks to verify persistence removal.' },
      { key: 'recovery', title: 'Recovery',
        prompt: '4–6 recovery actions, validation criteria, comms, and 72h metrics.' },
      { key: 'postIncident', title: 'Post-Incident',
        prompt: 'Checklist for lessons learned, control gaps, detections to add, KPIs.' },
      { key: 'mitreTactics', title: 'MITRE ATT&CK',
        prompt: 'Relevant tactics and techniques (ID:Name) as bullets.' },
      { key: 'severityGuidance', title: 'Severity Guidance',
        prompt: `Explain why this is ${severity} severity with escalation criteria and SLA targets (minutes).` }
    ];

    const stream = new PassThrough();

    // Start async work
    (async () => {
      try {
        // Meta first
        const useAzure = !!process.env.AZURE_OPENAI_ENDPOINT;
        const endpoint = String(process.env.AZURE_OPENAI_ENDPOINT || '').trim().replace(/\/+$/, '');
        const deployment = String(process.env.AZURE_OPENAI_DEPLOYMENT || '').trim();
        sse(stream, 'meta', {
          category, severity, environment,
          provider: useAzure ? 'azure' : 'openai',
          azureEndpoint: useAzure ? endpoint : undefined,
          azureDeployment: useAzure ? deployment : undefined,
          azureApiVersion: useAzure ? '2024-08-01-preview' : undefined
        });

        // Keep-alive pings every 15s (avoid idle proxies closing)
        const ka = setInterval(() => keepAlive(stream), 15000);

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

          sse(stream, 'section', { key: s.key, title: s.title, content });
        }

        clearInterval(ka);
        sse(stream, 'done', {});
      } catch (err) {
        sse(stream, 'error', { message: err?.message || 'Unknown error' });
      } finally {
        stream.end();
      }
    })();

    // Return SSE response
    return {
      status: 200,
      headers: {
        'Content-Type': 'text/event-stream; charset=utf-8',
        'Cache-Control': 'no-cache, no-transform',
        'Connection': 'keep-alive',
        'Access-Control-Allow-Origin': '*'
      },
      body: stream
    };
  }
});
