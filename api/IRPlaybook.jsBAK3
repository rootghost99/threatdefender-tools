// /api/IRPlaybook.js
// Azure Functions (v4, Node 18+) — one-shot JSON playbook generator.
// Uses Azure OpenAI when AZURE_OPENAI_ENDPOINT is set, else OpenAI.

const { app } = require('@azure/functions');

async function callLLM(messages, { useAzure }) {
  const temperature = 0.25;
  const maxTokens = 2400;

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

app.http('IRPlaybook', {
  methods: ['POST', 'OPTIONS'],
  authLevel: 'anonymous',
  handler: async (request) => {
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
        category = 'Credential Theft',
        incidentDetails = '',
        environment = { sentinel: true, mde: true, mdi: true, mdo: true },
        severity = 'High'
      } = body || {};

      const schema = {
        type: 'object',
        properties: {
          executiveSummary: { type: 'string' },
          initialTriage: { type: 'array', items: { type: 'string' } },
          investigationSteps: { type: 'array', items: { type: 'string' } },
          kql: {
            type: 'object',
            properties: {
              validateDetection: { type: 'string' },
              lateralMovement: { type: 'string' },
              timeline: { type: 'string' }
            }
          },
          containment: { type: 'array', items: { type: 'string' } },
          eradication: { type: 'array', items: { type: 'string' } },
          recovery: { type: 'array', items: { type: 'string' } },
          postIncident: { type: 'array', items: { type: 'string' } },
          mitreTactics: { type: 'array', items: { type: 'string' } },
          severityGuidance: { type: 'string' }
        },
        required: [
          'executiveSummary', 'initialTriage', 'investigationSteps', 'kql',
          'containment', 'eradication', 'recovery', 'postIncident', 'mitreTactics', 'severityGuidance'
        ]
      };

      const system =
        'You are a senior IR analyst for Microsoft Sentinel and Microsoft Defender. ' +
        'Produce concise, practical guidance. Use bullet lists where useful. ' +
        'For KQL, return fenced code blocks inside JSON values with ```kql. ' +
        'Never include em dashes. Output valid JSON only that matches the provided schema. No extra text.';

      const user = {
        category,
        severity,
        environment,
        details: incidentDetails,
        schema
      };

      const useAzure = !!process.env.AZURE_OPENAI_ENDPOINT;
      const content = await callLLM(
        [
          { role: 'system', content: system },
          { role: 'user', content: JSON.stringify(user) }
        ],
        { useAzure }
      );

      let obj;
      try {
        obj = JSON.parse(content);
      } catch {
        throw new Error('Model did not return valid JSON. Try again.');
      }

      return {
        status: 200,
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Access-Control-Allow-Origin': '*',
          'Cache-Control': 'no-store'
        },
        jsonBody: { playbook: obj, meta: { category, severity, environment, provider: useAzure ? 'azure' : 'openai' } }
      };
    } catch (err) {
      return {
        status: 500,
        headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*'},
        jsonBody: { error: String(err.message || err) }
      };
    }
  }
});
