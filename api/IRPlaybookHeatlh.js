// /api/IRPlaybookHealth.js
// Fast health check to verify LLM connectivity and surface provider/dep info.

const { app } = require('@azure/functions');

app.http('IRPlaybookHealth', {
  methods: ['GET'],
  authLevel: 'anonymous',
  handler: async (req, ctx) => {
    const useAzure = !!process.env.AZURE_OPENAI_ENDPOINT;
    try {
      if (useAzure) {
        const endpoint = String(process.env.AZURE_OPENAI_ENDPOINT || '').trim().replace(/\/+$/, '');
        const deployment = String(process.env.AZURE_OPENAI_DEPLOYMENT || '').trim();
        const apiVersion = '2024-08-01-preview';
        const url = `${endpoint}/openai/deployments/${encodeURIComponent(deployment)}/chat/completions?api-version=${apiVersion}`;
        const resp = await fetch(url, {
          method: 'POST',
          headers: { 'api-key': process.env.AZURE_OPENAI_API_KEY, 'Content-Type': 'application/json' },
          body: JSON.stringify({ messages: [{ role: 'user', content: 'ping' }], max_tokens: 1 })
        });
        if (!resp.ok) {
          const text = await resp.text();
          return { status: resp.status, jsonBody: { ok: false, provider: 'azure', endpoint, deployment, error: text } };
        }
        return { status: 200, jsonBody: { ok: true, provider: 'azure', endpoint, deployment } };
      } else {
        const model = process.env.OPENAI_MODEL || 'gpt-4o-mini';
        const resp = await fetch('https://api.openai.com/v1/chat/completions', {
          method: 'POST',
          headers: { Authorization: `Bearer ${process.env.OPENAI_API_KEY}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ model, messages: [{ role: 'user', content: 'ping' }], max_tokens: 1 })
        });
        if (!resp.ok) {
          const text = await resp.text();
          return { status: resp.status, jsonBody: { ok: false, provider: 'openai', model, error: text } };
        }
        return { status: 200, jsonBody: { ok: true, provider: 'openai', model } };
      }
    } catch (e) {
      return { status: 500, jsonBody: { ok: false, error: e.message } };
    }
  }
});
