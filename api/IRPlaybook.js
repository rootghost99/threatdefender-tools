// /api/IRPlaybook.js
// Azure Functions (v4) HTTP trigger that streams an IR playbook in sections.
// Output format: NDJSON (one JSON object per line). Example event:
// {"type":"section","key":"executiveSummary","content":"...markdown..."}
// Final event: {"type":"done"}
// Errors: {"type":"error","message":"..."}

const { app } = require('@azure/functions');
const { PassThrough } = require('stream');
const fetch = (...args) => import('node-fetch').then(({ default: f }) => f(...args));

/**
 * Minimal OpenAI/Azure OpenAI call wrapper.
 * This orchestrates one section at a time to keep things deterministic and easy to stream.
 * If you use Azure OpenAI, set:
 *   AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_API_KEY, AZURE_OPENAI_DEPLOYMENT
 * If you use OpenAI API, set:
 *   OPENAI_API_KEY, OPENAI_MODEL
 */
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
  } else {
    // OpenAI API (fallback)
    const url = 'https://api.openai.com/v1/chat/completions';
    const model = process.env.OPENAI_MODEL || 'gpt-4o-mini';
    const resp = await fetch(url, {
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
}

function writeNdjson(stream, obj) {
  stream.write(JSON.stringify(obj) + '\n');
}

app.http('IRPlaybook', {
  methods: ['POST', 'OPTIONS'],
  authLevel: 'anonymous',
  handler: async (request, context) => {
    // Handle CORS preflight
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

    // Kick off async work while returning a streaming response
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

        // Section prompts. Feel free to extend/reorder.
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
              'List 6–10 initial triage actions as bullet points. Be specific to Microsoft 365 Defender and Sentinel. ' +
              'Include links or console paths in parentheses, and any prerequisites.'
          },
          {
            key: 'investigationSteps',
            title: 'Investigation Steps',
            prompt:
              'Provide a numbered list of deep-dive investigation steps. Mention artifacts to collect, timelines to build, and pivots.'
          },
          {
            key: 'kqlValidateDetection',
            title: 'KQL: Validate Detection',
            prompt:
              'Return a fenced ```kql code block``` to validate the detection in Microsoft Sentinel. ' +
              'Comment lines to explain intent. Prefer tables: SecurityAlert, SecurityIncident, SigninLogs, IdentityInfo, DeviceInfo. ' +
              'Avoid smart quotes.'
          },
          {
            key: 'kqlLateralMovement',
            title: 'KQL: Lateral Movement',
            prompt:
              'Return a fenced ```kql code block``` to identify possible lateral movement across hosts and identities. ' +
              'Include comments. Avoid smart quotes.'
          },
          {
            key: 'kqlTimeline',
            title: 'KQL: Timeline',
            prompt:
              'Return a fenced ```kql code block``` to produce a chronological timeline with timestamps, actor, target, action, and source. ' +
              'Avoid smart quotes.'
          },
          {
            key: 'containment',
            title: 'Containment',
            prompt:
              'List 5–8 containment actions. Include conditional branches for SaaS vs on-prem. Provide tool-specific commands or paths.'
          },
          {
            key: 'eradication',
            title: 'Eradication',
            prompt:
              'List 4–6 eradication steps. Include hunting queries to verify persistence removal.'
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
              'Provide a checklist for lessons learned, control gaps, detections to add, and KPIs to track.'
          },
          {
            key: 'mitreTactics',
            title: 'MITRE ATT&CK',
            prompt:
              'List relevant MITRE ATT&CK tactics and techniques (ID:Name) as bullets. Keep it tight.'
          },
          {
            key: 'severityGuidance',
            title: 'Severity Guidance',
            prompt:
              `Explain why this case would be ${severity} severity, with escalation criteria and SLA targets in minutes.`
          }
        ];

        // Announce meta
        writeNdjson(stream, {
          type: 'meta',
          category,
          severity,
          environment
        });

        // Process sections sequentially; stream as each completes
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

          writeNdjson(stream, {
            type: 'section',
            key: s.key,
            title: s.title,
            content
          });
        }

        writeNdjson(stream, { type: 'done' });
      } catch (err) {
        writeNdjson(stream, {
          type: 'error',
          message: err?.message || 'Unknown error'
        });
      } finally {
        stream.end();
      }
    })();

    return {
      status: 200,
      headers: {
        // NDJSON plus permissive CORS for your web app
        'Content-Type': 'application/x-ndjson; charset=utf-8',
        'Cache-Control': 'no-store',
        'Access-Control-Allow-Origin': '*'
      },
      // Important: return the stream body
      body: stream
    };
  }
});
