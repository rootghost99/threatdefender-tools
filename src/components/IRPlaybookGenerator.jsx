// /src/components/IRPlaybookGenerator.jsx
// React component that streams an IR playbook from /api/IRPlaybook (NDJSON).
// Each section renders as soon as it arrives. Includes skeletons & copy buttons.

import React, { useMemo, useState } from 'react';

const SectionCard = ({ title, content, darkMode, loading = false }) => {
  const base = darkMode ? 'bg-gray-700 border-gray-600 text-gray-100' : 'bg-white border-gray-200 text-gray-900';
  const sub = darkMode ? 'text-gray-300' : 'text-gray-700';

  const onCopy = () => {
    if (content) navigator.clipboard.writeText(content);
  };

  return (
    <div className={`p-6 rounded-lg border ${base}`}>
      <div className="flex items-center justify-between mb-3">
        <h4 className="text-lg font-bold">{title}</h4>
        <button
          onClick={onCopy}
          disabled={!content}
          className={`text-xs px-3 py-1 rounded ${content ? (darkMode ? 'bg-gray-600 hover:bg-gray-500' : 'bg-gray-100 hover:bg-gray-200') : (darkMode ? 'bg-gray-800 text-gray-500' : 'bg-gray-100 text-gray-400')} `}
          title="Copy section"
        >
          Copy
        </button>
      </div>

      {loading ? (
        <div className="animate-pulse space-y-2">
          <div className={`h-4 rounded ${darkMode ? 'bg-gray-600' : 'bg-gray-200'}`} />
          <div className={`h-4 rounded w-5/6 ${darkMode ? 'bg-gray-600' : 'bg-gray-200'}`} />
          <div className={`h-4 rounded w-2/3 ${darkMode ? 'bg-gray-600' : 'bg-gray-200'}`} />
        </div>
      ) : content ? (
        <div className={`prose max-w-none ${darkMode ? 'prose-invert' : ''}`}>
          {/* Render markdown-ish content simply; you can swap in a markdown renderer if you use one elsewhere */}
          {content.split('\n').map((line, idx) => (
            <p key={idx} className={sub} style={{ whiteSpace: 'pre-wrap', margin: '0.35rem 0' }}>
              {line}
            </p>
          ))}
        </div>
      ) : (
        <p className={sub}>No content.</p>
      )}
    </div>
  );
};

export default function IRPlaybookGenerator({ darkMode }) {
  const [category, setCategory] = useState('Credential Theft');
  const [severity, setSeverity] = useState('High');
  const [details, setDetails] = useState('');
  const [env, setEnv] = useState({ sentinel: true, mde: true, mdi: true, mdo: true });

  const [running, setRunning] = useState(false);
  const [error, setError] = useState(null);

  // Progressive playbook state
  const [sections, setSections] = useState({
    executiveSummary: null,
    initialTriage: null,
    investigationSteps: null,
    kqlValidateDetection: null,
    kqlLateralMovement: null,
    kqlTimeline: null,
    containment: null,
    eradication: null,
    recovery: null,
    postIncident: null,
    mitreTactics: null,
    severityGuidance: null
  });

  const ordered = useMemo(
    () => [
      { key: 'executiveSummary', title: 'Executive Summary' },
      { key: 'initialTriage', title: 'Initial Triage' },
      { key: 'investigationSteps', title: 'Investigation Steps' },
      { key: 'kqlValidateDetection', title: 'KQL: Validate Detection' },
      { key: 'kqlLateralMovement', title: 'KQL: Lateral Movement' },
      { key: 'kqlTimeline', title: 'KQL: Timeline' },
      { key: 'containment', title: 'Containment' },
      { key: 'eradication', title: 'Eradication' },
      { key: 'recovery', title: 'Recovery' },
      { key: 'postIncident', title: 'Post-Incident' },
      { key: 'mitreTactics', title: 'MITRE ATT&CK' },
      { key: 'severityGuidance', title: 'Severity Guidance' }
    ],
    []
  );

  const reset = () => {
    setError(null);
    setSections({
      executiveSummary: null,
      initialTriage: null,
      investigationSteps: null,
      kqlValidateDetection: null,
      kqlLateralMovement: null,
      kqlTimeline: null,
      containment: null,
      eradication: null,
      recovery: null,
      postIncident: null,
      mitreTactics: null,
      severityGuidance: null
    });
  };

  const start = async () => {
    if (running) return;
    reset();
    setRunning(true);

    try {
      const res = await fetch('/api/IRPlaybook', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          category,
          severity,
          incidentDetails: details,
          environment: env
        })
      });

      if (!res.ok || !res.body) {
        const t = await res.text().catch(() => '');
        throw new Error(`Request failed: ${res.status} ${t}`);
      }

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed) continue;

          let evt;
          try {
            evt = JSON.parse(trimmed);
          } catch {
            // Ignore malformed line
            continue;
          }

          if (evt.type === 'meta') {
            // could display toast/badge if you want
            continue;
          }

          if (evt.type === 'section' && evt.key) {
            setSections(prev => ({ ...prev, [evt.key]: evt.content || '' }));
            continue;
          }

          if (evt.type === 'error') {
            setError(evt.message || 'Unknown error');
            continue;
          }

          if (evt.type === 'done') {
            // graceful end
          }
        }
      }
    } catch (e) {
      setError(e.message || 'Stream failed');
    } finally {
      setRunning(false);
    }
  };

  const base = darkMode ? 'bg-gray-800 text-gray-100' : 'bg-white text-gray-900';
  const sub = darkMode ? 'text-gray-300' : 'text-gray-700';

  return (
    <div className={`rounded-lg shadow-md p-6 ${base}`}>
      <div className="mb-6">
        <h2 className="text-xl font-bold mb-2">🧰 IR Playbook Generator (Streaming)</h2>
        <p className={`text-sm ${sub}`}>
          Generates a Microsoft-centric incident playbook and streams sections as they complete.
        </p>
      </div>

      {/* Controls */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
        <div>
          <label className={`block text-sm font-semibold mb-1 ${sub}`}>Category</label>
          <select
            value={category}
            onChange={e => setCategory(e.target.value)}
            className={`w-full px-3 py-2 rounded border ${darkMode ? 'bg-gray-700 border-gray-600' : 'bg-white border-gray-300'}`}
          >
            <option>Credential Theft</option>
            <option>Business Email Compromise</option>
            <option>Ransomware</option>
            <option>Phishing</option>
            <option>Malware</option>
            <option>Insider Threat</option>
          </select>
        </div>

        <div>
          <label className={`block text-sm font-semibold mb-1 ${sub}`}>Severity</label>
          <select
            value={severity}
            onChange={e => setSeverity(e.target.value)}
            className={`w-full px-3 py-2 rounded border ${darkMode ? 'bg-gray-700 border-gray-600' : 'bg-white border-gray-300'}`}
          >
            <option>Informational</option>
            <option>Low</option>
            <option>Medium</option>
            <option>High</option>
            <option>Critical</option>
          </select>
        </div>

        <div className="md:col-span-2">
          <label className={`block text-sm font-semibold mb-1 ${sub}`}>Incident Details / Context</label>
          <textarea
            rows={4}
            placeholder="Affected users, hosts, domains, observed behaviors, timestamps, etc."
            value={details}
            onChange={e => setDetails(e.target.value)}
            className={`w-full px-3 py-2 rounded border ${darkMode ? 'bg-gray-700 border-gray-600' : 'bg-white border-gray-300'} `}
          />
        </div>
      </div>

      {/* Environment toggles */}
      <div className="flex flex-wrap gap-2 mb-4">
        {[
          { key: 'sentinel', label: 'Microsoft Sentinel' },
          { key: 'mde', label: 'Defender for Endpoint' },
          { key: 'mdi', label: 'Defender for Identity' },
          { key: 'mdo', label: 'Defender for Office 365' }
        ].map(x => (
          <label key={x.key} className={`inline-flex items-center gap-2 px-3 py-2 rounded border ${darkMode ? 'border-gray-600' : 'border-gray-300'}`}>
            <input
              type="checkbox"
              checked={!!env[x.key]}
              onChange={(e) => setEnv(prev => ({ ...prev, [x.key]: e.target.checked }))}
            />
            <span className="text-sm">{x.label}</span>
          </label>
        ))}
      </div>

      <button
        onClick={start}
        disabled={running}
        className={`w-full py-3 px-6 rounded-lg font-semibold ${running ? (darkMode ? 'bg-gray-700 text-gray-400' : 'bg-gray-200 text-gray-400') : 'bg-blue-600 text-white hover:bg-blue-700'}`}
      >
        {running ? '⏳ Generating…' : '🚀 Generate Playbook (Streaming)'}
      </button>

      {/* Error */}
      {error && (
        <div className={`mt-4 p-4 rounded border ${darkMode ? 'bg-red-900 border-red-700 text-red-200' : 'bg-red-50 border-red-300 text-red-700'}`}>
          ⚠️ {error}
        </div>
      )}

      {/* Sections */}
      <div className="mt-6 space-y-4">
        {ordered.map(({ key, title }) => (
          <SectionCard
            key={key}
            title={title}
            content={sections[key]}
            loading={running && sections[key] == null}
            darkMode={darkMode}
          />
        ))}
      </div>
    </div>
  );
}
