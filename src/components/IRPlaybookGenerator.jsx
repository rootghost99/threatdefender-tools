// /src/components/IRPlaybookGenerator.jsx
import React, { useMemo, useState } from 'react';

const SectionCard = ({ title, content, darkMode }) => {
  const base = darkMode ? 'bg-gray-700 border-gray-600 text-gray-100' : 'bg-white border-gray-200 text-gray-900';
  const sub = darkMode ? 'text-gray-300' : 'text-gray-700';
  const onCopy = () => content && navigator.clipboard.writeText(content);

  // content can be markdown-ish; we keep it simple and preserve line breaks
  return (
    <div className={`p-6 rounded-lg border ${base}`}>
      <div className="flex items-center justify-between mb-3">
        <h4 className="text-lg font-bold">{title}</h4>
        <button
          onClick={onCopy}
          disabled={!content}
          className={`text-xs px-3 py-1 rounded ${content ? (darkMode ? 'bg-gray-600 hover:bg-gray-500' : 'bg-gray-100 hover:bg-gray-200') : (darkMode ? 'bg-gray-800 text-gray-500' : 'bg-gray-100 text-gray-400')}`}
        >
          Copy
        </button>
      </div>
      {content ? (
        <div className={`prose max-w-none ${darkMode ? 'prose-invert' : ''}`}>
          {String(content).split('\n').map((line, i) => (
            <p key={i} className={sub} style={{ whiteSpace: 'pre-wrap', margin: '0.35rem 0' }}>{line}</p>
          ))}
        </div>
      ) : <p className={sub}>No content.</p>}
    </div>
  );
};

export default function IRPlaybookGenerator({ darkMode }) {
  const [category, setCategory] = useState('Credential Theft');
  const [severity, setSeverity] = useState('High');
  const [details, setDetails] = useState('');
  const [env, setEnv] = useState({ sentinel: true, mde: true, mdi: true, mdo: true });

  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);
  const [pb, setPb] = useState(null);

  const ordered = useMemo(() => [
    { key: 'executiveSummary', title: 'Executive Summary' },
    { key: 'initialTriage', title: 'Initial Triage' },
    { key: 'investigationSteps', title: 'Investigation Steps' },
    { key: 'kql.validateDetection', title: 'KQL: Validate Detection', isKql: true },
    { key: 'kql.lateralMovement', title: 'KQL: Lateral Movement', isKql: true },
    { key: 'kql.timeline', title: 'KQL: Timeline', isKql: true },
    { key: 'containment', title: 'Containment' },
    { key: 'eradication', title: 'Eradication' },
    { key: 'recovery', title: 'Recovery' },
    { key: 'postIncident', title: 'Post-Incident' },
    { key: 'mitreTactics', title: 'MITRE ATT&CK' },
    { key: 'severityGuidance', title: 'Severity Guidance' }
  ], []);

  const start = async () => {
    if (loading) return;
    setLoading(true);
    setErr(null);
    setPb(null);

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

      const text = await res.text();
      if (!res.ok) {
        throw new Error(text || `Request failed with ${res.status}`);
      }
      const { playbook } = JSON.parse(text);
      setPb(playbook || {});
    } catch (e) {
      setErr(e.message || 'Failed to generate playbook');
    } finally {
      setLoading(false);
    }
  };

  const base = darkMode ? 'bg-gray-800 text-gray-100' : 'bg-white text-gray-900';
  const sub = darkMode ? 'text-gray-300' : 'text-gray-700';

  const get = (obj, path) => path.split('.').reduce((a, k) => (a ? a[k] : undefined), obj || {});

  return (
    <div className={`rounded-lg shadow-md p-6 ${base}`}>
      <div className="mb-6">
        <h2 className="text-xl font-bold">🧰 IR Playbook Generator</h2>
        <p className={`text-sm ${sub}`}>Generates a full playbook in one request.</p>
      </div>

      {/* Controls */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
        <div>
          <label className={`block text-sm font-semibold mb-1 ${sub}`}>Category</label>
          <select value={category} onChange={(e) => setCategory(e.target.value)}
            className={`w-full px-3 py-2 rounded border ${darkMode ? 'bg-gray-700 border-gray-600' : 'bg-white border-gray-300'}`}>
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
          <select value={severity} onChange={(e) => setSeverity(e.target.value)}
            className={`w-full px-3 py-2 rounded border ${darkMode ? 'bg-gray-700 border-gray-600' : 'bg-white border-gray-300'}`}>
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
            placeholder="Affected users, hosts, domains, observables, timestamps."
            value={details}
            onChange={(e) => setDetails(e.target.value)}
            className={`w-full px-3 py-2 rounded border ${darkMode ? 'bg-gray-700 border-gray-600' : 'bg-white border-gray-300'}`}
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
            <input type="checkbox" checked={!!env[x.key]} onChange={(e) => setEnv(prev => ({ ...prev, [x.key]: e.target.checked }))}/>
            <span className="text-sm">{x.label}</span>
          </label>
        ))}
      </div>

      <button
        onClick={start}
        disabled={loading}
        className={`w-full py-3 px-6 rounded-lg font-semibold ${loading ? (darkMode ? 'bg-gray-700 text-gray-400' : 'bg-gray-200 text-gray-400') : 'bg-blue-600 text-white hover:bg-blue-700'}`}
      >
        {loading ? 'Generating…' : 'Generate Playbook'}
      </button>

      {err && (
        <div className={`mt-4 p-4 rounded border ${darkMode ? 'bg-red-900 border-red-700 text-red-200' : 'bg-red-50 border-red-300 text-red-700'}`}>
          ⚠️ {err}
        </div>
      )}

      {/* Sections */}
      {pb && (
        <div className="mt-6 space-y-4">
          {ordered.map(({ key, title }) => (
            <SectionCard key={key} title={title} content={get(pb, key)} darkMode={darkMode} />
          ))}
        </div>
      )}
    </div>
  );
}
