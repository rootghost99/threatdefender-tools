// /src/components/IRPlaybookGenerator.jsx
import React, { useMemo, useState } from 'react';

/** Small card renderer with light code-fence support */
const SectionCard = ({ title, content, darkMode }) => {
  const base = darkMode ? 'bg-gray-700 border-gray-600 text-gray-100' : 'bg-white border-gray-200 text-gray-900';
  const sub  = darkMode ? 'text-gray-300' : 'text-gray-700';
  const onCopy = () => content && navigator.clipboard.writeText(String(content || ''));

  // Tiny fence parser for the first ```lang block
  const render = (txt) => {
    if (!txt) return <p className={sub}>No content.</p>;
    const s = String(txt);
    const m = s.match(/```(\w+)?\n([\s\S]*?)```/m);
    if (m) {
      const before = s.slice(0, m.index).trim();
      const after  = s.slice(m.index + m[0].length).trim();
      const lang   = m[1] || 'text';
      const code   = m[2];
      return (
        <div className="space-y-3">
          {before && before.split('\n').map((line, i) => (
            <p key={`b-${i}`} className={sub} style={{ whiteSpace: 'pre-wrap', margin: '0.35rem 0' }}>{line}</p>
          ))}
          <pre className={`rounded p-3 overflow-auto ${darkMode ? 'bg-gray-800' : 'bg-gray-100'}`}>
            <code className={`language-${lang}`} style={{ whiteSpace: 'pre' }}>{code}</code>
          </pre>
          {after && after.split('\n').map((line, i) => (
            <p key={`a-${i}`} className={sub} style={{ whiteSpace: 'pre-wrap', margin: '0.35rem 0' }}>{line}</p>
          ))}
        </div>
      );
    }
    return s.split('\n').map((line, i) => (
      <p key={i} className={sub} style={{ whiteSpace: 'pre-wrap', margin: '0.35rem 0' }}>{line}</p>
    ));
  };

  return (
    <div className={`p-6 rounded-lg border ${base}`}>
      <div className="flex items-center justify-between mb-3">
        <h4 className="text-lg font-bold">{title}</h4>
        <button
          onClick={onCopy}
          disabled={!content}
          className={`text-xs px-3 py-1 rounded ${
            content
              ? (darkMode ? 'bg-gray-600 hover:bg-gray-500' : 'bg-gray-100 hover:bg-gray-200')
              : (darkMode ? 'bg-gray-800 text-gray-500' : 'bg-gray-100 text-gray-400')
          }`}
        >
          Copy
        </button>
      </div>
      {render(content)}
    </div>
  );
};

// MITRE Tactic mapping (mirrors backend)
const MITRE_MAP = {
  'Phishing': { id: 'TA0001', name: 'Initial Access' },
  'Credential Theft': { id: 'TA0006', name: 'Credential Access' },
  'Password Spray / Brute Force': { id: 'TA0006', name: 'Credential Access' },
  'Malicious Script': { id: 'TA0002', name: 'Execution' },
  'Persistence Mechanism': { id: 'TA0003', name: 'Persistence' },
  'Privilege Escalation': { id: 'TA0004', name: 'Privilege Escalation' },
  'Defense Evasion': { id: 'TA0005', name: 'Defense Evasion' },
  'Discovery': { id: 'TA0007', name: 'Discovery' },
  'Lateral Movement': { id: 'TA0008', name: 'Lateral Movement' },
  'Data Collection': { id: 'TA0009', name: 'Collection' },
  'Data Exfiltration': { id: 'TA0010', name: 'Exfiltration' },
  'Command & Control': { id: 'TA0011', name: 'Command and Control' },
  'Ransomware / Impact': { id: 'TA0040', name: 'Impact' },
  'BEC': { id: 'TA0001', name: 'Initial Access' },
  'Insider Threat': { id: 'TA0009', name: 'Collection' },
  'Supply Chain / 3rd Party Breach': { id: 'TA0001', name: 'Initial Access' }
};

export default function IRPlaybookGenerator({ darkMode }) {
  const [category, setCategory]   = useState('Credential Theft');
  const [severity, setSeverity]   = useState('High');
  const [details, setDetails]     = useState('');
  const [env, setEnv]             = useState({ sentinel: true, mde: true, mdi: true, mdo: true });
  const [temperature, setTemp]    = useState(0.25); // prompt strength

  const [loading, setLoading] = useState(false);
  const [err, setErr]         = useState(null);
  const [pb, setPb]           = useState(null);

  const ordered = useMemo(() => [
    { key: 'executiveSummary',      title: 'Executive Summary' },
    { key: 'initialTriage',         title: 'Initial Triage' },
    { key: 'investigationSteps',    title: 'Investigation Steps' },
    { key: 'kql.validateDetection', title: 'KQL: Validate Detection' },
    { key: 'kql.lateralMovement',   title: 'KQL: Lateral Movement' },
    { key: 'kql.timeline',          title: 'KQL: Timeline' },
    { key: 'containment',           title: 'Containment' },
    { key: 'eradication',           title: 'Eradication' },
    { key: 'recovery',              title: 'Recovery' },
    { key: 'postIncident',          title: 'Post-Incident' },
    { key: 'mitreTactics',          title: 'MITRE ATT&CK' },
    { key: 'severityGuidance',      title: 'Severity Guidance' }
  ], []);

  const getPath = (obj, path) => path.split('.').reduce((a, k) => (a ? a[k] : undefined), obj || {});
  const mitre = MITRE_MAP[category] || null;

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
          environment: env,
          temperature // pass through to backend
        })
      });

      const text = await res.text();
      if (!res.ok) {
        try {
          const j = JSON.parse(text);
          throw new Error(j.error || text || `Request failed with ${res.status}`);
        } catch {
          throw new Error(text || `Request failed with ${res.status}`);
        }
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
  const sub  = darkMode ? 'text-gray-300' : 'text-gray-700';

  return (
    <div className={`rounded-lg shadow-md p-6 ${base}`}>
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold">🧰 IR Playbook Generator</h2>
          <p className={`text-sm ${sub}`}>Generates a full playbook in one request.</p>
        </div>
      </div>

      {/* Controls */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
        {/* Category (MITRE-aligned) */}
        <div>
          <label className={`block text-sm font-semibold mb-1 ${sub}`}>Category</label>
          <select
            value={category}
            onChange={(e) => setCategory(e.target.value)}
            className={`w-full px-3 py-2 rounded border ${darkMode ? 'bg-gray-700 border-gray-600' : 'bg-white border-gray-300'}`}
          >
            <optgroup label="Initial Access & Credential Theft">
              <option>Phishing</option>
              <option>Credential Theft</option>
              <option>Password Spray / Brute Force</option>
            </optgroup>

            <optgroup label="Execution & Persistence">
              <option>Malicious Script</option>
              <option>Persistence Mechanism</option>
              <option>Privilege Escalation</option>
            </optgroup>

            <optgroup label="Defense Evasion & Lateral Movement">
              <option>Defense Evasion</option>
              <option>Discovery</option>
              <option>Lateral Movement</option>
            </optgroup>

            <optgroup label="Collection, Exfiltration & Impact">
              <option>Data Collection</option>
              <option>Data Exfiltration</option>
              <option>Ransomware / Impact</option>
            </optgroup>

            <optgroup label="Specialized Scenarios">
              <option>Business Email Compromise</option>
              <option>Insider Threat</option>
              <option>Supply Chain / 3rd Party Breach</option>
              <option>Command & Control</option>
            </optgroup>
          </select>
          {/* Read-only MITRE label */}
          {mitre && (
            <div className={`mt-1 text-xs ${sub}`}>
              Mapped to MITRE tactic: <span className="font-semibold">{mitre.name}</span> ({mitre.id})
            </div>
          )}
        </div>

        <div>
          <label className={`block text-sm font-semibold mb-1 ${sub}`}>Severity</label>
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
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
            <input
              type="checkbox"
              checked={!!env[x.key]}
              onChange={(e) => setEnv(prev => ({ ...prev, [x.key]: e.target.checked }))}
            />
            <span className="text-sm">{x.label}</span>
          </label>
        ))}
      </div>

      {/* Prompt strength */}
      <div className="mb-4">
        <label className={`block text-sm font-semibold mb-1 ${sub}`}>Prompt strength</label>
        <div className="flex items-center gap-3">
          <span className="text-xs opacity-80">Conservative</span>
          <input
            type="range"
            min="0"
            max="1"
            step="0.05"
            value={temperature}
            onChange={(e) => setTemp(parseFloat(e.target.value))}
            className="w-full"
          />
          <span className="text-xs opacity-80">Creative</span>
          <span className="text-xs px-2 py-0.5 rounded bg-gray-200 text-gray-800">
            {temperature.toFixed(2)}
          </span>
        </div>
      </div>

      <button
        onClick={start}
        disabled={loading}
        className={`w-full py-3 px-6 rounded-lg font-semibold ${
          loading ? (darkMode ? 'bg-gray-700 text-gray-400' : 'bg-gray-200 text-gray-400')
                  : 'bg-blue-600 text-white hover:bg-blue-700'
        }`}
      >
        {loading ? 'Generating…' : 'Generate Playbook'}
      </button>

      {err && (
        <div className={`mt-4 p-4 rounded border ${darkMode ? 'bg-red-900 border-red-700 text-red-200' : 'bg-red-50 border-red-300 text-red-800'}`}>
          {err}
        </div>
      )}

      {pb && (
        <div className="mt-6 space-y-4">
          {ordered.map(item => {
            const val = getPath(pb, item.key);
            if (val == null) return null;

            // Arrays as bullet lists
            if (Array.isArray(val)) {
              return (
                <div key={item.key} className={`p-6 rounded-lg border ${darkMode ? 'bg-gray-700 border-gray-600' : 'bg-white border-gray-200'}`}>
                  <div className="flex items-center justify-between mb-3">
                    <h4 className="text-lg font-bold">{item.title}</h4>
                    <button
                      onClick={() => navigator.clipboard.writeText(val.join('\n'))}
                      className={`text-xs px-3 py-1 rounded ${darkMode ? 'bg-gray-600 hover:bg-gray-500' : 'bg-gray-100 hover:bg-gray-200'}`}
                    >
                      Copy
                    </button>
                  </div>
                  <ul className="list-disc ml-6">
                    {val.map((x, i) => (
                      <li key={i} className={sub} style={{ whiteSpace: 'pre-wrap' }}>{String(x)}</li>
                    ))}
                  </ul>
                </div>
              );
            }

            // Strings through SectionCard (handles ```kql)
            return <SectionCard key={item.key} title={item.title} content={String(val)} darkMode={darkMode} />;
          })}
        </div>
      )}
    </div>
  );
}