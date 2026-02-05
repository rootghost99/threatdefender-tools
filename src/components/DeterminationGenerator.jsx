import React, { useState, useCallback } from 'react';
import { motion } from 'framer-motion';

// Update this if your API base URL changes
const API_BASE_URL = '/api';

const DETECTION_TYPES = [
  'Anomalous Sign-In Activity',
  'Impossible Travel',
  'Suspicious Inbox Rule',
  'Malware Detection',
  'Phishing Email Reported',
  'MFA Fraud Alert',
  'Conditional Access Policy Change',
  'Privilege Escalation',
  'Data Exfiltration Attempt',
  'Suspicious PowerShell Execution',
  'Brute Force Attempt',
  'Other'
];

const DETERMINATIONS = [
  'Benign Positive',
  'True Positive',
  'False Positive'
];

export default function DeterminationGenerator({ darkMode }) {
  const [detectionType, setDetectionType] = useState('');
  const [customDetectionType, setCustomDetectionType] = useState('');
  const [determination, setDetermination] = useState('');
  const [clientName, setClientName] = useState('');
  const [internalNotes, setInternalNotes] = useState('');
  const [aiTriageNotes, setAiTriageNotes] = useState('');
  const [result, setResult] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [copied, setCopied] = useState(false);

  const isFormValid = (detectionType === 'Other' ? customDetectionType.trim() : detectionType) &&
    determination && clientName.trim() && internalNotes.trim();

  const handleGenerate = useCallback(async () => {
    if (!isFormValid) return;

    setLoading(true);
    setError(null);
    setResult('');

    try {
      const resp = await fetch(`${API_BASE_URL}/generate-determination`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          detectionType: detectionType === 'Other' ? customDetectionType.trim() : detectionType,
          determination,
          clientName: clientName.trim(),
          internalNotes: internalNotes.trim(),
          aiTriageNotes: aiTriageNotes.trim()
        })
      });

      const data = await resp.json();

      if (!resp.ok) {
        throw new Error(data.error || `Request failed with status ${resp.status}`);
      }

      setResult(data.result);
    } catch (err) {
      setError(err.message || 'An unexpected error occurred');
    } finally {
      setLoading(false);
    }
  }, [detectionType, customDetectionType, determination, clientName, internalNotes, aiTriageNotes, isFormValid]);

  const handleCopy = useCallback(() => {
    if (!result) return;
    navigator.clipboard.writeText(result).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }, [result]);

  const handleReset = useCallback(() => {
    setDetectionType('');
    setCustomDetectionType('');
    setDetermination('');
    setClientName('');
    setInternalNotes('');
    setAiTriageNotes('');
    setResult('');
    setError(null);
    setCopied(false);
  }, []);

  const cardBg = darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200';
  const inputBg = darkMode ? 'bg-gray-900 border-gray-600 text-white placeholder-gray-500' : 'bg-white border-gray-300 text-gray-900 placeholder-gray-400';
  const labelColor = darkMode ? 'text-gray-300' : 'text-gray-700';
  const textColor = darkMode ? 'text-white' : 'text-gray-900';
  const subText = darkMode ? 'text-gray-400' : 'text-gray-600';

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className={`text-2xl font-bold ${textColor}`}>Determination Generator</h2>
        <p className={`text-sm mt-1 ${subText}`}>
          Generate client-facing determination summaries from internal investigation notes
        </p>
      </div>

      {/* Form */}
      <div className={`rounded-lg border ${cardBg} p-6 space-y-5`}>
        {/* Detection Type */}
        <div>
          <label className={`block text-sm font-medium mb-1.5 ${labelColor}`}>
            Detection Type
          </label>
          <select
            value={detectionType}
            onChange={(e) => setDetectionType(e.target.value)}
            className={`w-full px-3 py-2 rounded-lg border text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 ${inputBg}`}
          >
            <option value="">Select detection type...</option>
            {DETECTION_TYPES.map((type) => (
              <option key={type} value={type}>{type}</option>
            ))}
          </select>
          {detectionType === 'Other' && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="mt-2"
            >
              <input
                type="text"
                value={customDetectionType}
                onChange={(e) => setCustomDetectionType(e.target.value)}
                placeholder="Enter custom detection type..."
                className={`w-full px-3 py-2 rounded-lg border text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 ${inputBg}`}
              />
            </motion.div>
          )}
        </div>

        {/* Determination */}
        <div>
          <label className={`block text-sm font-medium mb-1.5 ${labelColor}`}>
            Determination
          </label>
          <select
            value={determination}
            onChange={(e) => setDetermination(e.target.value)}
            className={`w-full px-3 py-2 rounded-lg border text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 ${inputBg}`}
          >
            <option value="">Select determination...</option>
            {DETERMINATIONS.map((d) => (
              <option key={d} value={d}>{d}</option>
            ))}
          </select>
        </div>

        {/* Client Name */}
        <div>
          <label className={`block text-sm font-medium mb-1.5 ${labelColor}`}>
            Client Name
          </label>
          <input
            type="text"
            value={clientName}
            onChange={(e) => setClientName(e.target.value)}
            placeholder="Enter client name..."
            className={`w-full px-3 py-2 rounded-lg border text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 ${inputBg}`}
          />
        </div>

        {/* Internal Analyst Notes */}
        <div>
          <label className={`block text-sm font-medium mb-1.5 ${labelColor}`}>
            Internal Analyst Notes
          </label>
          <textarea
            value={internalNotes}
            onChange={(e) => setInternalNotes(e.target.value)}
            placeholder="Paste your internal analyst notes here..."
            rows={6}
            className={`w-full px-3 py-2 rounded-lg border text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 resize-y ${inputBg}`}
          />
        </div>

        {/* AI Triage Notes */}
        <div>
          <label className={`block text-sm font-medium mb-1.5 ${labelColor}`}>
            AI Triage Notes
          </label>
          <textarea
            value={aiTriageNotes}
            onChange={(e) => setAiTriageNotes(e.target.value)}
            placeholder="Paste your AI triage bot notes here..."
            rows={6}
            className={`w-full px-3 py-2 rounded-lg border text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 resize-y ${inputBg}`}
          />
        </div>

        {/* Generate Button */}
        <div className="flex items-center gap-3">
          <motion.button
            whileHover={{ y: -1 }}
            whileTap={{ y: 0 }}
            onClick={handleGenerate}
            disabled={!isFormValid || loading}
            className={`px-5 py-2.5 rounded-lg text-sm font-medium transition-colors ${
              isFormValid && !loading
                ? 'bg-blue-600 hover:bg-blue-700 text-white'
                : 'bg-gray-600 text-gray-400 cursor-not-allowed'
            }`}
          >
            {loading ? (
              <span className="flex items-center gap-2">
                <span className="inline-block w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                Generating...
              </span>
            ) : (
              'Generate Determination'
            )}
          </motion.button>

          <motion.button
            whileHover={{ y: -1 }}
            whileTap={{ y: 0 }}
            onClick={handleReset}
            className={`px-4 py-2.5 rounded-lg text-sm font-medium transition-colors ${
              darkMode
                ? 'bg-gray-700 hover:bg-gray-600 text-gray-300'
                : 'bg-gray-200 hover:bg-gray-300 text-gray-700'
            }`}
          >
            Clear / Reset
          </motion.button>
        </div>
      </div>

      {/* Error Display */}
      {error && (
        <motion.div
          initial={{ opacity: 0, y: -8 }}
          animate={{ opacity: 1, y: 0 }}
          className="rounded-lg border border-red-500/50 bg-red-500/10 p-4"
        >
          <p className="text-sm text-red-400 font-medium">Error</p>
          <p className="text-sm text-red-300 mt-1">{error}</p>
        </motion.div>
      )}

      {/* Result Output */}
      {result && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          className={`rounded-lg border ${cardBg} p-6 space-y-4`}
        >
          <div className="flex items-center justify-between">
            <h3 className={`text-lg font-semibold ${textColor}`}>Generated Determination</h3>
            <motion.button
              whileHover={{ y: -1 }}
              whileTap={{ y: 0 }}
              onClick={handleCopy}
              className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                copied
                  ? 'bg-green-600 text-white'
                  : darkMode
                    ? 'bg-gray-700 hover:bg-gray-600 text-gray-300'
                    : 'bg-gray-200 hover:bg-gray-300 text-gray-700'
              }`}
            >
              {copied ? 'Copied!' : 'Copy to Clipboard'}
            </motion.button>
          </div>
          <textarea
            readOnly
            value={result}
            rows={8}
            className={`w-full px-3 py-2 rounded-lg border text-sm resize-y ${
              darkMode
                ? 'bg-gray-900 border-gray-600 text-gray-200'
                : 'bg-gray-50 border-gray-300 text-gray-800'
            }`}
          />
        </motion.div>
      )}
    </div>
  );
}
