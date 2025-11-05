// /src/components/PromptDetail.jsx
import React, { useState, useEffect } from 'react';
import ReactMarkdown from 'react-markdown';

export default function PromptDetail({ darkMode, promptId, onBack, onEdit }) {
  const [prompt, setPrompt] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Form state
  const [context, setContext] = useState('');
  const [variables, setVariables] = useState({});
  const [running, setRunning] = useState(false);
  const [output, setOutput] = useState(null);
  const [runError, setRunError] = useState(null);
  const [usage, setUsage] = useState(null);

  // Fetch prompt details
  useEffect(() => {
    fetchPrompt();
  }, [promptId]);

  const fetchPrompt = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(`/api/prompts/${promptId}`);
      if (!response.ok) throw new Error('Failed to fetch prompt');
      const data = await response.json();
      setPrompt(data);

      // Initialize variables
      const initialVars = {};
      if (data.variables) {
        data.variables.forEach(v => {
          initialVars[v.name] = v.defaultValue || '';
        });
      }
      setVariables(initialVars);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // Run prompt
  const handleRun = async () => {
    setRunning(true);
    setRunError(null);
    setOutput(null);
    setUsage(null);

    try {
      const response = await fetch(`/api/prompts/${promptId}/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ context, variables })
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to run prompt');
      }

      const data = await response.json();
      setOutput(data.output);
      setUsage(data.usage);
    } catch (err) {
      setRunError(err.message);
    } finally {
      setRunning(false);
    }
  };

  // Copy output to clipboard
  const copyOutput = () => {
    if (output) {
      navigator.clipboard.writeText(output);
    }
  };

  // Delete prompt
  const handleDelete = async () => {
    if (!window.confirm('Are you sure you want to delete this prompt? This action cannot be undone.')) {
      return;
    }

    try {
      const response = await fetch(`/api/prompts/${promptId}`, {
        method: 'DELETE'
      });

      if (!response.ok) throw new Error('Failed to delete prompt');

      alert('Prompt deleted successfully');
      onBack();
    } catch (err) {
      alert(`Error deleting prompt: ${err.message}`);
    }
  };

  const cardBg = darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200';
  const textPrimary = darkMode ? 'text-white' : 'text-gray-900';
  const textSecondary = darkMode ? 'text-gray-300' : 'text-gray-700';
  const textMuted = darkMode ? 'text-gray-400' : 'text-gray-500';
  const inputBg = darkMode ? 'bg-gray-700 border-gray-600 text-white' : 'bg-white border-gray-300 text-gray-900';
  const buttonPrimary = darkMode ? 'bg-blue-600 hover:bg-blue-700' : 'bg-blue-500 hover:bg-blue-600';
  const buttonSecondary = darkMode ? 'bg-gray-700 hover:bg-gray-600' : 'bg-gray-200 hover:bg-gray-300';
  const buttonDanger = darkMode ? 'bg-red-700 hover:bg-red-800' : 'bg-red-500 hover:bg-red-600';

  if (loading) {
    return (
      <div className={`text-center py-12 ${textMuted}`}>
        <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
        <p className="mt-4">Loading prompt...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="space-y-4">
        <button onClick={onBack} className={`px-4 py-2 rounded font-semibold ${buttonSecondary} ${textPrimary}`}>
          ← Back to Gallery
        </button>
        <div className="p-4 rounded bg-red-500/10 border border-red-500/50 text-red-400">
          <strong>Error:</strong> {error}
        </div>
      </div>
    );
  }

  if (!prompt) return null;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className={`p-6 rounded-lg border ${cardBg}`}>
        <div className="flex items-center justify-between mb-4">
          <button onClick={onBack} className={`px-4 py-2 rounded font-semibold ${buttonSecondary} ${textPrimary}`}>
            ← Back to Gallery
          </button>
          <div className="flex gap-2">
            <button
              onClick={() => onEdit(promptId)}
              className={`px-4 py-2 rounded font-semibold ${buttonSecondary} ${textPrimary}`}
            >
              ✏️ Edit
            </button>
            <button
              onClick={handleDelete}
              className={`px-4 py-2 rounded font-semibold text-white ${buttonDanger}`}
            >
              🗑️ Delete
            </button>
          </div>
        </div>

        <h2 className={`text-2xl font-bold mb-2 ${textPrimary}`}>
          {prompt.title}
        </h2>
        <p className={`${textSecondary} mb-4`}>
          {prompt.description}
        </p>

        {/* Metadata */}
        <div className="flex flex-wrap gap-2 mb-4">
          <span className={`text-xs px-2 py-1 rounded ${darkMode ? 'bg-blue-900/50 text-blue-300' : 'bg-blue-100 text-blue-700'}`}>
            {prompt.category}
          </span>
          {prompt.collection && (
            <span className={`text-xs px-2 py-1 rounded ${darkMode ? 'bg-purple-900/50 text-purple-300' : 'bg-purple-100 text-purple-700'}`}>
              {prompt.collection}
            </span>
          )}
          {prompt.tags.map((tag, idx) => (
            <span key={idx} className={`text-xs px-2 py-1 rounded ${darkMode ? 'bg-gray-700 text-gray-300' : 'bg-gray-200 text-gray-700'}`}>
              #{tag}
            </span>
          ))}
        </div>

        <div className={`text-xs ${textMuted}`}>
          Created by {prompt.createdBy} on {new Date(prompt.createdAt).toLocaleDateString()}
          {prompt.updatedBy && ` • Updated by ${prompt.updatedBy} on ${new Date(prompt.updatedAt).toLocaleDateString()}`}
        </div>
      </div>

      {/* Prompt Template Preview */}
      <div className={`p-6 rounded-lg border ${cardBg}`}>
        <h3 className={`text-lg font-bold mb-4 ${textPrimary}`}>
          📝 Prompt Instructions
        </h3>
        <div className={`prose prose-sm max-w-none ${darkMode ? 'prose-invert' : ''}`}>
          <ReactMarkdown>{prompt.userInstructions}</ReactMarkdown>
        </div>
      </div>

      {/* Context Input */}
      <div className={`p-6 rounded-lg border ${cardBg}`}>
        <h3 className={`text-lg font-bold mb-2 ${textPrimary}`}>
          📋 Incident Context (Optional)
        </h3>
        <p className={`text-sm mb-4 ${textMuted}`}>
          Paste relevant incident data, logs, or context here. Remember to redact sensitive information (credentials, PII, secrets).
        </p>
        <textarea
          value={context}
          onChange={(e) => setContext(e.target.value)}
          placeholder="Paste incident details, Sentinel logs, IP addresses, user information, etc..."
          rows={8}
          className={`w-full px-4 py-2 rounded border font-mono text-sm ${inputBg}`}
        />
        <div className={`text-xs mt-2 ${textMuted}`}>
          {context.length} characters {context.length > 5000 && '(Consider summarizing for better results)'}
        </div>
      </div>

      {/* Variables */}
      {prompt.variables && prompt.variables.length > 0 && (
        <div className={`p-6 rounded-lg border ${cardBg}`}>
          <h3 className={`text-lg font-bold mb-4 ${textPrimary}`}>
            🔧 Variables
          </h3>
          <div className="space-y-4">
            {prompt.variables.map((varDef, idx) => (
              <div key={idx}>
                <label className={`block text-sm font-medium mb-1 ${textSecondary}`}>
                  {varDef.label || varDef.name}
                  {varDef.required && <span className="text-red-500 ml-1">*</span>}
                </label>
                {varDef.description && (
                  <p className={`text-xs mb-2 ${textMuted}`}>{varDef.description}</p>
                )}
                {varDef.type === 'boolean' ? (
                  <input
                    type="checkbox"
                    checked={variables[varDef.name] || false}
                    onChange={(e) => setVariables({ ...variables, [varDef.name]: e.target.checked })}
                    className="w-4 h-4"
                  />
                ) : varDef.type === 'enum' && varDef.options ? (
                  <select
                    value={variables[varDef.name] || ''}
                    onChange={(e) => setVariables({ ...variables, [varDef.name]: e.target.value })}
                    className={`w-full px-4 py-2 rounded border ${inputBg}`}
                  >
                    <option value="">Select...</option>
                    {varDef.options.map((opt, i) => (
                      <option key={i} value={opt}>{opt}</option>
                    ))}
                  </select>
                ) : varDef.type === 'text' ? (
                  <textarea
                    value={variables[varDef.name] || ''}
                    onChange={(e) => setVariables({ ...variables, [varDef.name]: e.target.value })}
                    rows={3}
                    className={`w-full px-4 py-2 rounded border ${inputBg}`}
                  />
                ) : (
                  <input
                    type={varDef.type === 'number' ? 'number' : 'text'}
                    value={variables[varDef.name] || ''}
                    onChange={(e) => setVariables({ ...variables, [varDef.name]: e.target.value })}
                    className={`w-full px-4 py-2 rounded border ${inputBg}`}
                  />
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Run Button */}
      <div className="flex justify-end">
        <button
          onClick={handleRun}
          disabled={running}
          className={`px-6 py-3 rounded font-bold text-white ${running ? 'bg-gray-500 cursor-not-allowed' : buttonPrimary}`}
        >
          {running ? '⏳ Running...' : '▶️ Run Prompt'}
        </button>
      </div>

      {/* Run Error */}
      {runError && (
        <div className="p-4 rounded bg-red-500/10 border border-red-500/50 text-red-400">
          <strong>Error:</strong> {runError}
        </div>
      )}

      {/* Output */}
      {output && (
        <div className={`p-6 rounded-lg border ${cardBg}`}>
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className={`text-lg font-bold ${textPrimary}`}>
                ✨ Output
              </h3>
              {usage && (
                <p className={`text-xs mt-1 ${textMuted}`}>
                  Tokens: {usage.promptTokens} prompt + {usage.completionTokens} completion = {usage.totalTokens} total
                </p>
              )}
            </div>
            <button
              onClick={copyOutput}
              className={`px-4 py-2 rounded font-semibold ${buttonSecondary} ${textPrimary}`}
            >
              📋 Copy
            </button>
          </div>
          <div className={`prose prose-sm max-w-none ${darkMode ? 'prose-invert' : ''}`}>
            <ReactMarkdown>{output}</ReactMarkdown>
          </div>
        </div>
      )}
    </div>
  );
}
