// /src/components/PromptEditor.jsx
import React, { useState, useEffect } from 'react';
import ReactMarkdown from 'react-markdown';

export default function PromptEditor({ darkMode, promptId, onBack }) {
  const isEdit = !!promptId;

  // Form state
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [category, setCategory] = useState('General');
  const [tags, setTags] = useState('');
  const [collection, setCollection] = useState('');
  const [systemGuidance, setSystemGuidance] = useState('');
  const [userInstructions, setUserInstructions] = useState('');
  const [variables, setVariables] = useState([]);
  const [temperature, setTemperature] = useState(0.7);
  const [maxTokens, setMaxTokens] = useState(2000);

  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);
  const [showPreview, setShowPreview] = useState(false);

  // Fetch existing prompt if editing
  useEffect(() => {
    if (isEdit) {
      fetchPrompt();
    } else {
      // Set example template for new prompts
      setUserInstructions('# Security Analysis Prompt\n\nAnalyze the following incident:\n\n{{context}}\n\n## Instructions\n\n1. Summarize the key findings\n2. Assess the severity level\n3. Recommend next steps');
    }
  }, [promptId]);

  const fetchPrompt = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(`/api/prompts/${promptId}`);
      if (!response.ok) throw new Error('Failed to fetch prompt');
      const data = await response.json();

      setTitle(data.title);
      setDescription(data.description);
      setCategory(data.category);
      setTags(data.tags.join(', '));
      setCollection(data.collection);
      setSystemGuidance(data.systemGuidance);
      setUserInstructions(data.userInstructions);
      setVariables(data.variables || []);
      setTemperature(data.modelSettings.temperature || 0.7);
      setMaxTokens(data.modelSettings.maxTokens || 2000);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async () => {
    // Validation
    if (!title.trim()) {
      alert('Title is required');
      return;
    }
    if (!userInstructions.trim()) {
      alert('User instructions are required');
      return;
    }

    setSaving(true);
    setError(null);

    try {
      const payload = {
        title,
        description,
        category,
        tags: tags.split(',').map(t => t.trim()).filter(Boolean),
        collection,
        systemGuidance,
        userInstructions,
        variables,
        modelSettings: { temperature, maxTokens }
      };

      const url = isEdit ? `/api/prompts/${promptId}` : '/api/prompts';
      const method = isEdit ? 'PUT' : 'POST';

      const response = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to save prompt');
      }

      alert(isEdit ? 'Prompt updated successfully!' : 'Prompt created successfully!');
      onBack();
    } catch (err) {
      setError(err.message);
    } finally {
      setSaving(false);
    }
  };

  // Variable management
  const addVariable = () => {
    setVariables([
      ...variables,
      { name: '', label: '', type: 'string', required: false, description: '' }
    ]);
  };

  const updateVariable = (index, field, value) => {
    const updated = [...variables];
    updated[index][field] = value;
    setVariables(updated);
  };

  const removeVariable = (index) => {
    setVariables(variables.filter((_, i) => i !== index));
  };

  const cardBg = darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200';
  const textPrimary = darkMode ? 'text-white' : 'text-gray-900';
  const textSecondary = darkMode ? 'text-gray-300' : 'text-gray-700';
  const textMuted = darkMode ? 'text-gray-400' : 'text-gray-500';
  const inputBg = darkMode ? 'bg-gray-700 border-gray-600 text-white' : 'bg-white border-gray-300 text-gray-900';
  const buttonPrimary = darkMode ? 'bg-blue-600 hover:bg-blue-700' : 'bg-blue-500 hover:bg-blue-600';
  const buttonSecondary = darkMode ? 'bg-gray-700 hover:bg-gray-600' : 'bg-gray-200 hover:bg-gray-300';

  if (loading) {
    return (
      <div className={`text-center py-12 ${textMuted}`}>
        <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
        <p className="mt-4">Loading prompt...</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className={`p-6 rounded-lg border ${cardBg}`}>
        <div className="flex items-center justify-between mb-4">
          <button onClick={onBack} className={`px-4 py-2 rounded font-semibold ${buttonSecondary} ${textPrimary}`}>
            ← Cancel
          </button>
          <div className="flex gap-2">
            <button
              onClick={() => setShowPreview(!showPreview)}
              className={`px-4 py-2 rounded font-semibold ${buttonSecondary} ${textPrimary}`}
            >
              {showPreview ? '📝 Edit' : '👁️ Preview'}
            </button>
            <button
              onClick={handleSave}
              disabled={saving}
              className={`px-6 py-2 rounded font-bold text-white ${saving ? 'bg-gray-500 cursor-not-allowed' : buttonPrimary}`}
            >
              {saving ? 'Saving...' : isEdit ? 'Update Prompt' : 'Create Prompt'}
            </button>
          </div>
        </div>

        <h2 className={`text-2xl font-bold ${textPrimary}`}>
          {isEdit ? '✏️ Edit Prompt' : '➕ New Prompt'}
        </h2>
      </div>

      {error && (
        <div className="p-4 rounded bg-red-500/10 border border-red-500/50 text-red-400">
          <strong>Error:</strong> {error}
        </div>
      )}

      {/* Basic Information */}
      <div className={`p-6 rounded-lg border ${cardBg}`}>
        <h3 className={`text-lg font-bold mb-4 ${textPrimary}`}>
          📋 Basic Information
        </h3>

        <div className="space-y-4">
          <div>
            <label className={`block text-sm font-medium mb-1 ${textSecondary}`}>
              Title <span className="text-red-500">*</span>
            </label>
            <input
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="e.g., Security Event Response Prompt"
              className={`w-full px-4 py-2 rounded border ${inputBg}`}
            />
          </div>

          <div>
            <label className={`block text-sm font-medium mb-1 ${textSecondary}`}>
              Description
            </label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Brief description of what this prompt does..."
              rows={2}
              className={`w-full px-4 py-2 rounded border ${inputBg}`}
            />
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className={`block text-sm font-medium mb-1 ${textSecondary}`}>
                Category
              </label>
              <select
                value={category}
                onChange={(e) => setCategory(e.target.value)}
                className={`w-full px-4 py-2 rounded border ${inputBg}`}
              >
                <option value="General">General</option>
                <option value="Incident Response">Incident Response</option>
                <option value="Threat Analysis">Threat Analysis</option>
                <option value="Forensics">Forensics</option>
                <option value="Compliance">Compliance</option>
                <option value="Client Communication">Client Communication</option>
                <option value="Triage">Triage</option>
              </select>
            </div>

            <div>
              <label className={`block text-sm font-medium mb-1 ${textSecondary}`}>
                Collection (Optional)
              </label>
              <input
                type="text"
                value={collection}
                onChange={(e) => setCollection(e.target.value)}
                placeholder="e.g., SOC Playbooks"
                className={`w-full px-4 py-2 rounded border ${inputBg}`}
              />
            </div>
          </div>

          <div>
            <label className={`block text-sm font-medium mb-1 ${textSecondary}`}>
              Tags (comma-separated)
            </label>
            <input
              type="text"
              value={tags}
              onChange={(e) => setTags(e.target.value)}
              placeholder="e.g., phishing, email, triage"
              className={`w-full px-4 py-2 rounded border ${inputBg}`}
            />
          </div>
        </div>
      </div>

      {/* Prompt Content */}
      <div className={`p-6 rounded-lg border ${cardBg}`}>
        <h3 className={`text-lg font-bold mb-4 ${textPrimary}`}>
          📝 Prompt Content
        </h3>

        <div className="space-y-4">
          <div>
            <label className={`block text-sm font-medium mb-1 ${textSecondary}`}>
              System Guidance (Optional)
            </label>
            <p className={`text-xs mb-2 ${textMuted}`}>
              Instructions for the AI on how to behave and respond
            </p>
            <textarea
              value={systemGuidance}
              onChange={(e) => setSystemGuidance(e.target.value)}
              placeholder="You are a senior security analyst helping with incident response..."
              rows={3}
              className={`w-full px-4 py-2 rounded border font-mono text-sm ${inputBg}`}
            />
          </div>

          <div>
            <label className={`block text-sm font-medium mb-1 ${textSecondary}`}>
              User Instructions <span className="text-red-500">*</span>
            </label>
            <p className={`text-xs mb-2 ${textMuted}`}>
              The main prompt template. Use placeholders like {`{{variable}}`}, {`{variable}`}, or {`[variable]`} for variables.
            </p>
            {showPreview ? (
              <div className={`p-4 rounded border ${inputBg} prose prose-sm max-w-none ${darkMode ? 'prose-invert' : ''}`}>
                <ReactMarkdown>{userInstructions}</ReactMarkdown>
              </div>
            ) : (
              <textarea
                value={userInstructions}
                onChange={(e) => setUserInstructions(e.target.value)}
                placeholder="# Analysis Task&#10;&#10;Analyze the following...&#10;&#10;{{context}}"
                rows={12}
                className={`w-full px-4 py-2 rounded border font-mono text-sm ${inputBg}`}
              />
            )}
          </div>
        </div>
      </div>

      {/* Variables */}
      <div className={`p-6 rounded-lg border ${cardBg}`}>
        <div className="flex items-center justify-between mb-4">
          <h3 className={`text-lg font-bold ${textPrimary}`}>
            🔧 Variables
          </h3>
          <button
            onClick={addVariable}
            className={`px-4 py-2 rounded font-semibold ${buttonSecondary} ${textPrimary}`}
          >
            + Add Variable
          </button>
        </div>

        {variables.length === 0 ? (
          <p className={textMuted}>No variables defined. Add variables for dynamic user input.</p>
        ) : (
          <div className="space-y-4">
            {variables.map((v, idx) => (
              <div key={idx} className={`p-4 rounded border ${darkMode ? 'border-gray-600' : 'border-gray-300'}`}>
                <div className="flex items-center justify-between mb-3">
                  <span className={`font-bold ${textSecondary}`}>Variable {idx + 1}</span>
                  <button
                    onClick={() => removeVariable(idx)}
                    className="text-red-500 hover:text-red-700 font-bold"
                  >
                    ✕ Remove
                  </button>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <div>
                    <label className={`block text-xs font-medium mb-1 ${textMuted}`}>Name (key)</label>
                    <input
                      type="text"
                      value={v.name}
                      onChange={(e) => updateVariable(idx, 'name', e.target.value)}
                      placeholder="e.g., username"
                      className={`w-full px-3 py-1 text-sm rounded border ${inputBg}`}
                    />
                  </div>

                  <div>
                    <label className={`block text-xs font-medium mb-1 ${textMuted}`}>Label (display)</label>
                    <input
                      type="text"
                      value={v.label}
                      onChange={(e) => updateVariable(idx, 'label', e.target.value)}
                      placeholder="e.g., Username"
                      className={`w-full px-3 py-1 text-sm rounded border ${inputBg}`}
                    />
                  </div>

                  <div>
                    <label className={`block text-xs font-medium mb-1 ${textMuted}`}>Type</label>
                    <select
                      value={v.type}
                      onChange={(e) => updateVariable(idx, 'type', e.target.value)}
                      className={`w-full px-3 py-1 text-sm rounded border ${inputBg}`}
                    >
                      <option value="string">String</option>
                      <option value="text">Text (multiline)</option>
                      <option value="number">Number</option>
                      <option value="boolean">Boolean</option>
                      <option value="enum">Enum (select)</option>
                    </select>
                  </div>

                  <div className="flex items-center pt-5">
                    <label className="flex items-center">
                      <input
                        type="checkbox"
                        checked={v.required}
                        onChange={(e) => updateVariable(idx, 'required', e.target.checked)}
                        className="mr-2"
                      />
                      <span className={`text-sm ${textSecondary}`}>Required</span>
                    </label>
                  </div>

                  <div className="md:col-span-2">
                    <label className={`block text-xs font-medium mb-1 ${textMuted}`}>Description</label>
                    <input
                      type="text"
                      value={v.description}
                      onChange={(e) => updateVariable(idx, 'description', e.target.value)}
                      placeholder="Help text for this variable"
                      className={`w-full px-3 py-1 text-sm rounded border ${inputBg}`}
                    />
                  </div>

                  {v.type === 'enum' && (
                    <div className="md:col-span-2">
                      <label className={`block text-xs font-medium mb-1 ${textMuted}`}>Options (comma-separated)</label>
                      <input
                        type="text"
                        value={v.options ? v.options.join(', ') : ''}
                        onChange={(e) => updateVariable(idx, 'options', e.target.value.split(',').map(s => s.trim()))}
                        placeholder="e.g., Low, Medium, High, Critical"
                        className={`w-full px-3 py-1 text-sm rounded border ${inputBg}`}
                      />
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Model Settings */}
      <div className={`p-6 rounded-lg border ${cardBg}`}>
        <h3 className={`text-lg font-bold mb-4 ${textPrimary}`}>
          ⚙️ Model Settings
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className={`block text-sm font-medium mb-1 ${textSecondary}`}>
              Temperature (0-1)
            </label>
            <input
              type="number"
              min="0"
              max="1"
              step="0.1"
              value={temperature}
              onChange={(e) => setTemperature(parseFloat(e.target.value))}
              className={`w-full px-4 py-2 rounded border ${inputBg}`}
            />
            <p className={`text-xs mt-1 ${textMuted}`}>Lower = more focused, Higher = more creative</p>
          </div>

          <div>
            <label className={`block text-sm font-medium mb-1 ${textSecondary}`}>
              Max Tokens
            </label>
            <input
              type="number"
              min="100"
              max="8000"
              step="100"
              value={maxTokens}
              onChange={(e) => setMaxTokens(parseInt(e.target.value))}
              className={`w-full px-4 py-2 rounded border ${inputBg}`}
            />
            <p className={`text-xs mt-1 ${textMuted}`}>Maximum length of the response</p>
          </div>
        </div>
      </div>

      {/* Save Button (bottom) */}
      <div className="flex justify-end gap-2">
        <button onClick={onBack} className={`px-6 py-3 rounded font-bold ${buttonSecondary} ${textPrimary}`}>
          Cancel
        </button>
        <button
          onClick={handleSave}
          disabled={saving}
          className={`px-6 py-3 rounded font-bold text-white ${saving ? 'bg-gray-500 cursor-not-allowed' : buttonPrimary}`}
        >
          {saving ? 'Saving...' : isEdit ? 'Update Prompt' : 'Create Prompt'}
        </button>
      </div>
    </div>
  );
}
