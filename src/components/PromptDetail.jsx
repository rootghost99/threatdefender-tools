// /src/components/PromptDetail.jsx
import React, { useState, useEffect, useCallback } from 'react';
import ReactMarkdown from 'react-markdown';
import { useAuth } from '../contexts/AuthContext';

export default function PromptDetail({ darkMode, promptId, onBack, onEdit }) {
  const { isAuthenticated, getSentinelWorkspaces, getSentinelIncident, getIncidentLogs } = useAuth();

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

  // Sentinel incident loader state
  const [workspaces, setWorkspaces] = useState([]);
  const [workspacesLoading, setWorkspacesLoading] = useState(false);
  const [workspacesError, setWorkspacesError] = useState(null);
  const [selectedWorkspace, setSelectedWorkspace] = useState('');
  const [incidentNumber, setIncidentNumber] = useState('');
  const [incidentLoading, setIncidentLoading] = useState(false);
  const [incidentError, setIncidentError] = useState(null);
  const [showSentinelLoader, setShowSentinelLoader] = useState(false);

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

  // Load Sentinel workspaces when the loader is shown
  useEffect(() => {
    async function loadWorkspaces() {
      if (!showSentinelLoader || !isAuthenticated || workspaces.length > 0) return;

      setWorkspacesLoading(true);
      setWorkspacesError(null);
      try {
        const ws = await getSentinelWorkspaces((progressWorkspaces) => {
          setWorkspaces(progressWorkspaces);
        });
        setWorkspaces(ws);
        // Auto-select first workspace if only one
        if (ws.length === 1) {
          setSelectedWorkspace(ws[0].id);
        }
      } catch (err) {
        console.error('Failed to load workspaces:', err);
        setWorkspacesError(err.message || 'Failed to load workspaces');
      } finally {
        setWorkspacesLoading(false);
      }
    }

    loadWorkspaces();
  }, [showSentinelLoader, isAuthenticated, getSentinelWorkspaces, workspaces.length]);

  // Fetch incident from Sentinel
  const fetchIncident = useCallback(async () => {
    if (!selectedWorkspace || !incidentNumber.trim()) {
      setIncidentError('Please select a workspace and enter an incident number');
      return;
    }

    setIncidentLoading(true);
    setIncidentError(null);

    try {
      // Get incident details, alerts, and entities
      const { incident, alerts, entities } = await getSentinelIncident(selectedWorkspace, incidentNumber.trim());

      // Get workspace customerId for Log Analytics queries
      const workspace = workspaces.find(w => w.id === selectedWorkspace);

      // Try to get additional logs from Log Analytics
      let logs = null;
      if (workspace?.customerId && getIncidentLogs) {
        try {
          logs = await getIncidentLogs(workspace.customerId, incidentNumber.trim());
        } catch (logErr) {
          console.warn('Could not fetch Log Analytics data:', logErr);
        }
      }

      // Format the incident data as JSON for the context
      const incidentData = {
        incident: {
          id: incident.name,
          title: incident.properties?.title,
          description: incident.properties?.description,
          severity: incident.properties?.severity,
          status: incident.properties?.status,
          classification: incident.properties?.classification,
          classificationComment: incident.properties?.classificationComment,
          owner: incident.properties?.owner,
          labels: incident.properties?.labels,
          tactics: incident.properties?.additionalData?.tactics,
          techniques: incident.properties?.additionalData?.techniques,
          alertsCount: incident.properties?.additionalData?.alertsCount,
          createdTimeUtc: incident.properties?.createdTimeUtc,
          lastModifiedTimeUtc: incident.properties?.lastModifiedTimeUtc,
        },
        alerts: alerts.map(alert => ({
          id: alert.properties?.systemAlertId,
          name: alert.properties?.alertDisplayName,
          description: alert.properties?.description,
          severity: alert.properties?.severity,
          status: alert.properties?.status,
          providerName: alert.properties?.providerAlertId,
          tactics: alert.properties?.tactics,
          techniques: alert.properties?.techniques,
          timeGenerated: alert.properties?.timeGenerated,
          entities: alert.properties?.entities,
        })),
        entities: entities.map(entity => ({
          type: entity.kind,
          ...entity.properties,
        })),
        logAnalyticsData: logs,
      };

      // Set the context with formatted JSON
      setContext(JSON.stringify(incidentData, null, 2));

      // Auto-populate severity variable if it exists
      if (incident.properties?.severity) {
        const severityMap = {
          'Informational': 'Low',
          'Low': 'Low',
          'Medium': 'Medium',
          'High': 'High',
          'Critical': 'Critical'
        };
        const mappedSeverity = severityMap[incident.properties.severity] || incident.properties.severity;
        setVariables(prev => ({
          ...prev,
          severity: mappedSeverity
        }));
      }

      // Close the Sentinel loader panel
      setShowSentinelLoader(false);

    } catch (err) {
      console.error('Failed to fetch incident:', err);
      setIncidentError(`Failed to fetch incident: ${err.message}`);
    } finally {
      setIncidentLoading(false);
    }
  }, [selectedWorkspace, incidentNumber, workspaces, getSentinelIncident, getIncidentLogs]);

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

  // Copy specific section to clipboard
  const copySection = (sectionTitle) => {
    if (!output) return;

    // Find section by looking for headers (## or ###)
    const lines = output.split('\n');
    let inSection = false;
    let sectionContent = [];

    for (const line of lines) {
      // Check if this is the target section header
      if (line.match(/^#{2,3}\s/) && line.toLowerCase().includes(sectionTitle.toLowerCase())) {
        inSection = true;
        sectionContent.push(line);
        continue;
      }
      // Check if we've hit the next section
      if (inSection && line.match(/^#{2,3}\s/)) {
        break;
      }
      if (inSection) {
        sectionContent.push(line);
      }
    }

    if (sectionContent.length > 0) {
      navigator.clipboard.writeText(sectionContent.join('\n').trim());
    }
  };

  // Check if output contains dual sections (client + internal)
  const hasDualOutput = output &&
    (output.toLowerCase().includes('client-facing') || output.toLowerCase().includes('client facing')) &&
    (output.toLowerCase().includes('internal') || output.toLowerCase().includes('ticket notes'));

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
          {prompt.tags && prompt.tags.map((tag, idx) => (
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
        <div className="flex items-center justify-between mb-2">
          <h3 className={`text-lg font-bold ${textPrimary}`}>
            📋 Incident Context (Optional)
          </h3>
          {isAuthenticated && (
            <button
              onClick={() => setShowSentinelLoader(!showSentinelLoader)}
              className={`px-3 py-1.5 rounded font-semibold text-sm ${showSentinelLoader
                ? (darkMode ? 'bg-blue-600 text-white' : 'bg-blue-500 text-white')
                : (darkMode ? 'bg-blue-900/50 text-blue-300 hover:bg-blue-800' : 'bg-blue-100 text-blue-700 hover:bg-blue-200')
              }`}
            >
              🔷 {showSentinelLoader ? 'Hide Sentinel Loader' : 'Load from Sentinel'}
            </button>
          )}
        </div>

        {/* Sentinel Incident Loader */}
        {showSentinelLoader && isAuthenticated && (
          <div className={`mb-4 p-4 rounded-lg border ${darkMode ? 'bg-blue-900/20 border-blue-800' : 'bg-blue-50 border-blue-200'}`}>
            <p className={`text-sm mb-3 ${textSecondary}`}>
              Load incident data directly from Microsoft Sentinel. Select a workspace and enter the incident number.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-3">
              {/* Workspace Selector */}
              <div className="md:col-span-1">
                <label className={`block text-xs font-medium mb-1 ${textMuted}`}>
                  Sentinel Workspace
                </label>
                <select
                  value={selectedWorkspace}
                  onChange={(e) => setSelectedWorkspace(e.target.value)}
                  disabled={workspacesLoading || workspaces.length === 0}
                  className={`w-full px-3 py-2 rounded border text-sm ${inputBg} ${workspacesLoading ? 'opacity-50' : ''}`}
                >
                  <option value="">
                    {workspacesLoading ? 'Loading workspaces...' : workspaces.length === 0 ? 'No workspaces found' : 'Select workspace...'}
                  </option>
                  {workspaces.map((ws) => (
                    <option key={ws.id} value={ws.id}>
                      {ws.name} ({ws.subscriptionName})
                    </option>
                  ))}
                </select>
              </div>

              {/* Incident Number */}
              <div className="md:col-span-1">
                <label className={`block text-xs font-medium mb-1 ${textMuted}`}>
                  Incident Number
                </label>
                <input
                  type="text"
                  value={incidentNumber}
                  onChange={(e) => setIncidentNumber(e.target.value)}
                  placeholder="e.g., 12345"
                  className={`w-full px-3 py-2 rounded border text-sm ${inputBg}`}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && selectedWorkspace && incidentNumber.trim()) {
                      fetchIncident();
                    }
                  }}
                />
              </div>

              {/* Load Button */}
              <div className="md:col-span-1 flex items-end">
                <button
                  onClick={fetchIncident}
                  disabled={incidentLoading || !selectedWorkspace || !incidentNumber.trim()}
                  className={`w-full px-4 py-2 rounded font-semibold text-sm text-white ${
                    incidentLoading || !selectedWorkspace || !incidentNumber.trim()
                      ? 'bg-gray-500 cursor-not-allowed'
                      : 'bg-blue-600 hover:bg-blue-700'
                  }`}
                >
                  {incidentLoading ? '⏳ Loading...' : '📥 Load Incident'}
                </button>
              </div>
            </div>

            {/* Workspace Error */}
            {workspacesError && (
              <div className="p-2 rounded text-sm bg-red-500/10 border border-red-500/50 text-red-400 mb-2">
                {workspacesError}
              </div>
            )}

            {/* Incident Error */}
            {incidentError && (
              <div className="p-2 rounded text-sm bg-red-500/10 border border-red-500/50 text-red-400">
                {incidentError}
              </div>
            )}
          </div>
        )}

        {/* Not authenticated message */}
        {!isAuthenticated && (
          <p className={`text-sm mb-4 ${textMuted}`}>
            Paste relevant incident data, logs, or context here. <span className={darkMode ? 'text-blue-400' : 'text-blue-600'}>Sign in to load incidents directly from Sentinel.</span>
          </p>
        )}

        {isAuthenticated && !showSentinelLoader && (
          <p className={`text-sm mb-4 ${textMuted}`}>
            Paste relevant incident data, or use the "Load from Sentinel" button above to pull incident data directly.
          </p>
        )}

        {showSentinelLoader && (
          <p className={`text-sm mb-4 ${textMuted}`}>
            Or paste incident data manually below:
          </p>
        )}

        <textarea
          value={context}
          onChange={(e) => setContext(e.target.value)}
          placeholder="Paste incident details, Sentinel logs, IP addresses, user information, etc..."
          rows={8}
          className={`w-full px-4 py-2 rounded border font-mono text-sm ${inputBg}`}
        />
        <div className={`flex justify-between text-xs mt-2 ${textMuted}`}>
          <span>
            {context.length} characters {context.length > 5000 && '(Consider summarizing for better results)'}
          </span>
          {context && (
            <button
              onClick={() => setContext('')}
              className="text-red-400 hover:text-red-300"
            >
              Clear context
            </button>
          )}
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
            <div className="flex gap-2 flex-wrap justify-end">
              {hasDualOutput && (
                <>
                  <button
                    onClick={() => copySection('client-facing')}
                    className={`px-3 py-2 rounded font-semibold text-sm ${darkMode ? 'bg-green-700 hover:bg-green-600 text-white' : 'bg-green-100 hover:bg-green-200 text-green-800'}`}
                    title="Copy client-facing notes only"
                  >
                    📤 Copy Client Notes
                  </button>
                  <button
                    onClick={() => copySection('internal')}
                    className={`px-3 py-2 rounded font-semibold text-sm ${darkMode ? 'bg-yellow-700 hover:bg-yellow-600 text-white' : 'bg-yellow-100 hover:bg-yellow-200 text-yellow-800'}`}
                    title="Copy internal ticket notes only"
                  >
                    📝 Copy Internal Notes
                  </button>
                </>
              )}
              <button
                onClick={copyOutput}
                className={`px-4 py-2 rounded font-semibold ${buttonSecondary} ${textPrimary}`}
              >
                📋 Copy All
              </button>
            </div>
          </div>
          {hasDualOutput && (
            <div className={`mb-4 p-3 rounded text-sm ${darkMode ? 'bg-blue-900/30 text-blue-300 border border-blue-700' : 'bg-blue-50 text-blue-700 border border-blue-200'}`}>
              💡 <strong>Tip:</strong> This output contains separate sections for client-facing and internal notes. Use the buttons above to copy each section individually.
            </div>
          )}
          <div className={`prose prose-sm max-w-none ${darkMode ? 'prose-invert [&_*]:text-gray-100 [&_code]:bg-gray-700 [&_code]:text-gray-100 [&_pre]:bg-gray-900 [&_pre]:text-gray-100' : ''}`}>
            <ReactMarkdown>{output}</ReactMarkdown>
          </div>
        </div>
      )}
    </div>
  );
}
