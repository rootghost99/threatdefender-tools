// /src/components/PromptAdmin.jsx
import React, { useState, useEffect } from 'react';

export default function PromptAdmin({ darkMode, onBack }) {
  const [runs, setRuns] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filterPromptId, setFilterPromptId] = useState('');
  const [filterUser, setFilterUser] = useState('');
  const [selectedRun, setSelectedRun] = useState(null);
  const [viewingOutput, setViewingOutput] = useState(false);

  useEffect(() => {
    fetchRuns();
  }, []);

  const fetchRuns = async () => {
    setLoading(true);
    setError(null);
    try {
      let url = '/api/prompt-runs?limit=100';
      if (filterPromptId) url += `&promptId=${encodeURIComponent(filterPromptId)}`;
      if (filterUser) url += `&user=${encodeURIComponent(filterUser)}`;

      const response = await fetch(url);
      if (!response.ok) throw new Error('Failed to fetch runs');
      const data = await response.json();
      setRuns(data.runs || []);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const viewRunOutput = async (runId) => {
    setLoading(true);
    try {
      const response = await fetch(`/api/prompt-runs/${runId}`);
      if (!response.ok) throw new Error('Failed to fetch run details');
      const data = await response.json();
      setSelectedRun(data);
      setViewingOutput(true);
    } catch (err) {
      alert(`Error: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const closeOutput = () => {
    setViewingOutput(false);
    setSelectedRun(null);
  };

  // Calculate stats
  const totalRuns = runs.length;
  const totalTokens = runs.reduce((sum, r) => sum + (r.totalTokens || 0), 0);
  const avgTokensPerRun = totalRuns > 0 ? Math.round(totalTokens / totalRuns) : 0;
  const uniqueUsers = new Set(runs.map(r => r.submittedBy)).size;
  const uniquePrompts = new Set(runs.map(r => r.promptId)).size;

  const cardBg = darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200';
  const textPrimary = darkMode ? 'text-white' : 'text-gray-900';
  const textSecondary = darkMode ? 'text-gray-300' : 'text-gray-700';
  const textMuted = darkMode ? 'text-gray-400' : 'text-gray-500';
  const inputBg = darkMode ? 'bg-gray-700 border-gray-600 text-white' : 'bg-white border-gray-300 text-gray-900';
  const buttonSecondary = darkMode ? 'bg-gray-700 hover:bg-gray-600' : 'bg-gray-200 hover:bg-gray-300';
  const tableBorder = darkMode ? 'border-gray-700' : 'border-gray-200';
  const tableRowHover = darkMode ? 'hover:bg-gray-700' : 'hover:bg-gray-50';

  // Output view
  if (viewingOutput && selectedRun) {
    return (
      <div className="space-y-6">
        <div className={`p-6 rounded-lg border ${cardBg}`}>
          <button onClick={closeOutput} className={`px-4 py-2 rounded font-semibold ${buttonSecondary} ${textPrimary}`}>
            ← Back to Audit Log
          </button>

          <h2 className={`text-2xl font-bold mt-4 mb-2 ${textPrimary}`}>
            Run Details
          </h2>

          <div className={`text-sm space-y-2 ${textSecondary}`}>
            <p><strong>Run ID:</strong> {selectedRun.runId}</p>
            <p><strong>Prompt:</strong> {selectedRun.promptTitle}</p>
            <p><strong>Submitted By:</strong> {selectedRun.submittedBy}</p>
            <p><strong>Submitted At:</strong> {new Date(selectedRun.submittedAt).toLocaleString()}</p>
            <p><strong>Tokens:</strong> {selectedRun.promptTokens} prompt + {selectedRun.completionTokens} completion = {selectedRun.totalTokens} total</p>
            <p><strong>Model Settings:</strong> Temperature {selectedRun.temperature}, Max Tokens {selectedRun.maxTokens}</p>
          </div>
        </div>

        {selectedRun.contextSummary && (
          <div className={`p-6 rounded-lg border ${cardBg}`}>
            <h3 className={`text-lg font-bold mb-2 ${textPrimary}`}>Context Summary</h3>
            <pre className={`text-sm whitespace-pre-wrap ${textSecondary}`}>{selectedRun.contextSummary}</pre>
          </div>
        )}

        {selectedRun.variables && Object.keys(selectedRun.variables).length > 0 && (
          <div className={`p-6 rounded-lg border ${cardBg}`}>
            <h3 className={`text-lg font-bold mb-2 ${textPrimary}`}>Variables</h3>
            <div className="space-y-1">
              {Object.entries(selectedRun.variables).map(([key, value]) => (
                <p key={key} className={`text-sm ${textSecondary}`}>
                  <strong>{key}:</strong> {String(value)}
                </p>
              ))}
            </div>
          </div>
        )}

        <div className={`p-6 rounded-lg border ${cardBg}`}>
          <h3 className={`text-lg font-bold mb-2 ${textPrimary}`}>Output</h3>
          <pre className={`text-sm whitespace-pre-wrap ${textSecondary}`}>{selectedRun.output}</pre>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className={`p-6 rounded-lg border ${cardBg}`}>
        <button onClick={onBack} className={`px-4 py-2 rounded font-semibold mb-4 ${buttonSecondary} ${textPrimary}`}>
          ← Back to Gallery
        </button>

        <h2 className={`text-2xl font-bold mb-2 ${textPrimary}`}>
          📊 Prompt Gallery Audit & Stats
        </h2>
        <p className={`text-sm ${textMuted}`}>
          View usage statistics and audit trail for all prompt executions
        </p>
      </div>

      {/* Statistics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className={`p-5 rounded-lg border ${cardBg}`}>
          <div className={`text-3xl font-bold mb-1 ${textPrimary}`}>{totalRuns}</div>
          <div className={`text-sm ${textMuted}`}>Total Runs</div>
        </div>
        <div className={`p-5 rounded-lg border ${cardBg}`}>
          <div className={`text-3xl font-bold mb-1 ${textPrimary}`}>{uniquePrompts}</div>
          <div className={`text-sm ${textMuted}`}>Unique Prompts</div>
        </div>
        <div className={`p-5 rounded-lg border ${cardBg}`}>
          <div className={`text-3xl font-bold mb-1 ${textPrimary}`}>{uniqueUsers}</div>
          <div className={`text-sm ${textMuted}`}>Active Users</div>
        </div>
        <div className={`p-5 rounded-lg border ${cardBg}`}>
          <div className={`text-3xl font-bold mb-1 ${textPrimary}`}>{avgTokensPerRun}</div>
          <div className={`text-sm ${textMuted}`}>Avg Tokens/Run</div>
        </div>
      </div>

      {/* Filters */}
      <div className={`p-6 rounded-lg border ${cardBg}`}>
        <h3 className={`text-lg font-bold mb-4 ${textPrimary}`}>Filters</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label className={`block text-sm font-medium mb-1 ${textSecondary}`}>Prompt ID</label>
            <input
              type="text"
              value={filterPromptId}
              onChange={(e) => setFilterPromptId(e.target.value)}
              placeholder="Filter by prompt ID"
              className={`w-full px-4 py-2 rounded border ${inputBg}`}
            />
          </div>
          <div>
            <label className={`block text-sm font-medium mb-1 ${textSecondary}`}>User</label>
            <input
              type="text"
              value={filterUser}
              onChange={(e) => setFilterUser(e.target.value)}
              placeholder="Filter by user"
              className={`w-full px-4 py-2 rounded border ${inputBg}`}
            />
          </div>
          <div className="flex items-end">
            <button
              onClick={fetchRuns}
              className={`w-full px-4 py-2 rounded font-semibold ${buttonSecondary} ${textPrimary}`}
            >
              Apply Filters
            </button>
          </div>
        </div>
      </div>

      {/* Loading State */}
      {loading && (
        <div className={`text-center py-12 ${textMuted}`}>
          <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
          <p className="mt-4">Loading runs...</p>
        </div>
      )}

      {/* Error State */}
      {error && (
        <div className="p-4 rounded bg-red-500/10 border border-red-500/50 text-red-400">
          <strong>Error:</strong> {error}
        </div>
      )}

      {/* Runs Table */}
      {!loading && !error && (
        <div className={`rounded-lg border overflow-hidden ${cardBg}`}>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className={darkMode ? 'bg-gray-900' : 'bg-gray-50'}>
                <tr>
                  <th className={`px-4 py-3 text-left text-xs font-medium uppercase tracking-wider ${textMuted}`}>Date</th>
                  <th className={`px-4 py-3 text-left text-xs font-medium uppercase tracking-wider ${textMuted}`}>Prompt</th>
                  <th className={`px-4 py-3 text-left text-xs font-medium uppercase tracking-wider ${textMuted}`}>User</th>
                  <th className={`px-4 py-3 text-left text-xs font-medium uppercase tracking-wider ${textMuted}`}>Tokens</th>
                  <th className={`px-4 py-3 text-left text-xs font-medium uppercase tracking-wider ${textMuted}`}>Status</th>
                  <th className={`px-4 py-3 text-left text-xs font-medium uppercase tracking-wider ${textMuted}`}>Action</th>
                </tr>
              </thead>
              <tbody className={`divide-y ${tableBorder}`}>
                {runs.length === 0 ? (
                  <tr>
                    <td colSpan={6} className={`px-4 py-8 text-center ${textMuted}`}>
                      No runs found
                    </td>
                  </tr>
                ) : (
                  runs.map(run => (
                    <tr key={run.runId} className={tableRowHover}>
                      <td className={`px-4 py-3 text-sm whitespace-nowrap ${textSecondary}`}>
                        {new Date(run.submittedAt).toLocaleString()}
                      </td>
                      <td className={`px-4 py-3 text-sm ${textSecondary}`}>
                        <div className="max-w-xs truncate">{run.promptTitle || 'Untitled'}</div>
                        <div className={`text-xs ${textMuted}`}>{run.promptId}</div>
                      </td>
                      <td className={`px-4 py-3 text-sm ${textSecondary}`}>
                        {run.submittedBy}
                      </td>
                      <td className={`px-4 py-3 text-sm ${textSecondary}`}>
                        {run.totalTokens}
                      </td>
                      <td className={`px-4 py-3 text-sm ${textSecondary}`}>
                        <span className={`px-2 py-1 rounded text-xs ${
                          run.status === 'completed'
                            ? darkMode ? 'bg-green-900/50 text-green-300' : 'bg-green-100 text-green-700'
                            : darkMode ? 'bg-red-900/50 text-red-300' : 'bg-red-100 text-red-700'
                        }`}>
                          {run.status}
                        </span>
                      </td>
                      <td className={`px-4 py-3 text-sm ${textSecondary}`}>
                        <button
                          onClick={() => viewRunOutput(run.runId)}
                          className="text-blue-500 hover:text-blue-700 font-medium"
                        >
                          View Details
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
