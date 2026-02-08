import React, { useState, useEffect } from 'react';

export default function SOCHandoffTool({ darkMode }) {
  const [shiftData, setShiftData] = useState({
    date: new Date().toISOString().split('T')[0],
    currentAnalyst: '',
    nextAnalyst: '',
    shiftTime: '',
    nextShiftTime: '',
    incidents: [],
    tasks: [],
    escalations: [],
    systemNotes: '',
    generalNotes: ''
  });

  const [newIncident, setNewIncident] = useState({
    id: '',
    severity: 'Medium',
    title: '',
    status: 'In Progress',
    nextActions: '',
    assignedTo: ''
  });

  const [newTask, setNewTask] = useState({
    id: '',
    priority: 'Medium',
    description: '',
    dueBy: '',
    assignedTo: ''
  });

  const [newEscalation, setNewEscalation] = useState({
    id: '',
    type: 'Management',
    description: '',
    escalatedTo: '',
    reason: ''
  });

  const [showHandoff, setShowHandoff] = useState(false);

  // Load from localStorage on mount
  useEffect(() => {
    const saved = localStorage.getItem('socHandoff');
    if (saved) {
      setShiftData(JSON.parse(saved));
    }
  }, []);

  // Save to localStorage whenever data changes
  useEffect(() => {
    localStorage.setItem('socHandoff', JSON.stringify(shiftData));
  }, [shiftData]);

  const updateField = (field, value) => {
    setShiftData(prev => ({ ...prev, [field]: value }));
  };

  const addIncident = () => {
    if (!newIncident.title) return;
    const incident = { ...newIncident, id: Date.now().toString() };
    setShiftData(prev => ({ ...prev, incidents: [...prev.incidents, incident] }));
    setNewIncident({ id: '', severity: 'Medium', title: '', status: 'In Progress', nextActions: '', assignedTo: '' });
  };

  const removeIncident = (id) => {
    setShiftData(prev => ({ ...prev, incidents: prev.incidents.filter(i => i.id !== id) }));
  };

  const addTask = () => {
    if (!newTask.description) return;
    const task = { ...newTask, id: Date.now().toString() };
    setShiftData(prev => ({ ...prev, tasks: [...prev.tasks, task] }));
    setNewTask({ id: '', priority: 'Medium', description: '', dueBy: '', assignedTo: '' });
  };

  const removeTask = (id) => {
    setShiftData(prev => ({ ...prev, tasks: prev.tasks.filter(t => t.id !== id) }));
  };

  const addEscalation = () => {
    if (!newEscalation.description) return;
    const escalation = { ...newEscalation, id: Date.now().toString() };
    setShiftData(prev => ({ ...prev, escalations: [...prev.escalations, escalation] }));
    setNewEscalation({ id: '', type: 'Management', description: '', escalatedTo: '', reason: '' });
  };

  const removeEscalation = (id) => {
    setShiftData(prev => ({ ...prev, escalations: prev.escalations.filter(e => e.id !== id) }));
  };

  const generateHandoff = () => {
    setShowHandoff(true);
  };

  // Escape HTML to prevent XSS in exported HTML reports
  const escapeHtml = (text) => {
    if (!text) return '';
    return String(text)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  };

  const exportHandoff = () => {
    const timestamp = new Date().toLocaleString();
    
    const htmlContent = `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>SOC Shift Handoff - ${shiftData.date}</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 1000px; margin: 40px auto; padding: 20px; line-height: 1.6; }
    h1 { color: #1e40af; border-bottom: 3px solid #1e40af; padding-bottom: 10px; }
    h2 { color: #374151; margin-top: 30px; border-left: 4px solid #3b82f6; padding-left: 15px; }
    .header { background: #dbeafe; padding: 20px; border-left: 4px solid #1e40af; margin-bottom: 30px; border-radius: 4px; }
    .metadata { background: #f3f4f6; padding: 15px; border-radius: 8px; margin-bottom: 20px; display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
    .metadata-item { padding: 10px; background: white; border-radius: 4px; }
    table { width: 100%; border-collapse: collapse; margin: 15px 0; }
    th { background: #1e40af; color: white; padding: 12px; text-align: left; }
    td { padding: 10px; border-bottom: 1px solid #e5e7eb; }
    tr:hover { background: #f9fafb; }
    .severity-critical { background: #fee2e2; font-weight: bold; }
    .severity-high { background: #fed7aa; }
    .severity-medium { background: #fef3c7; }
    .severity-low { background: #d1fae5; }
    .status-open { color: #dc2626; font-weight: bold; }
    .status-in-progress { color: #f59e0b; font-weight: bold; }
    .status-escalated { color: #8b5cf6; font-weight: bold; }
    .priority-high { background: #fed7aa; }
    .priority-medium { background: #fef3c7; }
    .priority-low { background: #d1fae5; }
    .notes-section { background: #f9fafb; padding: 20px; border-radius: 8px; margin: 20px 0; }
    .footer { margin-top: 50px; padding-top: 20px; border-top: 2px solid #e5e7eb; text-align: center; color: #6b7280; }
    .empty-state { text-align: center; padding: 30px; color: #9ca3af; font-style: italic; }
  </style>
</head>
<body>
  <div class="header">
    <h1>🔄 SOC Shift Handoff Report</h1>
  </div>
  
  <div class="metadata">
    <div class="metadata-item">
      <strong>Date:</strong> ${escapeHtml(shiftData.date)}
    </div>
    <div class="metadata-item">
      <strong>Report Generated:</strong> ${escapeHtml(timestamp)}
    </div>
    <div class="metadata-item">
      <strong>Outgoing Analyst:</strong> ${escapeHtml(shiftData.currentAnalyst || 'Not specified')}
    </div>
    <div class="metadata-item">
      <strong>Incoming Analyst:</strong> ${escapeHtml(shiftData.nextAnalyst || 'Not specified')}
    </div>
    <div class="metadata-item">
      <strong>Current Shift:</strong> ${escapeHtml(shiftData.shiftTime || 'Not specified')}
    </div>
    <div class="metadata-item">
      <strong>Next Shift:</strong> ${escapeHtml(shiftData.nextShiftTime || 'Not specified')}
    </div>
  </div>

  <h2>🚨 Open Incidents (${shiftData.incidents.length})</h2>
  ${shiftData.incidents.length > 0 ? `
  <table>
    <thead>
      <tr>
        <th>Severity</th>
        <th>Title</th>
        <th>Status</th>
        <th>Assigned To</th>
        <th>Next Actions</th>
      </tr>
    </thead>
    <tbody>
      ${shiftData.incidents.map(inc => `
      <tr class="severity-${escapeHtml(inc.severity.toLowerCase())}">
        <td><strong>${escapeHtml(inc.severity)}</strong></td>
        <td>${escapeHtml(inc.title)}</td>
        <td class="status-${escapeHtml(inc.status.toLowerCase().replace(' ', '-'))}">${escapeHtml(inc.status)}</td>
        <td>${escapeHtml(inc.assignedTo || 'Unassigned')}</td>
        <td>${escapeHtml(inc.nextActions || 'No actions specified')}</td>
      </tr>
      `).join('')}
    </tbody>
  </table>
  ` : '<div class="empty-state">No open incidents</div>'}

  <h2>📋 Pending Tasks (${shiftData.tasks.length})</h2>
  ${shiftData.tasks.length > 0 ? `
  <table>
    <thead>
      <tr>
        <th>Priority</th>
        <th>Description</th>
        <th>Due By</th>
        <th>Assigned To</th>
      </tr>
    </thead>
    <tbody>
      ${shiftData.tasks.map(task => `
      <tr class="priority-${escapeHtml(task.priority.toLowerCase())}">
        <td><strong>${escapeHtml(task.priority)}</strong></td>
        <td>${escapeHtml(task.description)}</td>
        <td>${escapeHtml(task.dueBy || 'No deadline')}</td>
        <td>${escapeHtml(task.assignedTo || 'Unassigned')}</td>
      </tr>
      `).join('')}
    </tbody>
  </table>
  ` : '<div class="empty-state">No pending tasks</div>'}

  <h2>⚠️ Escalations (${shiftData.escalations.length})</h2>
  ${shiftData.escalations.length > 0 ? `
  <table>
    <thead>
      <tr>
        <th>Type</th>
        <th>Description</th>
        <th>Escalated To</th>
        <th>Reason</th>
      </tr>
    </thead>
    <tbody>
      ${shiftData.escalations.map(esc => `
      <tr>
        <td><strong>${escapeHtml(esc.type)}</strong></td>
        <td>${escapeHtml(esc.description)}</td>
        <td>${escapeHtml(esc.escalatedTo)}</td>
        <td>${escapeHtml(esc.reason)}</td>
      </tr>
      `).join('')}
    </tbody>
  </table>
  ` : '<div class="empty-state">No escalations</div>'}

  ${shiftData.systemNotes ? `
  <h2>🖥️ System Status & Notes</h2>
  <div class="notes-section">
    <pre style="white-space: pre-wrap; font-family: inherit;">${escapeHtml(shiftData.systemNotes)}</pre>
  </div>
  ` : ''}

  ${shiftData.generalNotes ? `
  <h2>📝 General Notes</h2>
  <div class="notes-section">
    <pre style="white-space: pre-wrap; font-family: inherit;">${escapeHtml(shiftData.generalNotes)}</pre>
  </div>
  ` : ''}

  <div class="footer">
    <p><strong>ThreatDefender SOC Operations</strong></p>
    <p>eGroup Enabling Technologies | ThreatHunter MSSP Team</p>
  </div>
</body>
</html>`;

    const blob = new Blob([htmlContent], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `SOC-Handoff-${shiftData.date}-${Date.now()}.html`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const clearHandoff = () => {
	if (window.confirm('Clear all handoff data? This cannot be undone.')) {
      const emptyData = {
        date: new Date().toISOString().split('T')[0],
        currentAnalyst: '',
        nextAnalyst: '',
        shiftTime: '',
        nextShiftTime: '',
        incidents: [],
        tasks: [],
        escalations: [],
        systemNotes: '',
        generalNotes: ''
      };
      setShiftData(emptyData);
      setShowHandoff(false);
    }
  };

  const getSeverityColor = (severity) => {
    switch(severity) {
      case 'Critical': return darkMode ? 'bg-red-900 text-red-200' : 'bg-red-100 text-red-800';
      case 'High': return darkMode ? 'bg-orange-900 text-orange-200' : 'bg-orange-100 text-orange-800';
      case 'Medium': return darkMode ? 'bg-yellow-900 text-yellow-200' : 'bg-yellow-100 text-yellow-800';
      case 'Low': return darkMode ? 'bg-green-900 text-green-200' : 'bg-green-100 text-green-800';
      default: return darkMode ? 'bg-gray-700 text-gray-200' : 'bg-gray-100 text-gray-800';
    }
  };

  const getStatusColor = (status) => {
    switch(status) {
      case 'Open': return darkMode ? 'bg-red-900 text-red-200' : 'bg-red-100 text-red-800';
      case 'In Progress': return darkMode ? 'bg-blue-900 text-blue-200' : 'bg-blue-100 text-blue-800';
      case 'Escalated': return darkMode ? 'bg-purple-900 text-purple-200' : 'bg-purple-100 text-purple-800';
      case 'Resolved': return darkMode ? 'bg-green-900 text-green-200' : 'bg-green-100 text-green-800';
      default: return darkMode ? 'bg-gray-700 text-gray-200' : 'bg-gray-100 text-gray-800';
    }
  };

  return (
    <div className={`min-h-screen p-6 ${darkMode ? 'bg-gray-900' : 'bg-gray-50'}`}>
      <div className="max-w-7xl mx-auto">
        <div className="mb-8 flex items-center justify-between">
          <div>
            <h1 className={`text-3xl font-bold mb-2 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
              🔄 ThreatDefender - SOC Shift Handoff
            </h1>
            <p className={darkMode ? 'text-gray-400' : 'text-gray-600'}>
              Structured handoff documentation for SOC operations
            </p>
          </div>
        </div>

        {!showHandoff ? (
          <div className="space-y-6">
            {/* Shift Info */}
            <div className={`rounded-lg shadow p-6 ${darkMode ? 'bg-gray-800 border border-gray-700' : 'bg-white border border-gray-200'}`}>
              <h2 className={`text-xl font-bold mb-4 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                Shift Information
              </h2>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <label className={`block text-sm font-semibold mb-2 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                    Date
                  </label>
                  <input
                    type="date"
                    value={shiftData.date}
                    onChange={(e) => updateField('date', e.target.value)}
                    className={`w-full p-2 border rounded-md ${
                      darkMode ? 'bg-gray-900 border-gray-700 text-gray-300' : 'bg-white border-gray-300'
                    }`}
                  />
                </div>
                <div>
                  <label className={`block text-sm font-semibold mb-2 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                    Current Analyst
                  </label>
                  <input
                    type="text"
                    value={shiftData.currentAnalyst}
                    onChange={(e) => updateField('currentAnalyst', e.target.value)}
                    placeholder="Your name"
                    className={`w-full p-2 border rounded-md ${
                      darkMode ? 'bg-gray-900 border-gray-700 text-gray-300' : 'bg-white border-gray-300'
                    }`}
                  />
                </div>
                <div>
                  <label className={`block text-sm font-semibold mb-2 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                    Next Analyst
                  </label>
                  <input
                    type="text"
                    value={shiftData.nextAnalyst}
                    onChange={(e) => updateField('nextAnalyst', e.target.value)}
                    placeholder="Next analyst name"
                    className={`w-full p-2 border rounded-md ${
                      darkMode ? 'bg-gray-900 border-gray-700 text-gray-300' : 'bg-white border-gray-300'
                    }`}
                  />
                </div>
                <div>
                  <label className={`block text-sm font-semibold mb-2 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                    Current Shift Time
                  </label>
                  <input
                    type="text"
                    value={shiftData.shiftTime}
                    onChange={(e) => updateField('shiftTime', e.target.value)}
                    placeholder="e.g., 08:00 - 16:00"
                    className={`w-full p-2 border rounded-md ${
                      darkMode ? 'bg-gray-900 border-gray-700 text-gray-300' : 'bg-white border-gray-300'
                    }`}
                  />
                </div>
                <div>
                  <label className={`block text-sm font-semibold mb-2 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                    Next Shift Time
                  </label>
                  <input
                    type="text"
                    value={shiftData.nextShiftTime}
                    onChange={(e) => updateField('nextShiftTime', e.target.value)}
                    placeholder="e.g., 16:00 - 00:00"
                    className={`w-full p-2 border rounded-md ${
                      darkMode ? 'bg-gray-900 border-gray-700 text-gray-300' : 'bg-white border-gray-300'
                    }`}
                  />
                </div>
              </div>
            </div>

            {/* Incidents */}
            <div className={`rounded-lg shadow p-6 ${darkMode ? 'bg-gray-800 border border-gray-700' : 'bg-white border border-gray-200'}`}>
              <h2 className={`text-xl font-bold mb-4 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                🚨 Open Incidents ({shiftData.incidents.length})
              </h2>
              
              {shiftData.incidents.length > 0 && (
                <div className="mb-4 space-y-3">
                  {shiftData.incidents.map(inc => (
                    <div key={inc.id} className={`p-4 rounded-lg border ${darkMode ? 'bg-gray-900 border-gray-700' : 'bg-gray-50 border-gray-200'}`}>
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-2">
                            <span className={`px-3 py-1 rounded-full text-xs font-semibold ${getSeverityColor(inc.severity)}`}>
                              {inc.severity}
                            </span>
                            <span className={`px-3 py-1 rounded-full text-xs font-semibold ${getStatusColor(inc.status)}`}>
                              {inc.status}
                            </span>
                          </div>
                          <h3 className={`font-semibold mb-1 ${darkMode ? 'text-white' : 'text-gray-900'}`}>{inc.title}</h3>
                          {inc.assignedTo && <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Assigned: {inc.assignedTo}</p>}
                          {inc.nextActions && <p className={`text-sm mt-2 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}><strong>Next Actions:</strong> {inc.nextActions}</p>}
                        </div>
                        <button
                          onClick={() => removeIncident(inc.id)}
                          className="text-red-600 hover:text-red-700 ml-4"
                        >
                          ✕
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              <div className="space-y-3">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <select
                    value={newIncident.severity}
                    onChange={(e) => setNewIncident({...newIncident, severity: e.target.value})}
                    className={`p-2 border rounded-md ${darkMode ? 'bg-gray-900 border-gray-700 text-gray-300' : 'bg-white border-gray-300'}`}
                  >
                    <option value="Low">Low</option>
                    <option value="Medium">Medium</option>
                    <option value="High">High</option>
                    <option value="Critical">Critical</option>
                  </select>
                  <select
                    value={newIncident.status}
                    onChange={(e) => setNewIncident({...newIncident, status: e.target.value})}
                    className={`p-2 border rounded-md ${darkMode ? 'bg-gray-900 border-gray-700 text-gray-300' : 'bg-white border-gray-300'}`}
                  >
                    <option value="Open">Open</option>
                    <option value="In Progress">In Progress</option>
                    <option value="Escalated">Escalated</option>
                    <option value="Resolved">Resolved</option>
                  </select>
                </div>
                <input
                  type="text"
                  value={newIncident.title}
                  onChange={(e) => setNewIncident({...newIncident, title: e.target.value})}
                  placeholder="Incident title"
                  className={`w-full p-2 border rounded-md ${darkMode ? 'bg-gray-900 border-gray-700 text-gray-300' : 'bg-white border-gray-300'}`}
                />
                <input
                  type="text"
                  value={newIncident.assignedTo}
                  onChange={(e) => setNewIncident({...newIncident, assignedTo: e.target.value})}
                  placeholder="Assigned to"
                  className={`w-full p-2 border rounded-md ${darkMode ? 'bg-gray-900 border-gray-700 text-gray-300' : 'bg-white border-gray-300'}`}
                />
                <textarea
                  value={newIncident.nextActions}
                  onChange={(e) => setNewIncident({...newIncident, nextActions: e.target.value})}
                  placeholder="Next actions required"
                  className={`w-full p-2 border rounded-md ${darkMode ? 'bg-gray-900 border-gray-700 text-gray-300' : 'bg-white border-gray-300'}`}
                  rows="2"
                />
                <button
                  onClick={addIncident}
                  className="w-full px-4 py-2 bg-red-600 text-white rounded-md font-semibold hover:bg-red-700"
                >
                  + Add Incident
                </button>
              </div>
            </div>

            {/* Tasks */}
            <div className={`rounded-lg shadow p-6 ${darkMode ? 'bg-gray-800 border border-gray-700' : 'bg-white border border-gray-200'}`}>
              <h2 className={`text-xl font-bold mb-4 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                📋 Pending Tasks ({shiftData.tasks.length})
              </h2>
              
              {shiftData.tasks.length > 0 && (
                <div className="mb-4 space-y-3">
                  {shiftData.tasks.map(task => (
                    <div key={task.id} className={`p-4 rounded-lg border ${darkMode ? 'bg-gray-900 border-gray-700' : 'bg-gray-50 border-gray-200'}`}>
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-2">
                            <span className={`px-3 py-1 rounded-full text-xs font-semibold ${getSeverityColor(task.priority)}`}>
                              {task.priority}
                            </span>
                            {task.dueBy && <span className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Due: {task.dueBy}</span>}
                          </div>
                          <p className={`${darkMode ? 'text-white' : 'text-gray-900'}`}>{task.description}</p>
                          {task.assignedTo && <p className={`text-sm mt-1 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Assigned: {task.assignedTo}</p>}
                        </div>
                        <button
                          onClick={() => removeTask(task.id)}
                          className="text-red-600 hover:text-red-700 ml-4"
                        >
                          ✕
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              <div className="space-y-3">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <select
                    value={newTask.priority}
                    onChange={(e) => setNewTask({...newTask, priority: e.target.value})}
                    className={`p-2 border rounded-md ${darkMode ? 'bg-gray-900 border-gray-700 text-gray-300' : 'bg-white border-gray-300'}`}
                  >
                    <option value="Low">Low Priority</option>
                    <option value="Medium">Medium Priority</option>
                    <option value="High">High Priority</option>
                  </select>
                  <input
                    type="text"
                    value={newTask.dueBy}
                    onChange={(e) => setNewTask({...newTask, dueBy: e.target.value})}
                    placeholder="Due by (e.g., EOD, 3PM, Tomorrow)"
                    className={`p-2 border rounded-md ${darkMode ? 'bg-gray-900 border-gray-700 text-gray-300' : 'bg-white border-gray-300'}`}
                  />
                </div>
                <input
                  type="text"
                  value={newTask.description}
                  onChange={(e) => setNewTask({...newTask, description: e.target.value})}
                  placeholder="Task description"
                  className={`w-full p-2 border rounded-md ${darkMode ? 'bg-gray-900 border-gray-700 text-gray-300' : 'bg-white border-gray-300'}`}
                />
                <input
                  type="text"
                  value={newTask.assignedTo}
                  onChange={(e) => setNewTask({...newTask, assignedTo: e.target.value})}
                  placeholder="Assigned to"
                  className={`w-full p-2 border rounded-md ${darkMode ? 'bg-gray-900 border-gray-700 text-gray-300' : 'bg-white border-gray-300'}`}
                />
                <button
                  onClick={addTask}
                  className="w-full px-4 py-2 bg-blue-600 text-white rounded-md font-semibold hover:bg-blue-700"
                >
                  + Add Task
                </button>
              </div>
            </div>

            {/* Escalations */}
            <div className={`rounded-lg shadow p-6 ${darkMode ? 'bg-gray-800 border border-gray-700' : 'bg-white border border-gray-200'}`}>
              <h2 className={`text-xl font-bold mb-4 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                ⚠️ Escalations ({shiftData.escalations.length})
              </h2>
              
              {shiftData.escalations.length > 0 && (
                <div className="mb-4 space-y-3">
                  {shiftData.escalations.map(esc => (
                    <div key={esc.id} className={`p-4 rounded-lg border ${darkMode ? 'bg-purple-900 bg-opacity-20 border-purple-700' : 'bg-purple-50 border-purple-200'}`}>
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-2">
                            <span className={`px-3 py-1 rounded-full text-xs font-semibold ${darkMode ? 'bg-purple-900 text-purple-200' : 'bg-purple-200 text-purple-800'}`}>
                              {esc.type}
                            </span>
                          </div>
                          <p className={`font-semibold mb-1 ${darkMode ? 'text-white' : 'text-gray-900'}`}>{esc.description}</p>
                          <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Escalated to: {esc.escalatedTo}</p>
                          <p className={`text-sm mt-1 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}><strong>Reason:</strong> {esc.reason}</p>
                        </div>
                        <button
                          onClick={() => removeEscalation(esc.id)}
                          className="text-red-600 hover:text-red-700 ml-4"
                        >
                          ✕
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              <div className="space-y-3">
                <select
                  value={newEscalation.type}
                  onChange={(e) => setNewEscalation({...newEscalation, type: e.target.value})}
                  className={`w-full p-2 border rounded-md ${darkMode ? 'bg-gray-900 border-gray-700 text-gray-300' : 'bg-white border-gray-300'}`}
                >
                  <option value="Management">Management</option>
                  <option value="Technical">Technical/Engineering</option>
                  <option value="Client">Client</option>
                  <option value="Vendor">Vendor/Partner</option>
                </select>
                <input
                  type="text"
                  value={newEscalation.description}
                  onChange={(e) => setNewEscalation({...newEscalation, description: e.target.value})}
                  placeholder="Escalation description"
                  className={`w-full p-2 border rounded-md ${darkMode ? 'bg-gray-900 border-gray-700 text-gray-300' : 'bg-white border-gray-300'}`}
                />
                <input
                  type="text"
                  value={newEscalation.escalatedTo}
                  onChange={(e) => setNewEscalation({...newEscalation, escalatedTo: e.target.value})}
                  placeholder="Escalated to (name/team)"
                  className={`w-full p-2 border rounded-md ${darkMode ? 'bg-gray-900 border-gray-700 text-gray-300' : 'bg-white border-gray-300'}`}
                />
                <textarea
                  value={newEscalation.reason}
                  onChange={(e) => setNewEscalation({...newEscalation, reason: e.target.value})}
                  placeholder="Reason for escalation"
                  className={`w-full p-2 border rounded-md ${darkMode ? 'bg-gray-900 border-gray-700 text-gray-300' : 'bg-white border-gray-300'}`}
                  rows="2"
                />
                <button
                  onClick={addEscalation}
                  className="w-full px-4 py-2 bg-purple-600 text-white rounded-md font-semibold hover:bg-purple-700"
                >
                  + Add Escalation
                </button>
              </div>
            </div>

            {/* Notes */}
            <div className={`rounded-lg shadow p-6 ${darkMode ? 'bg-gray-800 border border-gray-700' : 'bg-white border border-gray-200'}`}>
              <h2 className={`text-xl font-bold mb-4 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                📝 Notes
              </h2>
              
              <div className="space-y-4">
                <div>
                  <label className={`block text-sm font-semibold mb-2 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                    System Status & Issues
                  </label>
                  <textarea
                    value={shiftData.systemNotes}
                    onChange={(e) => updateField('systemNotes', e.target.value)}
                    placeholder="Any system issues, outages, degraded performance, maintenance windows, etc."
                    className={`w-full p-3 border rounded-md ${darkMode ? 'bg-gray-900 border-gray-700 text-gray-300' : 'bg-white border-gray-300'}`}
                    rows="4"
                  />
                </div>

                <div>
                  <label className={`block text-sm font-semibold mb-2 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                    General Notes & Observations
                  </label>
                  <textarea
                    value={shiftData.generalNotes}
                    onChange={(e) => updateField('generalNotes', e.target.value)}
                    placeholder="Any other important information, trends observed, recommendations for next shift, etc."
                    className={`w-full p-3 border rounded-md ${darkMode ? 'bg-gray-900 border-gray-700 text-gray-300' : 'bg-white border-gray-300'}`}
                    rows="4"
                  />
                </div>
              </div>
            </div>

            {/* Actions */}
            <div className="flex gap-4 flex-wrap">
              <button
                onClick={generateHandoff}
                className="px-6 py-3 bg-blue-600 text-white rounded-md font-semibold hover:bg-blue-700 transition"
              >
                📋 Preview Handoff
              </button>
              <button
                onClick={exportHandoff}
                className="px-6 py-3 bg-green-600 text-white rounded-md font-semibold hover:bg-green-700 transition"
              >
                📄 Export Handoff
              </button>
              <button
                onClick={clearHandoff}
                className="px-6 py-3 bg-red-600 text-white rounded-md font-semibold hover:bg-red-700 transition"
              >
                🗑️ Clear All
              </button>
            </div>
          </div>
        ) : (
          <div className={`rounded-lg shadow p-8 ${darkMode ? 'bg-gray-800 border border-gray-700' : 'bg-white border border-gray-200'}`}>
            <div className="flex justify-between items-start mb-6">
              <h2 className={`text-2xl font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                Handoff Preview
              </h2>
              <button
                onClick={() => setShowHandoff(false)}
                className="px-4 py-2 bg-gray-600 text-white rounded-md font-semibold hover:bg-gray-700"
              >
                ← Back to Edit
              </button>
            </div>

            <div className={`prose max-w-none ${darkMode ? 'prose-invert' : ''}`}>
              <div className="mb-6 p-4 bg-blue-50 rounded-lg">
                <p><strong>Date:</strong> {shiftData.date}</p>
                <p><strong>Outgoing Analyst:</strong> {shiftData.currentAnalyst || 'Not specified'}</p>
                <p><strong>Incoming Analyst:</strong> {shiftData.nextAnalyst || 'Not specified'}</p>
                <p><strong>Shift Times:</strong> {shiftData.shiftTime} → {shiftData.nextShiftTime}</p>
              </div>

              <h3>🚨 Open Incidents ({shiftData.incidents.length})</h3>
              {shiftData.incidents.length > 0 ? (
                <ul>
                  {shiftData.incidents.map(inc => (
                    <li key={inc.id}>
                      <strong>[{inc.severity}] {inc.title}</strong> - {inc.status}
                      {inc.assignedTo && ` (Assigned: ${inc.assignedTo})`}
                      {inc.nextActions && <div className="text-sm mt-1">Next: {inc.nextActions}</div>}
                    </li>
                  ))}
                </ul>
              ) : (
                <p>No open incidents</p>
              )}

              <h3>📋 Pending Tasks ({shiftData.tasks.length})</h3>
              {shiftData.tasks.length > 0 ? (
                <ul>
                  {shiftData.tasks.map(task => (
                    <li key={task.id}>
                      <strong>[{task.priority}]</strong> {task.description}
                      {task.dueBy && ` (Due: ${task.dueBy})`}
                      {task.assignedTo && ` - Assigned: ${task.assignedTo}`}
                    </li>
                  ))}
                </ul>
              ) : (
                <p>No pending tasks</p>
              )}

              <h3>⚠️ Escalations ({shiftData.escalations.length})</h3>
              {shiftData.escalations.length > 0 ? (
                <ul>
                  {shiftData.escalations.map(esc => (
                    <li key={esc.id}>
                      <strong>[{esc.type}]</strong> {esc.description} - Escalated to: {esc.escalatedTo}
                      <div className="text-sm mt-1">Reason: {esc.reason}</div>
                    </li>
                  ))}
                </ul>
              ) : (
                <p>No escalations</p>
              )}

              {shiftData.systemNotes && (
                <>
                  <h3>🖥️ System Status & Notes</h3>
                  <pre className="whitespace-pre-wrap">{shiftData.systemNotes}</pre>
                </>
              )}

              {shiftData.generalNotes && (
                <>
                  <h3>📝 General Notes</h3>
                  <pre className="whitespace-pre-wrap">{shiftData.generalNotes}</pre>
                </>
              )}
            </div>

            <div className="mt-8 flex gap-4">
              <button
                onClick={exportHandoff}
                className="px-6 py-3 bg-green-600 text-white rounded-md font-semibold hover:bg-green-700"
              >
                📄 Export Handoff
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
