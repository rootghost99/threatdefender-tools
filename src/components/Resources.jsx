// Resources - Cybersecurity Tools and Links Management
// Uses localStorage for persistence (works without backend API)
import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';

const STORAGE_KEY = 'threatdefender-resources';

// Separate component for username modal to properly manage input state
function UsernameModal({ darkMode, cardBg, textPrimary, textMuted, inputBg, onSave, onCancel }) {
  const [inputValue, setInputValue] = useState('');

  const handleSave = () => {
    if (inputValue.trim()) {
      onSave(inputValue);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className={`p-6 rounded-lg border ${cardBg} max-w-md w-full mx-4`}>
        <h3 className={`text-lg font-semibold mb-4 ${textPrimary}`}>
          Set Your Username
        </h3>
        <p className={`text-sm mb-4 ${textMuted}`}>
          Enter a username to track who made changes. This will be saved for future edits.
        </p>
        <input
          type="text"
          placeholder="Enter your name or username"
          value={inputValue}
          onChange={(e) => setInputValue(e.target.value)}
          className={`w-full px-4 py-2 rounded-lg border mb-4 ${inputBg} focus:outline-none focus:ring-2 focus:ring-blue-500`}
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              handleSave();
            }
          }}
          autoFocus
        />
        <div className="flex gap-2 justify-end">
          <button
            onClick={onCancel}
            className={`px-4 py-2 rounded-lg ${darkMode ? 'bg-gray-600 hover:bg-gray-500' : 'bg-gray-200 hover:bg-gray-300 text-gray-700'}`}
          >
            Cancel
          </button>
          <button
            onClick={handleSave}
            className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white"
          >
            Save
          </button>
        </div>
      </div>
    </div>
  );
}

// Helper to get current user (simplified - uses localStorage username or 'anonymous')
const getCurrentUser = () => {
  return localStorage.getItem('threatdefender-username') || 'anonymous';
};

export default function Resources({ darkMode }) {
  const [resources, setResources] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [editingId, setEditingId] = useState(null);
  const [editForm, setEditForm] = useState({ siteName: '', url: '', notes: '' });
  const [isAdding, setIsAdding] = useState(false);
  const [newResource, setNewResource] = useState({ siteName: '', url: '', notes: '' });
  const [saving, setSaving] = useState(false);
  const [username, setUsername] = useState(getCurrentUser());
  const [showUsernamePrompt, setShowUsernamePrompt] = useState(false);

  // Styling classes based on dark mode
  const cardBg = darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200';
  const textPrimary = darkMode ? 'text-white' : 'text-gray-900';
  const textSecondary = darkMode ? 'text-gray-300' : 'text-gray-700';
  const textMuted = darkMode ? 'text-gray-400' : 'text-gray-500';
  const inputBg = darkMode ? 'bg-gray-700 border-gray-600 text-white placeholder-gray-400' : 'bg-white border-gray-300 text-gray-900 placeholder-gray-400';
  const tableHeaderBg = darkMode ? 'bg-gray-700' : 'bg-gray-50';
  const tableRowHover = darkMode ? 'hover:bg-gray-700' : 'hover:bg-gray-50';
  const borderColor = darkMode ? 'border-gray-700' : 'border-gray-200';

  // Load resources from localStorage on mount
  useEffect(() => {
    loadResources();
  }, []);

  const loadResources = () => {
    setLoading(true);
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        setResources(JSON.parse(stored));
      }
    } catch (err) {
      console.error('Error loading resources:', err);
    } finally {
      setLoading(false);
    }
  };

  const saveResources = (newResources) => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(newResources));
      setResources(newResources);
    } catch (err) {
      console.error('Error saving resources:', err);
      alert('Error saving resources');
    }
  };

  const generateId = () => {
    return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  };

  const handleCreate = () => {
    if (!newResource.siteName.trim() || !newResource.url.trim()) {
      alert('Site name and URL are required');
      return;
    }

    // Prompt for username if not set
    if (username === 'anonymous') {
      setShowUsernamePrompt(true);
      return;
    }

    setSaving(true);
    const now = new Date().toISOString();
    const resource = {
      id: generateId(),
      siteName: newResource.siteName.trim(),
      url: newResource.url.trim(),
      notes: newResource.notes.trim(),
      createdBy: username,
      createdAt: now,
      lastUpdatedBy: username,
      updatedAt: now
    };

    const newResources = [...resources, resource].sort((a, b) =>
      (a.siteName || '').localeCompare(b.siteName || '')
    );
    saveResources(newResources);
    setNewResource({ siteName: '', url: '', notes: '' });
    setIsAdding(false);
    setSaving(false);
  };

  const handleEdit = (resource) => {
    setEditingId(resource.id);
    setEditForm({
      siteName: resource.siteName,
      url: resource.url,
      notes: resource.notes || ''
    });
  };

  const handleUpdate = () => {
    if (!editForm.siteName.trim() || !editForm.url.trim()) {
      alert('Site name and URL are required');
      return;
    }

    // Prompt for username if not set
    if (username === 'anonymous') {
      setShowUsernamePrompt(true);
      return;
    }

    setSaving(true);
    const now = new Date().toISOString();
    const newResources = resources.map(r => {
      if (r.id === editingId) {
        return {
          ...r,
          siteName: editForm.siteName.trim(),
          url: editForm.url.trim(),
          notes: editForm.notes.trim(),
          lastUpdatedBy: username,
          updatedAt: now
        };
      }
      return r;
    }).sort((a, b) => (a.siteName || '').localeCompare(b.siteName || ''));

    saveResources(newResources);
    setEditingId(null);
    setEditForm({ siteName: '', url: '', notes: '' });
    setSaving(false);
  };

  const handleDelete = (id) => {
    if (!window.confirm('Are you sure you want to delete this resource?')) {
      return;
    }

    const newResources = resources.filter(r => r.id !== id);
    saveResources(newResources);
  };

  const cancelEdit = () => {
    setEditingId(null);
    setEditForm({ siteName: '', url: '', notes: '' });
  };

  const cancelAdd = () => {
    setIsAdding(false);
    setNewResource({ siteName: '', url: '', notes: '' });
  };

  const handleSetUsername = (newUsername) => {
    const trimmed = newUsername.trim();
    if (trimmed) {
      localStorage.setItem('threatdefender-username', trimmed);
      setUsername(trimmed);
    }
    setShowUsernamePrompt(false);
  };

  // Filter resources based on search term
  const filteredResources = resources.filter(r => {
    const search = searchTerm.toLowerCase();
    return (
      (r.siteName && r.siteName.toLowerCase().includes(search)) ||
      (r.url && r.url.toLowerCase().includes(search)) ||
      (r.notes && r.notes.toLowerCase().includes(search))
    );
  });

  const formatDate = (dateString) => {
    if (!dateString) return '-';
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric'
    });
  };

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      className="space-y-6"
    >
      {/* Username Prompt Modal */}
      {showUsernamePrompt && (
        <UsernameModal
          darkMode={darkMode}
          cardBg={cardBg}
          textPrimary={textPrimary}
          textMuted={textMuted}
          inputBg={inputBg}
          onSave={handleSetUsername}
          onCancel={() => setShowUsernamePrompt(false)}
        />
      )}

      {/* Header */}
      <div className={`p-6 rounded-lg border ${cardBg}`}>
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div>
            <h1 className={`text-2xl font-bold ${textPrimary}`}>
              Cybersecurity Resources
            </h1>
            <p className={`mt-1 ${textMuted}`}>
              Quick access to security tools and resources. Anyone can add or edit links.
            </p>
          </div>

          <div className="flex items-center gap-3">
            {username !== 'anonymous' && (
              <span className={`text-sm ${textMuted}`}>
                Editing as: <span className={textSecondary}>{username}</span>
                <button
                  onClick={() => setShowUsernamePrompt(true)}
                  className="ml-2 text-blue-500 hover:text-blue-400"
                >
                  (change)
                </button>
              </span>
            )}
            <button
              onClick={() => setIsAdding(true)}
              disabled={isAdding || editingId}
              className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                isAdding || editingId
                  ? 'bg-gray-500 cursor-not-allowed'
                  : darkMode
                  ? 'bg-blue-600 hover:bg-blue-700 text-white'
                  : 'bg-blue-500 hover:bg-blue-600 text-white'
              }`}
            >
              + Add Resource
            </button>
          </div>
        </div>

        {/* Search */}
        <div className="mt-4">
          <input
            type="text"
            placeholder="Search resources..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className={`w-full md:w-80 px-4 py-2 rounded-lg border ${inputBg} focus:outline-none focus:ring-2 focus:ring-blue-500`}
          />
        </div>
      </div>

      {/* Loading State */}
      {loading && (
        <div className={`p-12 rounded-lg border ${cardBg} text-center`}>
          <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500 mb-4"></div>
          <p className={textMuted}>Loading resources...</p>
        </div>
      )}

      {/* Resources Table */}
      {!loading && (
        <div className={`rounded-lg border overflow-hidden ${cardBg}`}>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className={tableHeaderBg}>
                <tr>
                  <th className={`px-6 py-3 text-left text-xs font-semibold uppercase tracking-wider ${textMuted}`}>
                    Site Name
                  </th>
                  <th className={`px-6 py-3 text-left text-xs font-semibold uppercase tracking-wider ${textMuted}`}>
                    Notes
                  </th>
                  <th className={`px-6 py-3 text-left text-xs font-semibold uppercase tracking-wider ${textMuted}`}>
                    Last Updated By
                  </th>
                  <th className={`px-6 py-3 text-left text-xs font-semibold uppercase tracking-wider ${textMuted}`}>
                    Updated
                  </th>
                  <th className={`px-6 py-3 text-right text-xs font-semibold uppercase tracking-wider ${textMuted}`}>
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className={`divide-y ${borderColor}`}>
                {/* Add New Row */}
                {isAdding && (
                  <tr className={darkMode ? 'bg-gray-750' : 'bg-blue-50'}>
                    <td className="px-6 py-4">
                      <div className="space-y-2">
                        <input
                          type="text"
                          placeholder="Site name"
                          value={newResource.siteName}
                          onChange={(e) => setNewResource({ ...newResource, siteName: e.target.value })}
                          className={`w-full px-3 py-1.5 rounded border ${inputBg} focus:outline-none focus:ring-2 focus:ring-blue-500`}
                          autoFocus
                        />
                        <input
                          type="url"
                          placeholder="https://example.com"
                          value={newResource.url}
                          onChange={(e) => setNewResource({ ...newResource, url: e.target.value })}
                          className={`w-full px-3 py-1.5 rounded border ${inputBg} focus:outline-none focus:ring-2 focus:ring-blue-500`}
                        />
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <textarea
                        placeholder="Notes (optional)"
                        value={newResource.notes}
                        onChange={(e) => setNewResource({ ...newResource, notes: e.target.value })}
                        rows={2}
                        className={`w-full px-3 py-1.5 rounded border ${inputBg} focus:outline-none focus:ring-2 focus:ring-blue-500 resize-none`}
                      />
                    </td>
                    <td className="px-6 py-4">
                      <span className={textMuted}>-</span>
                    </td>
                    <td className="px-6 py-4">
                      <span className={textMuted}>-</span>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex justify-end gap-2">
                        <button
                          onClick={handleCreate}
                          disabled={saving}
                          className={`px-3 py-1.5 rounded text-sm font-medium ${
                            saving
                              ? 'bg-gray-500 cursor-not-allowed'
                              : 'bg-green-600 hover:bg-green-700'
                          } text-white`}
                        >
                          {saving ? 'Saving...' : 'Save'}
                        </button>
                        <button
                          onClick={cancelAdd}
                          disabled={saving}
                          className={`px-3 py-1.5 rounded text-sm font-medium ${
                            darkMode
                              ? 'bg-gray-600 hover:bg-gray-500'
                              : 'bg-gray-200 hover:bg-gray-300 text-gray-700'
                          }`}
                        >
                          Cancel
                        </button>
                      </div>
                    </td>
                  </tr>
                )}

                {/* Resource Rows */}
                {filteredResources.map((resource) => (
                  <tr key={resource.id} className={`${tableRowHover} transition-colors`}>
                    {editingId === resource.id ? (
                      // Edit Mode
                      <>
                        <td className="px-6 py-4">
                          <div className="space-y-2">
                            <input
                              type="text"
                              value={editForm.siteName}
                              onChange={(e) => setEditForm({ ...editForm, siteName: e.target.value })}
                              className={`w-full px-3 py-1.5 rounded border ${inputBg} focus:outline-none focus:ring-2 focus:ring-blue-500`}
                              autoFocus
                            />
                            <input
                              type="url"
                              value={editForm.url}
                              onChange={(e) => setEditForm({ ...editForm, url: e.target.value })}
                              className={`w-full px-3 py-1.5 rounded border ${inputBg} focus:outline-none focus:ring-2 focus:ring-blue-500`}
                            />
                          </div>
                        </td>
                        <td className="px-6 py-4">
                          <textarea
                            value={editForm.notes}
                            onChange={(e) => setEditForm({ ...editForm, notes: e.target.value })}
                            rows={2}
                            className={`w-full px-3 py-1.5 rounded border ${inputBg} focus:outline-none focus:ring-2 focus:ring-blue-500 resize-none`}
                          />
                        </td>
                        <td className="px-6 py-4">
                          <span className={textMuted}>{resource.lastUpdatedBy || '-'}</span>
                        </td>
                        <td className="px-6 py-4">
                          <span className={textMuted}>{formatDate(resource.updatedAt)}</span>
                        </td>
                        <td className="px-6 py-4">
                          <div className="flex justify-end gap-2">
                            <button
                              onClick={handleUpdate}
                              disabled={saving}
                              className={`px-3 py-1.5 rounded text-sm font-medium ${
                                saving
                                  ? 'bg-gray-500 cursor-not-allowed'
                                  : 'bg-green-600 hover:bg-green-700'
                              } text-white`}
                            >
                              {saving ? 'Saving...' : 'Save'}
                            </button>
                            <button
                              onClick={cancelEdit}
                              disabled={saving}
                              className={`px-3 py-1.5 rounded text-sm font-medium ${
                                darkMode
                                  ? 'bg-gray-600 hover:bg-gray-500'
                                  : 'bg-gray-200 hover:bg-gray-300 text-gray-700'
                              }`}
                            >
                              Cancel
                            </button>
                          </div>
                        </td>
                      </>
                    ) : (
                      // View Mode
                      <>
                        <td className="px-6 py-4">
                          <div>
                            <a
                              href={resource.url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className={`font-medium hover:underline ${
                                darkMode ? 'text-blue-400 hover:text-blue-300' : 'text-blue-600 hover:text-blue-700'
                              }`}
                            >
                              {resource.siteName}
                            </a>
                            <p className={`text-xs mt-1 truncate max-w-xs ${textMuted}`}>
                              {resource.url}
                            </p>
                          </div>
                        </td>
                        <td className="px-6 py-4">
                          <p className={`text-sm ${textSecondary} whitespace-pre-wrap max-w-md`}>
                            {resource.notes || '-'}
                          </p>
                        </td>
                        <td className="px-6 py-4">
                          <span className={`text-sm ${textSecondary}`}>
                            {resource.lastUpdatedBy || '-'}
                          </span>
                        </td>
                        <td className="px-6 py-4">
                          <span className={`text-sm ${textMuted}`}>
                            {formatDate(resource.updatedAt)}
                          </span>
                        </td>
                        <td className="px-6 py-4">
                          <div className="flex justify-end gap-2">
                            <button
                              onClick={() => handleEdit(resource)}
                              disabled={isAdding || editingId}
                              className={`px-3 py-1.5 rounded text-sm font-medium transition-colors ${
                                isAdding || editingId
                                  ? 'bg-gray-500 cursor-not-allowed text-gray-300'
                                  : darkMode
                                  ? 'bg-gray-600 hover:bg-gray-500 text-white'
                                  : 'bg-gray-200 hover:bg-gray-300 text-gray-700'
                              }`}
                            >
                              Edit
                            </button>
                            <button
                              onClick={() => handleDelete(resource.id)}
                              disabled={isAdding || editingId}
                              className={`px-3 py-1.5 rounded text-sm font-medium transition-colors ${
                                isAdding || editingId
                                  ? 'bg-gray-500 cursor-not-allowed text-gray-300'
                                  : 'bg-red-600 hover:bg-red-700 text-white'
                              }`}
                            >
                              Delete
                            </button>
                          </div>
                        </td>
                      </>
                    )}
                  </tr>
                ))}

                {/* Empty State */}
                {!isAdding && filteredResources.length === 0 && (
                  <tr>
                    <td colSpan="5" className="px-6 py-12 text-center">
                      <div className={textMuted}>
                        <p className="text-lg font-medium mb-2">
                          {searchTerm ? 'No resources found' : 'No resources yet'}
                        </p>
                        <p className="text-sm">
                          {searchTerm
                            ? 'Try adjusting your search term'
                            : 'Click "Add Resource" to add your first cybersecurity tool or link'}
                        </p>
                      </div>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Stats */}
      {!loading && resources.length > 0 && (
        <div className={`text-sm ${textMuted}`}>
          Showing {filteredResources.length} of {resources.length} resources
          <span className="ml-2">(stored in browser)</span>
        </div>
      )}
    </motion.div>
  );
}
