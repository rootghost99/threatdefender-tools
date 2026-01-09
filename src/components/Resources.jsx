// Resources - Cybersecurity Tools and Links Management
import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';

export default function Resources({ darkMode }) {
  const [resources, setResources] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [editingId, setEditingId] = useState(null);
  const [editForm, setEditForm] = useState({ siteName: '', url: '', notes: '' });
  const [isAdding, setIsAdding] = useState(false);
  const [newResource, setNewResource] = useState({ siteName: '', url: '', notes: '' });
  const [saving, setSaving] = useState(false);

  // Styling classes based on dark mode
  const cardBg = darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200';
  const textPrimary = darkMode ? 'text-white' : 'text-gray-900';
  const textSecondary = darkMode ? 'text-gray-300' : 'text-gray-700';
  const textMuted = darkMode ? 'text-gray-400' : 'text-gray-500';
  const inputBg = darkMode ? 'bg-gray-700 border-gray-600 text-white placeholder-gray-400' : 'bg-white border-gray-300 text-gray-900 placeholder-gray-400';
  const tableBg = darkMode ? 'bg-gray-800' : 'bg-white';
  const tableHeaderBg = darkMode ? 'bg-gray-700' : 'bg-gray-50';
  const tableRowHover = darkMode ? 'hover:bg-gray-700' : 'hover:bg-gray-50';
  const borderColor = darkMode ? 'border-gray-700' : 'border-gray-200';

  useEffect(() => {
    fetchResources();
  }, []);

  const fetchResources = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch('/api/resources');
      if (!response.ok) {
        throw new Error('Failed to fetch resources');
      }
      const data = await response.json();
      setResources(data.resources || []);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleCreate = async () => {
    if (!newResource.siteName.trim() || !newResource.url.trim()) {
      alert('Site name and URL are required');
      return;
    }

    setSaving(true);
    try {
      const response = await fetch('/api/resources', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newResource)
      });

      if (!response.ok) {
        throw new Error('Failed to create resource');
      }

      const data = await response.json();
      setResources([...resources, data.resource]);
      setNewResource({ siteName: '', url: '', notes: '' });
      setIsAdding(false);
    } catch (err) {
      alert('Error creating resource: ' + err.message);
    } finally {
      setSaving(false);
    }
  };

  const handleEdit = (resource) => {
    setEditingId(resource.id);
    setEditForm({
      siteName: resource.siteName,
      url: resource.url,
      notes: resource.notes
    });
  };

  const handleUpdate = async () => {
    if (!editForm.siteName.trim() || !editForm.url.trim()) {
      alert('Site name and URL are required');
      return;
    }

    setSaving(true);
    try {
      const response = await fetch(`/api/resources/${editingId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(editForm)
      });

      if (!response.ok) {
        throw new Error('Failed to update resource');
      }

      const data = await response.json();
      setResources(resources.map(r => r.id === editingId ? data.resource : r));
      setEditingId(null);
      setEditForm({ siteName: '', url: '', notes: '' });
    } catch (err) {
      alert('Error updating resource: ' + err.message);
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (id) => {
    if (!window.confirm('Are you sure you want to delete this resource?')) {
      return;
    }

    try {
      const response = await fetch(`/api/resources/${id}`, {
        method: 'DELETE'
      });

      if (!response.ok) {
        throw new Error('Failed to delete resource');
      }

      setResources(resources.filter(r => r.id !== id));
    } catch (err) {
      alert('Error deleting resource: ' + err.message);
    }
  };

  const cancelEdit = () => {
    setEditingId(null);
    setEditForm({ siteName: '', url: '', notes: '' });
  };

  const cancelAdd = () => {
    setIsAdding(false);
    setNewResource({ siteName: '', url: '', notes: '' });
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

      {/* Error State */}
      {error && (
        <div className={`p-4 rounded-lg border ${darkMode ? 'bg-red-900/20 border-red-800 text-red-400' : 'bg-red-50 border-red-200 text-red-600'}`}>
          <p className="font-medium">Error loading resources</p>
          <p className="text-sm mt-1">{error}</p>
          <button
            onClick={fetchResources}
            className="mt-2 text-sm underline hover:no-underline"
          >
            Try again
          </button>
        </div>
      )}

      {/* Loading State */}
      {loading && (
        <div className={`p-12 rounded-lg border ${cardBg} text-center`}>
          <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500 mb-4"></div>
          <p className={textMuted}>Loading resources...</p>
        </div>
      )}

      {/* Resources Table */}
      {!loading && !error && (
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
      {!loading && !error && resources.length > 0 && (
        <div className={`text-sm ${textMuted}`}>
          Showing {filteredResources.length} of {resources.length} resources
        </div>
      )}
    </motion.div>
  );
}
