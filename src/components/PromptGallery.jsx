// /src/components/PromptGallery.jsx
import React, { useState, useEffect } from 'react';
import { Routes, Route, useNavigate, useParams } from 'react-router-dom';
import PromptDetail from './PromptDetail';
import PromptEditor from './PromptEditor';
import PromptAdmin from './PromptAdmin';
import Breadcrumb from './Breadcrumb';

// Main gallery list view
function PromptGalleryList({ darkMode }) {
  const navigate = useNavigate();
  const [prompts, setPrompts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('');
  const [showSplash, setShowSplash] = useState(true);

  // Show splash screen on mount
  useEffect(() => {
    const timer = setTimeout(() => {
      setShowSplash(false);
    }, 3500); // Show splash for 3.5 seconds

    return () => clearTimeout(timer);
  }, []);

  // Fetch prompts
  useEffect(() => {
    fetchPrompts();
  }, [categoryFilter]);

  const fetchPrompts = async () => {
    setLoading(true);
    setError(null);
    try {
      let url = '/api/prompts';
      if (categoryFilter) {
        url += `?category=${encodeURIComponent(categoryFilter)}`;
      }
      console.log('[PromptGallery] Fetching from:', url);
      const response = await fetch(url);
      console.log('[PromptGallery] Response status:', response.status, response.statusText);

      if (!response.ok) {
        const errorText = await response.text();
        console.error('[PromptGallery] Error response body:', errorText);
        throw new Error(`Failed to fetch prompts (${response.status} ${response.statusText}): ${errorText.substring(0, 200)}`);
      }

      const data = await response.json();
      console.log('[PromptGallery] Received data:', { promptCount: data.prompts?.length, data });
      setPrompts(data.prompts || []);
    } catch (err) {
      console.error('[PromptGallery] Fetch error:', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // Filter prompts by search term
  const filteredPrompts = prompts.filter(p => {
    if (!searchTerm) return true;
    const search = searchTerm.toLowerCase();
    return (
      p.title?.toLowerCase().includes(search) ||
      p.description?.toLowerCase().includes(search) ||
      (p.tags && p.tags.some(t => t.toLowerCase().includes(search)))
    );
  });

  // Get unique categories
  const categories = ['', ...new Set(prompts.map(p => p.category).filter(Boolean))];

  // Styles
  const cardBg = darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200';
  const textPrimary = darkMode ? 'text-white' : 'text-gray-900';
  const textSecondary = darkMode ? 'text-gray-300' : 'text-gray-700';
  const textMuted = darkMode ? 'text-gray-400' : 'text-gray-500';
  const inputBg = darkMode ? 'bg-gray-700 border-gray-600 text-white' : 'bg-white border-gray-300 text-gray-900';
  const buttonPrimary = darkMode ? 'bg-blue-600 hover:bg-blue-700' : 'bg-blue-500 hover:bg-blue-600';
  const buttonSecondary = darkMode ? 'bg-gray-700 hover:bg-gray-600' : 'bg-gray-200 hover:bg-gray-300';

  // Show splash screen on initial load
  if (showSplash) {
    return (
      <div className={`flex items-center justify-center min-h-[60vh] ${darkMode ? 'text-white' : 'text-gray-900'}`}>
        <div className="text-center">
          <div className="mb-6">
            <div className="inline-block animate-pulse text-6xl mb-4">📚</div>
          </div>
          <h2 className="text-3xl font-bold mb-2 animate-pulse">
            Remember: No blind Copypasta here!
          </h2>
          <div className="flex justify-center mt-6">
            <div className="flex space-x-2">
              <div className={`w-3 h-3 rounded-full animate-bounce ${darkMode ? 'bg-blue-400' : 'bg-blue-600'}`} style={{ animationDelay: '0ms' }}></div>
              <div className={`w-3 h-3 rounded-full animate-bounce ${darkMode ? 'bg-blue-400' : 'bg-blue-600'}`} style={{ animationDelay: '150ms' }}></div>
              <div className={`w-3 h-3 rounded-full animate-bounce ${darkMode ? 'bg-blue-400' : 'bg-blue-600'}`} style={{ animationDelay: '300ms' }}></div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Sticky Header */}
      <div className={`p-6 rounded-lg border ${cardBg} sticky top-20 z-40`}>
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className={`text-2xl font-bold ${textPrimary}`}>
              📚 Prompt Gallery
            </h2>
            <p className={`text-sm mt-1 ${textMuted}`}>
              Browse, search, and run vetted AI prompts for security analysis
            </p>
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => navigate('/prompt-gallery/admin')}
              className={`px-4 py-2 rounded font-semibold ${buttonSecondary} ${textPrimary}`}
            >
              📊 Audit
            </button>
            <button
              onClick={() => navigate('/prompt-gallery/editor/new')}
              className={`px-4 py-2 rounded font-semibold text-white ${buttonPrimary}`}
            >
              ➕ New Prompt
            </button>
          </div>
        </div>

        {/* Search and Filter */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className={`block text-sm font-medium mb-1 ${textSecondary}`}>
              Search
            </label>
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search by title, description, or tags..."
              className={`w-full px-4 py-2 rounded border ${inputBg}`}
            />
          </div>
          <div>
            <label className={`block text-sm font-medium mb-1 ${textSecondary}`}>
              Category
            </label>
            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
              className={`w-full px-4 py-2 rounded border ${inputBg}`}
            >
              <option value="">All Categories</option>
              {categories.filter(c => c).map(cat => (
                <option key={cat} value={cat}>{cat}</option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Loading State */}
      {loading && (
        <div className={`text-center py-12 ${textMuted}`}>
          <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
          <p className="mt-4">Loading prompts...</p>
        </div>
      )}

      {/* Error State */}
      {error && (
        <div className="p-4 rounded bg-red-500/10 border border-red-500/50 text-red-400">
          <strong>Error:</strong> {error}
        </div>
      )}

      {/* Empty State */}
      {!loading && !error && filteredPrompts.length === 0 && (
        <div className={`text-center py-12 ${cardBg} rounded-lg border`}>
          <div className="text-6xl mb-4">🔍</div>
          <h3 className={`text-xl font-bold mb-2 ${textPrimary}`}>No prompts found</h3>
          <p className={textMuted}>
            {searchTerm || categoryFilter
              ? 'Try adjusting your search or filters'
              : 'Get started by creating your first prompt'
            }
          </p>
          {!searchTerm && !categoryFilter && (
            <button
              onClick={() => navigate('/prompt-gallery/editor/new')}
              className={`mt-4 px-6 py-2 rounded font-semibold text-white ${buttonPrimary}`}
            >
              Create First Prompt
            </button>
          )}
        </div>
      )}

      {/* Prompt Cards */}
      {!loading && !error && filteredPrompts.length > 0 && (
        <div>
          <div className={`mb-4 ${textMuted}`}>
            Found {filteredPrompts.length} prompt{filteredPrompts.length !== 1 ? 's' : ''}
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {filteredPrompts.map(prompt => (
              <div
                key={prompt.id}
                className={`p-5 rounded-lg border ${cardBg} hover:shadow-lg transition-shadow cursor-pointer`}
                onClick={() => navigate(`/prompt-gallery/detail/${prompt.id}`)}
              >
                {/* Category Badge */}
                <div className="flex items-start justify-between mb-3">
                  <span className={`text-xs px-2 py-1 rounded ${darkMode ? 'bg-blue-900/50 text-blue-300' : 'bg-blue-100 text-blue-700'}`}>
                    {prompt.category || 'General'}
                  </span>
                  {prompt.collection && (
                    <span className={`text-xs px-2 py-1 rounded ${darkMode ? 'bg-purple-900/50 text-purple-300' : 'bg-purple-100 text-purple-700'}`}>
                      {prompt.collection}
                    </span>
                  )}
                </div>

                {/* Title */}
                <h3 className={`text-lg font-bold mb-2 ${textPrimary}`}>
                  {prompt.title}
                </h3>

                {/* Description */}
                <p className={`text-sm mb-3 line-clamp-2 ${textSecondary}`}>
                  {prompt.description || 'No description provided'}
                </p>

                {/* Tags */}
                {prompt.tags && prompt.tags.length > 0 && (
                  <div className="flex flex-wrap gap-1 mb-3">
                    {prompt.tags.slice(0, 3).map((tag, idx) => (
                      <span
                        key={idx}
                        className={`text-xs px-2 py-0.5 rounded ${darkMode ? 'bg-gray-700 text-gray-300' : 'bg-gray-200 text-gray-700'}`}
                      >
                        #{tag}
                      </span>
                    ))}
                    {prompt.tags.length > 3 && (
                      <span className={`text-xs ${textMuted}`}>
                        +{prompt.tags.length - 3} more
                      </span>
                    )}
                  </div>
                )}

                {/* Variables Count */}
                {prompt.variables && prompt.variables.length > 0 && (
                  <div className={`text-xs ${textMuted}`}>
                    📝 {prompt.variables.length} variable{prompt.variables.length !== 1 ? 's' : ''}
                  </div>
                )}

                {/* Metadata */}
                <div className={`text-xs mt-3 pt-3 border-t ${darkMode ? 'border-gray-700' : 'border-gray-200'} ${textMuted}`}>
                  Created by {prompt.createdBy} • {new Date(prompt.createdAt).toLocaleDateString()}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// Wrapper components for routes with breadcrumbs
function PromptDetailWrapper({ darkMode }) {
  const { id } = useParams();
  const navigate = useNavigate();

  const breadcrumbs = [
    { label: 'Prompt Gallery', href: '/prompt-gallery' },
    { label: 'Prompt Details', href: `/prompt-gallery/detail/${id}` }
  ];

  return (
    <div>
      <Breadcrumb items={breadcrumbs} darkMode={darkMode} />
      <PromptDetail
        darkMode={darkMode}
        promptId={id}
        onBack={() => navigate('/prompt-gallery')}
        onEdit={(promptId) => navigate(`/prompt-gallery/editor/${promptId}`)}
      />
    </div>
  );
}

function PromptEditorWrapper({ darkMode }) {
  const { id } = useParams();
  const navigate = useNavigate();

  const isNew = id === 'new';
  const breadcrumbs = [
    { label: 'Prompt Gallery', href: '/prompt-gallery' },
    { label: isNew ? 'Create Prompt' : 'Edit Prompt', href: `/prompt-gallery/editor/${id}` }
  ];

  return (
    <div>
      <Breadcrumb items={breadcrumbs} darkMode={darkMode} />
      <PromptEditor
        darkMode={darkMode}
        promptId={isNew ? null : id}
        onBack={() => navigate('/prompt-gallery')}
      />
    </div>
  );
}

function PromptAdminWrapper({ darkMode }) {
  const navigate = useNavigate();

  const breadcrumbs = [
    { label: 'Prompt Gallery', href: '/prompt-gallery' },
    { label: 'Audit Log', href: '/prompt-gallery/admin' }
  ];

  return (
    <div>
      <Breadcrumb items={breadcrumbs} darkMode={darkMode} />
      <PromptAdmin
        darkMode={darkMode}
        onBack={() => navigate('/prompt-gallery')}
      />
    </div>
  );
}

// Main component with routing
export default function PromptGallery({ darkMode }) {
  return (
    <Routes>
      <Route path="/" element={<PromptGalleryList darkMode={darkMode} />} />
      <Route path="/detail/:id" element={<PromptDetailWrapper darkMode={darkMode} />} />
      <Route path="/editor/:id" element={<PromptEditorWrapper darkMode={darkMode} />} />
      <Route path="/admin" element={<PromptAdminWrapper darkMode={darkMode} />} />
    </Routes>
  );
}
