// Main navigation component with dropdown menus for better organization
import React, { useState, useEffect, useRef } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';

export default function Navigation({ tabs, darkMode, onDarkModeToggle }) {
  const location = useLocation();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [openDropdown, setOpenDropdown] = useState(null);
  const dropdownRef = useRef(null);

  const currentPath = location.pathname;

  // Organize tabs into categories
  const categories = {
    home: {
      id: 'threat-intel',
      name: 'Home',
      icon: '🏠'
    },
    threatIntel: {
      name: 'Threat Intelligence',
      icon: '🛡️',
      items: [
        tabs.find(t => t.id === 'threat-intel')
      ].filter(Boolean)
    },
    engineering: {
      name: 'Engineering',
      icon: '⚙️',
      items: [
        tabs.find(t => t.id === 'prompt-gallery'),
        tabs.find(t => t.id === 'kql-diff')
      ].filter(Boolean)
    },
    jobTools: {
      name: 'Job Tools',
      icon: '🛠️',
      items: [
        tabs.find(t => t.id === 'ir-playbook'),
        tabs.find(t => t.id === 'soc-handoff'),
        tabs.find(t => t.id === 'email-posture')
      ].filter(Boolean)
    }
  };

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setOpenDropdown(null);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // Close dropdowns and mobile menu on route change
  useEffect(() => {
    setMobileMenuOpen(false);
    setOpenDropdown(null);
  }, [currentPath]);

  // Keyboard navigation
  useEffect(() => {
    const handleKeyDown = (e) => {
      // Escape to close dropdowns and mobile menu
      if (e.key === 'Escape') {
        setOpenDropdown(null);
        if (mobileMenuOpen) {
          setMobileMenuOpen(false);
        }
      }

      // Cmd/Ctrl + H for home
      if ((e.metaKey || e.ctrlKey) && e.key === 'h') {
        e.preventDefault();
        window.location.href = `/${categories.home.id}`;
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [mobileMenuOpen, categories.home.id]);

  const toggleDropdown = (categoryKey) => {
    setOpenDropdown(openDropdown === categoryKey ? null : categoryKey);
  };

  const isPathInCategory = (category) => {
    return category.items?.some(item => currentPath.startsWith(`/${item.id}`));
  };

  const DropdownMenu = ({ categoryKey, category }) => {
    const isOpen = openDropdown === categoryKey;
    const isActive = isPathInCategory(category);

    return (
      <div className="relative" ref={isOpen ? dropdownRef : null}>
        <button
          onClick={() => toggleDropdown(categoryKey)}
          className={`relative px-4 py-2 rounded-t-lg font-semibold whitespace-nowrap transition-all flex items-center gap-2 ${
            isActive || isOpen
              ? darkMode
                ? 'bg-gray-900 text-white shadow-lg'
                : 'bg-gray-50 text-gray-900 shadow-lg'
              : darkMode
              ? 'text-gray-400 hover:text-gray-300 hover:bg-gray-700'
              : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100'
          }`}
          aria-expanded={isOpen}
          aria-haspopup="true"
        >
          <span className="text-lg">{category.icon}</span>
          {category.name}
          <span className={`transition-transform ${isOpen ? 'rotate-180' : ''}`}>▼</span>

          {/* Active indicator */}
          {isActive && (
            <motion.div
              layoutId="activeDropdown"
              className={`absolute bottom-0 left-0 right-0 h-1 ${
                darkMode ? 'bg-blue-500' : 'bg-blue-600'
              } rounded-t-full`}
              initial={false}
              transition={{ type: 'spring', stiffness: 500, damping: 30 }}
            />
          )}
        </button>

        <AnimatePresence>
          {isOpen && (
            <motion.div
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              transition={{ duration: 0.15 }}
              className={`absolute top-full left-0 mt-1 min-w-[200px] rounded-lg shadow-lg overflow-hidden z-50 ${
                darkMode ? 'bg-gray-800 border border-gray-700' : 'bg-white border border-gray-200'
              }`}
            >
              {category.items.map((item) => {
                const isItemActive = currentPath.startsWith(`/${item.id}`);
                return (
                  <Link
                    key={item.id}
                    to={`/${item.id}`}
                    className={`flex items-center gap-3 px-4 py-3 transition ${
                      isItemActive
                        ? darkMode
                          ? 'bg-gray-900 text-white border-l-4 border-blue-500'
                          : 'bg-gray-50 text-gray-900 border-l-4 border-blue-600'
                        : darkMode
                        ? 'text-gray-300 hover:bg-gray-700'
                        : 'text-gray-700 hover:bg-gray-50'
                    }`}
                  >
                    <span className="text-lg">{item.icon}</span>
                    <span className="font-medium">{item.name}</span>
                  </Link>
                );
              })}
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    );
  };

  return (
    <nav
      className={`border-b ${darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'} sticky top-0 z-50 shadow-sm`}
      aria-label="Main navigation"
    >
      <div className="max-w-7xl mx-auto px-6 py-4">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h1 className={`text-2xl font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>
              🛡️ ThreatDefender Operations Suite
            </h1>
            <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
              eGroup Enabling Technologies | ThreatDefender MSSP/MXDR
            </p>
          </div>

          <div className="flex items-center gap-2">
            {/* Dark Mode Toggle */}
            <button
              onClick={onDarkModeToggle}
              className={`px-4 py-2 rounded-md font-semibold transition ${
                darkMode
                  ? 'bg-gray-700 text-yellow-400 hover:bg-gray-600'
                  : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
              }`}
              aria-label={`Switch to ${darkMode ? 'light' : 'dark'} mode`}
            >
              {darkMode ? '☀️ Light' : '🌙 Dark'}
            </button>

            {/* Mobile Menu Toggle */}
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className={`md:hidden px-3 py-2 rounded-md ${
                darkMode ? 'bg-gray-700 text-white hover:bg-gray-600' : 'bg-gray-200 text-gray-900 hover:bg-gray-300'
              }`}
              aria-label="Toggle mobile menu"
              aria-expanded={mobileMenuOpen}
            >
              {mobileMenuOpen ? '✕' : '☰'}
            </button>
          </div>
        </div>

        {/* Desktop Navigation */}
        <div className="hidden md:flex items-center gap-2" role="navigation">
          {/* Home Button */}
          <Link
            to={`/${categories.home.id}`}
            className={`relative px-4 py-2 rounded-t-lg font-semibold whitespace-nowrap transition-all flex items-center gap-2 ${
              currentPath.startsWith(`/${categories.home.id}`)
                ? darkMode
                  ? 'bg-gray-900 text-white shadow-lg'
                  : 'bg-gray-50 text-gray-900 shadow-lg'
                : darkMode
                ? 'text-gray-400 hover:text-gray-300 hover:bg-gray-700'
                : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100'
            }`}
          >
            <span className="text-lg">{categories.home.icon}</span>
            {categories.home.name}
            <span className="text-xs text-gray-500 ml-1">⌘H</span>

            {currentPath.startsWith(`/${categories.home.id}`) && (
              <motion.div
                layoutId="activeTab"
                className={`absolute bottom-0 left-0 right-0 h-1 ${
                  darkMode ? 'bg-blue-500' : 'bg-blue-600'
                } rounded-t-full`}
                initial={false}
                transition={{ type: 'spring', stiffness: 500, damping: 30 }}
              />
            )}
          </Link>

          {/* Category Dropdowns */}
          <DropdownMenu categoryKey="threatIntel" category={categories.threatIntel} />
          <DropdownMenu categoryKey="engineering" category={categories.engineering} />
          <DropdownMenu categoryKey="jobTools" category={categories.jobTools} />
        </div>

        {/* Mobile Navigation */}
        <AnimatePresence>
          {mobileMenuOpen && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="md:hidden overflow-hidden"
            >
              <div className="py-2 space-y-1" role="menu">
                {/* Home */}
                <Link
                  to={`/${categories.home.id}`}
                  className={`flex items-center px-4 py-3 rounded-lg font-semibold transition ${
                    currentPath.startsWith(`/${categories.home.id}`)
                      ? darkMode
                        ? 'bg-gray-900 text-white border-l-4 border-blue-500'
                        : 'bg-gray-50 text-gray-900 border-l-4 border-blue-600'
                      : darkMode
                      ? 'text-gray-400 hover:text-gray-300 hover:bg-gray-700'
                      : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100'
                  }`}
                >
                  <span className="mr-3 text-xl">{categories.home.icon}</span>
                  {categories.home.name}
                </Link>

                {/* All other items grouped by category */}
                {Object.entries(categories).map(([key, category]) => {
                  if (key === 'home' || !category.items) return null;

                  return (
                    <div key={key}>
                      <div className={`px-4 py-2 text-xs font-bold uppercase tracking-wider ${
                        darkMode ? 'text-gray-500' : 'text-gray-400'
                      }`}>
                        {category.icon} {category.name}
                      </div>
                      {category.items.map((item) => {
                        const isActive = currentPath.startsWith(`/${item.id}`);
                        return (
                          <Link
                            key={item.id}
                            to={`/${item.id}`}
                            className={`flex items-center px-6 py-3 rounded-lg font-semibold transition ${
                              isActive
                                ? darkMode
                                  ? 'bg-gray-900 text-white border-l-4 border-blue-500'
                                  : 'bg-gray-50 text-gray-900 border-l-4 border-blue-600'
                                : darkMode
                                ? 'text-gray-400 hover:text-gray-300 hover:bg-gray-700'
                                : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100'
                            }`}
                          >
                            <span className="mr-3 text-xl">{item.icon}</span>
                            {item.name}
                          </Link>
                        );
                      })}
                    </div>
                  );
                })}
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </nav>
  );
}
