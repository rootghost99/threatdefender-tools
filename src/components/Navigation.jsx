// Main navigation component with keyboard shortcuts and mobile support
import React, { useState, useEffect, useCallback } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';

export default function Navigation({ tabs, darkMode, onDarkModeToggle }) {
  const location = useLocation();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [showScrollIndicators, setShowScrollIndicators] = useState({ left: false, right: false });

  // Scroll navigation
  const scrollTabs = (direction) => {
    const container = document.getElementById('tab-container');
    if (container) {
      const scrollAmount = 200;
      container.scrollBy({
        left: direction === 'left' ? -scrollAmount : scrollAmount,
        behavior: 'smooth'
      });
    }
  };

  const currentPath = location.pathname;
  const activeTabId = tabs.find(t => currentPath.startsWith(`/${t.id}`))?.id || tabs[0]?.id;

  // Keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (e) => {
      // Cmd/Ctrl + 1-6 for tab navigation
      if ((e.metaKey || e.ctrlKey) && e.key >= '1' && e.key <= '6') {
        e.preventDefault();
        const index = parseInt(e.key) - 1;
        if (tabs[index]) {
          window.location.href = `/${tabs[index].id}`;
        }
      }

      // Cmd/Ctrl + K for search (future enhancement)
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        // Could open a command palette here
      }

      // Escape to close mobile menu
      if (e.key === 'Escape' && mobileMenuOpen) {
        setMobileMenuOpen(false);
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [tabs, mobileMenuOpen]);

  // Arrow key navigation
  const handleTabKeyDown = useCallback((e, tabId) => {
    if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
      e.preventDefault();
      const currentIndex = tabs.findIndex(t => t.id === tabId);
      const nextIndex = e.key === 'ArrowRight'
        ? (currentIndex + 1) % tabs.length
        : (currentIndex - 1 + tabs.length) % tabs.length;

      const nextTab = tabs[nextIndex];
      document.querySelector(`[data-tab-id="${nextTab.id}"]`)?.focus();
    } else if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      window.location.href = `/${tabId}`;
    }
  }, [tabs]);

  // Check for scroll indicators
  useEffect(() => {
    const checkScroll = () => {
      const container = document.getElementById('tab-container');
      if (container) {
        const scrollLeft = container.scrollLeft;
        const scrollWidth = container.scrollWidth;
        const clientWidth = container.clientWidth;

        setShowScrollIndicators({
          left: scrollLeft > 5,
          right: scrollLeft < scrollWidth - clientWidth - 5
        });
      }
    };

    const container = document.getElementById('tab-container');
    if (container) {
      container.addEventListener('scroll', checkScroll);
      checkScroll();

      // Also check on resize
      window.addEventListener('resize', checkScroll);

      // Check after a short delay to ensure content is loaded
      const timer = setTimeout(checkScroll, 100);

      return () => {
        container.removeEventListener('scroll', checkScroll);
        window.removeEventListener('resize', checkScroll);
        clearTimeout(timer);
      };
    }
  }, []);

  // Close mobile menu on route change
  useEffect(() => {
    setMobileMenuOpen(false);
  }, [currentPath]);

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
        <div className="hidden md:flex relative items-center gap-2">
          {/* Left Scroll Button */}
          {showScrollIndicators.left && (
            <button
              onClick={() => scrollTabs('left')}
              className={`flex-shrink-0 px-2 py-2 rounded-md transition z-20 ${
                darkMode ? 'bg-gray-700 text-white hover:bg-gray-600' : 'bg-gray-200 text-gray-900 hover:bg-gray-300'
              }`}
              aria-label="Scroll tabs left"
            >
              ◀
            </button>
          )}

          {/* Scroll Indicator Gradient */}
          {showScrollIndicators.left && (
            <div className={`absolute left-12 top-0 bottom-0 w-8 pointer-events-none z-10 ${
              darkMode ? 'bg-gradient-to-r from-gray-800' : 'bg-gradient-to-r from-white'
            }`} />
          )}
          {showScrollIndicators.right && (
            <div className={`absolute right-12 top-0 bottom-0 w-8 pointer-events-none z-10 ${
              darkMode ? 'bg-gradient-to-l from-gray-800' : 'bg-gradient-to-l from-white'
            }`} />
          )}

          <div
            id="tab-container"
            className="flex gap-2 overflow-x-auto scrollbar-hide pr-4 flex-1"
            role="tablist"
            style={{ scrollPaddingRight: '1rem' }}
          >
            {tabs.map((tab, index) => {
              const isActive = activeTabId === tab.id;
              return (
                <Link
                  key={tab.id}
                  to={`/${tab.id}`}
                  data-tab-id={tab.id}
                  role="tab"
                  aria-selected={isActive}
                  aria-controls={`panel-${tab.id}`}
                  tabIndex={isActive ? 0 : -1}
                  onKeyDown={(e) => handleTabKeyDown(e, tab.id)}
                  className={`relative px-4 py-2 rounded-t-lg font-semibold whitespace-nowrap transition-all focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 ${
                    darkMode ? 'focus:ring-offset-gray-800' : 'focus:ring-offset-white'
                  } ${
                    isActive
                      ? darkMode
                        ? 'bg-gray-900 text-white shadow-lg'
                        : 'bg-gray-50 text-gray-900 shadow-lg'
                      : darkMode
                      ? 'text-gray-400 hover:text-gray-300 hover:bg-gray-700'
                      : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100'
                  }`}
                >
                  <span className="mr-2 text-lg">{tab.icon}</span>
                  {tab.name}

                  {/* Keyboard shortcut hint */}
                  {index < 6 && (
                    <span className={`ml-2 text-xs ${
                      darkMode ? 'text-gray-500' : 'text-gray-400'
                    }`}>
                      ⌘{index + 1}
                    </span>
                  )}

                  {/* Active indicator */}
                  {isActive && (
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
              );
            })}
          </div>

          {/* Right Scroll Button */}
          {showScrollIndicators.right && (
            <button
              onClick={() => scrollTabs('right')}
              className={`flex-shrink-0 px-2 py-2 rounded-md transition z-20 ${
                darkMode ? 'bg-gray-700 text-white hover:bg-gray-600' : 'bg-gray-200 text-gray-900 hover:bg-gray-300'
              }`}
              aria-label="Scroll tabs right"
            >
              ▶
            </button>
          )}
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
                {tabs.map((tab) => {
                  const isActive = activeTabId === tab.id;
                  return (
                    <Link
                      key={tab.id}
                      to={`/${tab.id}`}
                      role="menuitem"
                      className={`flex items-center px-4 py-3 rounded-lg font-semibold transition ${
                        isActive
                          ? darkMode
                            ? 'bg-gray-900 text-white border-l-4 border-blue-500'
                            : 'bg-gray-50 text-gray-900 border-l-4 border-blue-600'
                          : darkMode
                          ? 'text-gray-400 hover:text-gray-300 hover:bg-gray-700'
                          : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100'
                      }`}
                    >
                      <span className="mr-3 text-xl">{tab.icon}</span>
                      {tab.name}
                    </Link>
                  );
                })}
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* Add custom scrollbar hiding */}
      <style>{`
        .scrollbar-hide::-webkit-scrollbar {
          display: none;
        }
        .scrollbar-hide {
          -ms-overflow-style: none;
          scrollbar-width: none;
        }
      `}</style>
    </nav>
  );
}
