// Navigation context for managing navigation state across the app
import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';

const NavigationContext = createContext();

export const useNavigation = () => {
  const context = useContext(NavigationContext);
  if (!context) {
    throw new Error('useNavigation must be used within NavigationProvider');
  }
  return context;
};

export function NavigationProvider({ children }) {
  const navigate = useNavigate();
  const location = useLocation();
  const [scrollPositions, setScrollPositions] = useState({});
  const [navigationHistory, setNavigationHistory] = useState([]);
  const [hasUnsavedChanges, setHasUnsavedChanges] = useState(false);

  // Save scroll position for current route
  const saveScrollPosition = useCallback((path) => {
    const scrollY = window.scrollY;
    setScrollPositions(prev => ({
      ...prev,
      [path]: scrollY
    }));
  }, []);

  // Restore scroll position for route
  const restoreScrollPosition = useCallback((path) => {
    const savedPosition = scrollPositions[path];
    if (savedPosition !== undefined) {
      window.scrollTo(0, savedPosition);
    } else {
      window.scrollTo(0, 0);
    }
  }, [scrollPositions]);

  // Track navigation history
  useEffect(() => {
    setNavigationHistory(prev => {
      const newHistory = [...prev, location.pathname];
      // Keep last 50 entries
      return newHistory.slice(-50);
    });
  }, [location.pathname]);

  // Save scroll position on route change
  useEffect(() => {
    const path = location.pathname;
    return () => {
      saveScrollPosition(path);
    };
  }, [location.pathname, saveScrollPosition]);

  // Navigate with unsaved changes check
  const navigateWithCheck = useCallback((to, options = {}) => {
    if (hasUnsavedChanges && !options.skipCheck) {
      const confirmed = window.confirm(
        'You have unsaved changes. Are you sure you want to leave?'
      );
      if (!confirmed) {
        return false;
      }
    }

    setHasUnsavedChanges(false);
    navigate(to, options);
    return true;
  }, [hasUnsavedChanges, navigate]);

  // Get recently visited routes
  const getRecentRoutes = useCallback((limit = 5) => {
    const unique = [...new Set(navigationHistory)].reverse();
    return unique.slice(0, limit);
  }, [navigationHistory]);

  const value = {
    navigate: navigateWithCheck,
    location,
    scrollPositions,
    saveScrollPosition,
    restoreScrollPosition,
    navigationHistory,
    getRecentRoutes,
    hasUnsavedChanges,
    setHasUnsavedChanges
  };

  return (
    <NavigationContext.Provider value={value}>
      {children}
    </NavigationContext.Provider>
  );
}
