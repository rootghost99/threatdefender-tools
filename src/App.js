import React, { useState, useEffect, lazy, Suspense } from 'react';
import { Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import Navigation from './components/Navigation';
import SkipNav from './components/SkipNav';

// Lazy load components for better performance
const KQLDiffViewer = lazy(() => import('./components/KQLDiffViewer'));
const SOCHandoffTool = lazy(() => import('./components/SOCHandoffTool'));
const ThreatIntelLookup = lazy(() => import('./components/ThreatIntelLookup'));
const EmailPostureCheck = lazy(() => import('./components/EmailPostureCheck'));
const EmailHeaderAnalyzer = lazy(() => import('./components/EmailHeaderAnalyzer'));
const PromptGallery = lazy(() => import('./components/PromptGallery'));
const AlertTriageAssistant = lazy(() => import('./components/AlertTriageAssistant'));

// Loading component
function LoadingFallback({ darkMode }) {
  return (
    <div className={`flex items-center justify-center py-12 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
      <div className="text-center">
        <div className="inline-block animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mb-4"></div>
        <p>Loading...</p>
      </div>
    </div>
  );
}

// Page wrapper with animations
function PageWrapper({ children, darkMode }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -10 }}
      transition={{ duration: 0.2 }}
    >
      {children}
    </motion.div>
  );
}

export default function ThreatDefenderDashboard() {
  const [darkMode, setDarkMode] = useState(true);
  const location = useLocation();

  const tabs = [
    { id: 'alert-triage', name: 'Alert Triage', icon: '🚨', component: AlertTriageAssistant },
    { id: 'threat-intel', name: 'Threat Intel Lookup', icon: '🛡️', component: ThreatIntelLookup },
    { id: 'prompt-gallery', name: 'Prompt Gallery', icon: '📚', component: PromptGallery },
    { id: 'soc-handoff', name: 'SOC Shift Handoff', icon: '🔄', component: SOCHandoffTool },
    { id: 'kql-diff', name: 'KQL Diff Viewer', icon: '🔍', component: KQLDiffViewer },
    { id: 'email-posture', name: 'Email Posture Check', icon: '📧', component: EmailPostureCheck },
    { id: 'email-headers', name: 'Email Header Analyzer', icon: '🔬', component: EmailHeaderAnalyzer },
  ];

  // Update document title based on route
  useEffect(() => {
    const path = location.pathname;
    const tab = tabs.find(t => path.includes(t.id));
    if (tab) {
      document.title = `${tab.name} - ThreatDefender Command Base`;
    } else {
      document.title = 'ThreatDefender Command Base';
    }
  }, [location.pathname, tabs]);

  return (
    <div className={`min-h-screen flex flex-col ${darkMode ? 'bg-gray-900' : 'bg-gray-50'}`}>
      <SkipNav darkMode={darkMode} />

      <Navigation
        tabs={tabs}
        darkMode={darkMode}
        onDarkModeToggle={() => setDarkMode(!darkMode)}
      />

      {/* Main Content */}
      <main id="main-content" className="flex-1 max-w-7xl mx-auto px-6 py-6 w-full">
        <Suspense fallback={<LoadingFallback darkMode={darkMode} />}>
          <AnimatePresence mode="wait">
            <Routes>
              <Route
                path="/alert-triage"
                element={
                  <PageWrapper darkMode={darkMode}>
                    <AlertTriageAssistant darkMode={darkMode} />
                  </PageWrapper>
                }
              />
              <Route
                path="/threat-intel"
                element={
                  <PageWrapper darkMode={darkMode}>
                    <ThreatIntelLookup darkMode={darkMode} />
                  </PageWrapper>
                }
              />
              <Route
                path="/prompt-gallery/*"
                element={
                  <PageWrapper darkMode={darkMode}>
                    <PromptGallery darkMode={darkMode} />
                  </PageWrapper>
                }
              />
              <Route
                path="/soc-handoff"
                element={
                  <PageWrapper darkMode={darkMode}>
                    <SOCHandoffTool darkMode={darkMode} />
                  </PageWrapper>
                }
              />
              <Route
                path="/kql-diff"
                element={
                  <PageWrapper darkMode={darkMode}>
                    <KQLDiffViewer darkMode={darkMode} />
                  </PageWrapper>
                }
              />
              <Route
                path="/email-posture"
                element={
                  <PageWrapper darkMode={darkMode}>
                    <EmailPostureCheck darkMode={darkMode} />
                  </PageWrapper>
                }
              />
              <Route
                path="/email-headers"
                element={
                  <PageWrapper darkMode={darkMode}>
                    <EmailHeaderAnalyzer darkMode={darkMode} />
                  </PageWrapper>
                }
              />
              <Route path="/" element={<Navigate to="/alert-triage" replace />} />
              <Route path="*" element={<Navigate to="/alert-triage" replace />} />
            </Routes>
          </AnimatePresence>
        </Suspense>
      </main>

      {/* Footer */}
      <footer className={`py-6 border-t ${darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'}`}>
        <div className="max-w-7xl mx-auto px-6 text-center">
          <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
            ThreatDefender Operations Suite | Built for ThreatDefender MSSP Team
          </p>
          <p className={`text-xs mt-1 ${darkMode ? 'text-gray-500' : 'text-gray-500'}`}>
            eGroup Enabling Technologies © {new Date().getFullYear()}
          </p>
        </div>
      </footer>
    </div>
  );
}
