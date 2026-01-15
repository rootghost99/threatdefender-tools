// TriageChat.jsx - Interactive AI Triage Chat Component
// Connects to td-triage-api for follow-up analysis on Sentinel incidents

import React, { useState, useEffect, useRef, useCallback } from 'react';

// Default API base URL - adjust for your environment
const DEFAULT_API_BASE = '/api';

// Severity color mapping
const SEVERITY_COLORS = {
  Critical: { bg: '#dc2626', text: '#ffffff', border: '#b91c1c' },
  High: { bg: '#ea580c', text: '#ffffff', border: '#c2410c' },
  Medium: { bg: '#eab308', text: '#1f2937', border: '#ca8a04' },
  Low: { bg: '#2563eb', text: '#ffffff', border: '#1d4ed8' },
  Informational: { bg: '#6b7280', text: '#ffffff', border: '#4b5563' }
};

// Quick action buttons configuration
const QUICK_ACTIONS = [
  { id: 'critical', label: 'Critical steps', message: 'What are the most critical investigation steps I should take immediately for this incident?' },
  { id: 'tpfp', label: 'TP/FP assessment', message: 'Based on the available evidence, what is your assessment of whether this is a true positive or false positive? Please explain your reasoning.' },
  { id: 'logs', label: 'Log recommendations', message: 'What additional logs should I query in Microsoft Sentinel to investigate this incident further? Please provide specific KQL queries.' },
  { id: 'summary', label: 'Executive summary', message: 'Please provide a brief executive summary of this incident suitable for reporting to management, including current status and recommended actions.' }
];

// Message component with markdown-like formatting
function ChatMessage({ message, darkMode }) {
  const isUser = message.role === 'user';

  // Simple markdown-style formatting for code blocks and lists
  const formatContent = (content) => {
    if (!content) return null;

    // Split on code blocks
    const parts = content.split(/(```[\s\S]*?```)/g);

    return parts.map((part, idx) => {
      // Code block
      if (part.startsWith('```')) {
        const code = part.replace(/```\w*\n?/g, '').replace(/```$/g, '');
        return (
          <pre
            key={idx}
            style={{
              backgroundColor: darkMode ? '#1f2937' : '#f3f4f6',
              color: darkMode ? '#34d399' : '#1f2937',
              padding: '12px',
              borderRadius: '6px',
              overflow: 'auto',
              fontSize: '13px',
              margin: '8px 0',
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-word'
            }}
          >
            {code.trim()}
          </pre>
        );
      }

      // Regular text with inline formatting
      return (
        <span key={idx} style={{ whiteSpace: 'pre-wrap' }}>
          {part.split('\n').map((line, lineIdx) => {
            // Bullet points
            if (line.trim().startsWith('- ') || line.trim().startsWith('* ')) {
              return (
                <div key={lineIdx} style={{ marginLeft: '16px', display: 'flex', alignItems: 'flex-start' }}>
                  <span style={{ marginRight: '8px' }}>&bull;</span>
                  <span>{line.replace(/^[\s]*[-*]\s/, '')}</span>
                </div>
              );
            }
            // Numbered lists
            if (/^\d+\.\s/.test(line.trim())) {
              return (
                <div key={lineIdx} style={{ marginLeft: '16px' }}>
                  {line}
                </div>
              );
            }
            // Regular line
            return lineIdx === 0 ? line : <React.Fragment key={lineIdx}><br />{line}</React.Fragment>;
          })}
        </span>
      );
    });
  };

  return (
    <div
      style={{
        display: 'flex',
        justifyContent: isUser ? 'flex-end' : 'flex-start',
        marginBottom: '16px'
      }}
    >
      <div
        style={{
          maxWidth: '80%',
          padding: '12px 16px',
          borderRadius: isUser ? '16px 16px 4px 16px' : '16px 16px 16px 4px',
          backgroundColor: isUser
            ? (darkMode ? '#3b82f6' : '#2563eb')
            : (darkMode ? '#374151' : '#f3f4f6'),
          color: isUser
            ? '#ffffff'
            : (darkMode ? '#e5e7eb' : '#1f2937'),
          fontSize: '14px',
          lineHeight: '1.5'
        }}
      >
        {formatContent(message.content)}
      </div>
    </div>
  );
}

// Loading indicator component
function LoadingIndicator({ darkMode }) {
  return (
    <div
      style={{
        display: 'flex',
        justifyContent: 'flex-start',
        marginBottom: '16px'
      }}
    >
      <div
        style={{
          padding: '12px 16px',
          borderRadius: '16px 16px 16px 4px',
          backgroundColor: darkMode ? '#374151' : '#f3f4f6',
          color: darkMode ? '#9ca3af' : '#6b7280',
          fontSize: '14px',
          display: 'flex',
          alignItems: 'center',
          gap: '8px'
        }}
      >
        <span style={{ animation: 'pulse 1.5s ease-in-out infinite' }}>Analyzing</span>
        <span style={{ display: 'flex', gap: '4px' }}>
          <span style={{ animation: 'bounce 1s ease-in-out infinite', animationDelay: '0ms' }}>.</span>
          <span style={{ animation: 'bounce 1s ease-in-out infinite', animationDelay: '200ms' }}>.</span>
          <span style={{ animation: 'bounce 1s ease-in-out infinite', animationDelay: '400ms' }}>.</span>
        </span>
      </div>
      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.5; }
        }
        @keyframes bounce {
          0%, 100% { transform: translateY(0); }
          50% { transform: translateY(-4px); }
        }
      `}</style>
    </div>
  );
}

// Initial analysis display component
function InitialAnalysis({ analysis, darkMode }) {
  if (!analysis) return null;

  const [expanded, setExpanded] = useState(true);

  return (
    <div
      style={{
        backgroundColor: darkMode ? '#1f2937' : '#ffffff',
        border: `1px solid ${darkMode ? '#374151' : '#e5e7eb'}`,
        borderRadius: '8px',
        marginBottom: '16px',
        overflow: 'hidden'
      }}
    >
      <div
        onClick={() => setExpanded(!expanded)}
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          padding: '12px 16px',
          cursor: 'pointer',
          backgroundColor: darkMode ? '#111827' : '#f9fafb'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span>&#x1F916;</span>
          <span style={{ fontWeight: '600', color: darkMode ? '#f3f4f6' : '#1f2937' }}>
            Initial AI Analysis
          </span>
        </div>
        <span style={{ color: darkMode ? '#9ca3af' : '#6b7280', transform: expanded ? 'rotate(180deg)' : 'rotate(0)', transition: 'transform 0.2s' }}>
          &#x25BC;
        </span>
      </div>

      {expanded && (
        <div style={{ padding: '16px' }}>
          {/* Summary */}
          {analysis.summary && (
            <div style={{ marginBottom: '16px' }}>
              <div style={{ fontSize: '12px', fontWeight: '600', color: darkMode ? '#9ca3af' : '#6b7280', marginBottom: '4px' }}>
                Summary
              </div>
              <div style={{ color: darkMode ? '#e5e7eb' : '#374151', fontSize: '14px', lineHeight: '1.5' }}>
                {analysis.summary}
              </div>
            </div>
          )}

          {/* Severity and Confidence */}
          <div style={{ display: 'flex', gap: '16px', marginBottom: '16px', flexWrap: 'wrap' }}>
            {analysis.severity && (
              <div style={{
                padding: '6px 12px',
                borderRadius: '9999px',
                backgroundColor: SEVERITY_COLORS[analysis.severity]?.bg || '#6b7280',
                color: SEVERITY_COLORS[analysis.severity]?.text || '#ffffff',
                fontSize: '13px',
                fontWeight: '600'
              }}>
                {analysis.severity}
              </div>
            )}
            {analysis.confidence && (
              <div style={{
                padding: '6px 12px',
                borderRadius: '9999px',
                backgroundColor: darkMode ? '#374151' : '#e5e7eb',
                color: darkMode ? '#e5e7eb' : '#374151',
                fontSize: '13px'
              }}>
                {analysis.confidence}% confidence
              </div>
            )}
          </div>

          {/* MITRE Techniques */}
          {analysis.mitreTechniques?.length > 0 && (
            <div style={{ marginBottom: '16px' }}>
              <div style={{ fontSize: '12px', fontWeight: '600', color: darkMode ? '#9ca3af' : '#6b7280', marginBottom: '8px' }}>
                MITRE ATT&CK Techniques
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                {analysis.mitreTechniques.map((technique, idx) => (
                  <span
                    key={idx}
                    style={{
                      padding: '4px 8px',
                      borderRadius: '4px',
                      backgroundColor: darkMode ? '#7c3aed' : '#8b5cf6',
                      color: '#ffffff',
                      fontSize: '12px',
                      fontWeight: '500'
                    }}
                  >
                    {technique}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Recommended Actions */}
          {analysis.recommendedActions?.length > 0 && (
            <div>
              <div style={{ fontSize: '12px', fontWeight: '600', color: darkMode ? '#9ca3af' : '#6b7280', marginBottom: '8px' }}>
                Recommended Actions
              </div>
              <ul style={{ margin: 0, paddingLeft: '20px', color: darkMode ? '#e5e7eb' : '#374151', fontSize: '14px', lineHeight: '1.6' }}>
                {analysis.recommendedActions.map((action, idx) => (
                  <li key={idx}>{action}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// Main TriageChat component
export default function TriageChat({
  sessionId: propSessionId,
  apiBaseUrl = DEFAULT_API_BASE,
  darkMode = true,
  onError,
  onSessionLoaded
}) {
  // Try to get sessionId from props or URL
  const [sessionId] = useState(() => {
    if (propSessionId) return propSessionId;

    // Try to extract from URL path (e.g., /triage-chat/:sessionId)
    const pathMatch = window.location.pathname.match(/\/triage-chat\/([a-f0-9-]{36})/i);
    if (pathMatch) return pathMatch[1];

    // Try to extract from URL params
    const params = new URLSearchParams(window.location.search);
    return params.get('sessionId') || params.get('session');
  });

  // State
  const [session, setSession] = useState(null);
  const [messages, setMessages] = useState([]);
  const [inputValue, setInputValue] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [initialLoading, setInitialLoading] = useState(true);

  // Refs
  const messagesEndRef = useRef(null);
  const inputRef = useRef(null);

  // Scroll to bottom of messages
  const scrollToBottom = useCallback(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, []);

  // Fetch session on mount
  useEffect(() => {
    if (!sessionId) {
      setError('No session ID provided. Please access this page with a valid session.');
      setInitialLoading(false);
      return;
    }

    async function fetchSession() {
      try {
        const response = await fetch(`${apiBaseUrl}/session/${sessionId}`);

        if (!response.ok) {
          const errData = await response.json().catch(() => ({}));
          throw new Error(errData.error || `Failed to load session: ${response.status}`);
        }

        const data = await response.json();
        setSession(data.session);
        setMessages(data.session.conversationHistory || []);

        if (onSessionLoaded) {
          onSessionLoaded(data.session);
        }
      } catch (err) {
        const errorMessage = err.message || 'Failed to load session';
        setError(errorMessage);
        if (onError) {
          onError(err);
        }
      } finally {
        setInitialLoading(false);
      }
    }

    fetchSession();
  }, [sessionId, apiBaseUrl, onError, onSessionLoaded]);

  // Scroll when messages change
  useEffect(() => {
    scrollToBottom();
  }, [messages, scrollToBottom]);

  // Send message handler
  const sendMessage = useCallback(async (messageText) => {
    if (!messageText.trim() || loading || !session) return;

    const userMessage = { role: 'user', content: messageText.trim() };

    // Optimistically add user message
    setMessages(prev => [...prev, userMessage]);
    setInputValue('');
    setLoading(true);
    setError(null);

    try {
      const response = await fetch(`${apiBaseUrl}/session/${sessionId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: messageText.trim() })
      });

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.error || `Request failed: ${response.status}`);
      }

      const data = await response.json();

      // Add assistant response
      setMessages(prev => [...prev, { role: 'assistant', content: data.response }]);

    } catch (err) {
      // Remove optimistic user message on error
      setMessages(prev => prev.slice(0, -1));
      setInputValue(messageText);
      const errorMessage = err.message || 'Failed to send message';
      setError(errorMessage);
      if (onError) {
        onError(err);
      }
    } finally {
      setLoading(false);
      inputRef.current?.focus();
    }
  }, [loading, session, sessionId, apiBaseUrl, onError]);

  // Handle form submit
  const handleSubmit = (e) => {
    e.preventDefault();
    sendMessage(inputValue);
  };

  // Handle quick action click
  const handleQuickAction = (action) => {
    sendMessage(action.message);
  };

  // Styles
  const containerStyle = {
    display: 'flex',
    flexDirection: 'column',
    height: '100%',
    minHeight: '500px',
    maxHeight: '800px',
    backgroundColor: darkMode ? '#111827' : '#ffffff',
    color: darkMode ? '#f3f4f6' : '#1f2937',
    borderRadius: '12px',
    border: `1px solid ${darkMode ? '#374151' : '#e5e7eb'}`,
    overflow: 'hidden',
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif'
  };

  // Loading state
  if (initialLoading) {
    return (
      <div style={{ ...containerStyle, alignItems: 'center', justifyContent: 'center' }}>
        <div style={{ textAlign: 'center', color: darkMode ? '#9ca3af' : '#6b7280' }}>
          <div style={{ fontSize: '24px', marginBottom: '12px' }}>&#x1F50D;</div>
          <div>Loading session...</div>
        </div>
      </div>
    );
  }

  // Error state (no session)
  if (!session) {
    return (
      <div style={{ ...containerStyle, alignItems: 'center', justifyContent: 'center', padding: '24px' }}>
        <div style={{ textAlign: 'center' }}>
          <div style={{ fontSize: '48px', marginBottom: '16px' }}>&#x26A0;&#xFE0F;</div>
          <div style={{ fontSize: '18px', fontWeight: '600', marginBottom: '8px', color: darkMode ? '#f87171' : '#dc2626' }}>
            Session Not Found
          </div>
          <div style={{ color: darkMode ? '#9ca3af' : '#6b7280', maxWidth: '400px' }}>
            {error || 'Unable to load the triage session. Please ensure you have a valid session link.'}
          </div>
        </div>
      </div>
    );
  }

  const severityColor = SEVERITY_COLORS[session.incidentSeverity] || SEVERITY_COLORS.Informational;

  return (
    <div style={containerStyle}>
      {/* Header */}
      <div
        style={{
          padding: '16px 20px',
          backgroundColor: darkMode ? '#1f2937' : '#f9fafb',
          borderBottom: `1px solid ${darkMode ? '#374151' : '#e5e7eb'}`
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '8px' }}>
          <div style={{ flex: 1, marginRight: '16px' }}>
            <h2 style={{
              margin: 0,
              fontSize: '16px',
              fontWeight: '600',
              color: darkMode ? '#f3f4f6' : '#1f2937',
              lineHeight: '1.4'
            }}>
              {session.incidentTitle || 'Incident Triage'}
            </h2>
          </div>
          {session.incidentSeverity && (
            <div style={{
              padding: '4px 12px',
              borderRadius: '9999px',
              backgroundColor: severityColor.bg,
              color: severityColor.text,
              fontSize: '12px',
              fontWeight: '600',
              flexShrink: 0
            }}>
              {session.incidentSeverity}
            </div>
          )}
        </div>

        <div style={{
          display: 'flex',
          gap: '16px',
          fontSize: '13px',
          color: darkMode ? '#9ca3af' : '#6b7280',
          flexWrap: 'wrap'
        }}>
          {session.tenantName && (
            <span>Tenant: {session.tenantName}</span>
          )}
          {session.incidentId && (
            <span>Incident: {session.incidentId}</span>
          )}
          {session.messageCount > 0 && (
            <span>{session.messageCount} messages</span>
          )}
        </div>
      </div>

      {/* Messages Area */}
      <div
        style={{
          flex: 1,
          overflowY: 'auto',
          padding: '16px 20px',
          backgroundColor: darkMode ? '#111827' : '#ffffff'
        }}
      >
        {/* Initial Analysis Card */}
        <InitialAnalysis analysis={session.initialAnalysis} darkMode={darkMode} />

        {/* Chat Messages */}
        {messages.length === 0 && !session.initialAnalysis && (
          <div style={{
            textAlign: 'center',
            padding: '40px 20px',
            color: darkMode ? '#6b7280' : '#9ca3af'
          }}>
            <div style={{ fontSize: '32px', marginBottom: '12px' }}>&#x1F4AC;</div>
            <div>Ask follow-up questions about this incident</div>
          </div>
        )}

        {messages.map((msg, idx) => (
          <ChatMessage key={idx} message={msg} darkMode={darkMode} />
        ))}

        {loading && <LoadingIndicator darkMode={darkMode} />}

        <div ref={messagesEndRef} />
      </div>

      {/* Error Banner */}
      {error && (
        <div style={{
          padding: '12px 20px',
          backgroundColor: darkMode ? 'rgba(220, 38, 38, 0.1)' : 'rgba(220, 38, 38, 0.05)',
          borderTop: `1px solid ${darkMode ? '#991b1b' : '#fecaca'}`,
          color: darkMode ? '#f87171' : '#dc2626',
          fontSize: '13px',
          display: 'flex',
          alignItems: 'center',
          gap: '8px'
        }}>
          <span>&#x26A0;&#xFE0F;</span>
          <span>{error}</span>
          <button
            onClick={() => setError(null)}
            style={{
              marginLeft: 'auto',
              background: 'none',
              border: 'none',
              color: 'inherit',
              cursor: 'pointer',
              padding: '4px',
              fontSize: '16px'
            }}
          >
            &times;
          </button>
        </div>
      )}

      {/* Quick Actions */}
      <div style={{
        padding: '12px 20px',
        backgroundColor: darkMode ? '#1f2937' : '#f9fafb',
        borderTop: `1px solid ${darkMode ? '#374151' : '#e5e7eb'}`,
        display: 'flex',
        gap: '8px',
        flexWrap: 'wrap'
      }}>
        {QUICK_ACTIONS.map(action => (
          <button
            key={action.id}
            onClick={() => handleQuickAction(action)}
            disabled={loading}
            style={{
              padding: '6px 12px',
              fontSize: '12px',
              fontWeight: '500',
              borderRadius: '6px',
              border: `1px solid ${darkMode ? '#4b5563' : '#d1d5db'}`,
              backgroundColor: darkMode ? '#374151' : '#ffffff',
              color: darkMode ? '#e5e7eb' : '#374151',
              cursor: loading ? 'not-allowed' : 'pointer',
              opacity: loading ? 0.5 : 1,
              transition: 'background-color 0.15s, border-color 0.15s'
            }}
            onMouseEnter={(e) => {
              if (!loading) {
                e.target.style.backgroundColor = darkMode ? '#4b5563' : '#f3f4f6';
                e.target.style.borderColor = darkMode ? '#6b7280' : '#9ca3af';
              }
            }}
            onMouseLeave={(e) => {
              e.target.style.backgroundColor = darkMode ? '#374151' : '#ffffff';
              e.target.style.borderColor = darkMode ? '#4b5563' : '#d1d5db';
            }}
          >
            {action.label}
          </button>
        ))}
      </div>

      {/* Input Area */}
      <form
        onSubmit={handleSubmit}
        style={{
          padding: '16px 20px',
          backgroundColor: darkMode ? '#1f2937' : '#f9fafb',
          borderTop: `1px solid ${darkMode ? '#374151' : '#e5e7eb'}`,
          display: 'flex',
          gap: '12px'
        }}
      >
        <input
          ref={inputRef}
          type="text"
          value={inputValue}
          onChange={(e) => setInputValue(e.target.value)}
          placeholder="Ask a follow-up question..."
          disabled={loading}
          style={{
            flex: 1,
            padding: '10px 16px',
            fontSize: '14px',
            borderRadius: '8px',
            border: `1px solid ${darkMode ? '#4b5563' : '#d1d5db'}`,
            backgroundColor: darkMode ? '#374151' : '#ffffff',
            color: darkMode ? '#f3f4f6' : '#1f2937',
            outline: 'none',
            transition: 'border-color 0.15s'
          }}
          onFocus={(e) => {
            e.target.style.borderColor = darkMode ? '#6b7280' : '#9ca3af';
          }}
          onBlur={(e) => {
            e.target.style.borderColor = darkMode ? '#4b5563' : '#d1d5db';
          }}
        />
        <button
          type="submit"
          disabled={loading || !inputValue.trim()}
          style={{
            padding: '10px 20px',
            fontSize: '14px',
            fontWeight: '600',
            borderRadius: '8px',
            border: 'none',
            backgroundColor: loading || !inputValue.trim()
              ? (darkMode ? '#374151' : '#e5e7eb')
              : '#3b82f6',
            color: loading || !inputValue.trim()
              ? (darkMode ? '#6b7280' : '#9ca3af')
              : '#ffffff',
            cursor: loading || !inputValue.trim() ? 'not-allowed' : 'pointer',
            transition: 'background-color 0.15s'
          }}
          onMouseEnter={(e) => {
            if (!loading && inputValue.trim()) {
              e.target.style.backgroundColor = '#2563eb';
            }
          }}
          onMouseLeave={(e) => {
            if (!loading && inputValue.trim()) {
              e.target.style.backgroundColor = '#3b82f6';
            }
          }}
        >
          {loading ? 'Sending...' : 'Send'}
        </button>
      </form>
    </div>
  );
}
