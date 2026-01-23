// TriageChat.jsx - Interactive AI Triage Chat Component
// Connects to td-triage-api for follow-up analysis on Sentinel incidents
// Includes ConnectWise Manage integration for ticket management

import React, { useState, useEffect, useRef, useCallback } from 'react';
import { useParams } from 'react-router-dom';

// Default API base URL - adjust for your environment
const DEFAULT_API_BASE = '/api';

// ConnectWise configuration
const CW_STATUSES = ['New', 'In Progress', 'Pending Client Determination', 'Closed'];
const CW_TYPES = ['Undetermined', 'Pending', 'True Positive', 'False Positive', 'Benign Positive', 'Out of Scope'];

// Severity color mapping
const SEVERITY_COLORS = {
  Critical: { bg: '#dc2626', text: '#ffffff', border: '#b91c1c' },
  High: { bg: '#ea580c', text: '#ffffff', border: '#c2410c' },
  Medium: { bg: '#eab308', text: '#1f2937', border: '#ca8a04' },
  Low: { bg: '#2563eb', text: '#ffffff', border: '#1d4ed8' },
  Informational: { bg: '#6b7280', text: '#ffffff', border: '#4b5563' }
};

// Incident type detection keywords
const INCIDENT_TYPE_KEYWORDS = {
  email: ['phishing', 'spam', 'malicious email', 'bec', 'business email'],
  identity: ['sign-in', 'login', 'impossible travel', 'mfa', 'authentication', 'password'],
  malware: ['malware', 'virus', 'ransomware', 'defender', 'edr', 'suspicious process'],
  data: ['exfiltration', 'data loss', 'dlp', 'sensitive', 'upload']
};

// Incident type labels with icons
const INCIDENT_TYPE_LABELS = {
  email: { icon: '📧', label: 'Email Threat Actions' },
  identity: { icon: '🔐', label: 'Identity Threat Actions' },
  malware: { icon: '🦠', label: 'Malware Threat Actions' },
  data: { icon: '📊', label: 'Data Protection Actions' },
  general: { icon: '🔍', label: 'Investigation Actions' }
};

// Quick actions per incident type
const QUICK_ACTIONS_BY_TYPE = {
  email: [
    { id: 'links', label: 'Check clicked links', message: 'Did the user click any links in the suspicious email? If so, what were they and what happened after?' },
    { id: 'mailbox', label: 'Pull mailbox logs', message: 'Pull mailbox audit logs for this user. Show me recent email activity including any rules created, forwarding changes, or suspicious actions.' },
    { id: 'forwarding', label: 'Check forwarding', message: 'Check if this email was forwarded externally. Are there any mailbox rules that forward or redirect emails to external addresses?' },
    { id: 'recipients', label: 'List recipients', message: 'List other recipients of this email. How many users in the organization received this same message?' },
    { id: 'notification', label: 'Draft notification', message: 'Draft a user notification message I can send to affected users about this phishing/malicious email incident.' }
  ],
  identity: [
    { id: 'travel', label: 'Verify travel/VPN', message: 'Is this a legitimate travel or VPN scenario? What evidence supports or contradicts a true positive assessment?' },
    { id: 'signins', label: 'Recent sign-ins', message: 'Show recent sign-in activity for this user. Include locations, devices, and any failed attempts.' },
    { id: 'risky', label: 'Other risky sign-ins', message: 'Check for other risky sign-ins in this tenant. Are there similar patterns affecting other users?' },
    { id: 'password', label: 'Password reset?', message: 'Should we reset this user\'s password? What are the risks of not resetting versus false positive disruption?' },
    { id: 'ca', label: 'CA policy hits', message: 'Review conditional access policy hits for this user. What policies were triggered and what was the outcome?' }
  ],
  malware: [
    { id: 'isolated', label: 'Device isolated?', message: 'Is this device currently isolated? What is the current containment status and network connectivity?' },
    { id: 'process', label: 'Process tree', message: 'What\'s the full process tree for this detection? Show the parent process chain and any child processes spawned.' },
    { id: 'lateral', label: 'Lateral movement', message: 'Check for lateral movement indicators. Has there been any suspicious network activity or authentication from this device to others?' },
    { id: 'iocs', label: 'Other devices', message: 'List other devices with this IOC (hash, domain, IP). How widespread is this indicator across the environment?' },
    { id: 'avscan', label: 'Run full scan?', message: 'Should we run a full AV scan on this device? What remediation actions are recommended?' }
  ],
  data: [
    { id: 'accessed', label: 'What data?', message: 'What data was accessed or potentially exfiltrated? Provide details on file types, sensitivity labels, and volume.' },
    { id: 'authorized', label: 'User authorized?', message: 'Is this user authorized for this data? What are their normal access patterns compared to this activity?' },
    { id: 'dlpalerts', label: 'Other DLP alerts', message: 'Check for other DLP alerts on this user. Is there a pattern of data handling policy violations?' },
    { id: 'revoke', label: 'Revoke access?', message: 'Should we revoke this user\'s access to sensitive data? What is the risk assessment and business impact?' },
    { id: 'report', label: 'Draft report', message: 'Draft an incident report for this data exposure suitable for compliance/legal review. Include timeline, scope, and recommended actions.' }
  ],
  general: [
    { id: 'critical', label: 'Critical steps', message: 'What are the most critical investigation steps I should take immediately for this incident?' },
    { id: 'tpfp', label: 'TP/FP assessment', message: 'Based on the available evidence, what is your assessment of whether this is a true positive or false positive? Please explain your reasoning.' },
    { id: 'logs', label: 'Log recommendations', message: 'What additional logs should I query in Microsoft Sentinel to investigate this incident further? Please provide specific KQL queries.' },
    { id: 'summary', label: 'Executive summary', message: 'Please provide a brief executive summary of this incident suitable for reporting to management, including current status and recommended actions.' }
  ]
};

// Detect incident type from title
function detectIncidentType(incidentTitle) {
  if (!incidentTitle) return 'general';

  const titleLower = incidentTitle.toLowerCase();

  for (const [type, keywords] of Object.entries(INCIDENT_TYPE_KEYWORDS)) {
    for (const keyword of keywords) {
      if (titleLower.includes(keyword)) {
        return type;
      }
    }
  }

  return 'general';
}

// Code block component with copy button
function CodeBlock({ code, darkMode }) {
  const [copied, setCopied] = React.useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  return (
    <div style={{ position: 'relative', margin: '8px 0' }}>
      <button
        onClick={handleCopy}
        style={{
          position: 'absolute',
          top: '8px',
          right: '8px',
          padding: '4px 8px',
          fontSize: '11px',
          fontWeight: '500',
          borderRadius: '4px',
          border: `1px solid ${darkMode ? '#4b5563' : '#d1d5db'}`,
          backgroundColor: copied
            ? (darkMode ? '#065f46' : '#d1fae5')
            : (darkMode ? '#374151' : '#ffffff'),
          color: copied
            ? (darkMode ? '#6ee7b7' : '#065f46')
            : (darkMode ? '#e5e7eb' : '#374151'),
          cursor: 'pointer',
          transition: 'all 0.15s',
          zIndex: 1
        }}
        onMouseEnter={(e) => {
          if (!copied) {
            e.target.style.backgroundColor = darkMode ? '#4b5563' : '#f3f4f6';
          }
        }}
        onMouseLeave={(e) => {
          if (!copied) {
            e.target.style.backgroundColor = darkMode ? '#374151' : '#ffffff';
          }
        }}
      >
        {copied ? '✓ Copied' : 'Copy'}
      </button>
      <pre
        style={{
          backgroundColor: darkMode ? '#1f2937' : '#f3f4f6',
          color: darkMode ? '#34d399' : '#1f2937',
          padding: '12px',
          paddingTop: '36px',
          borderRadius: '6px',
          overflow: 'auto',
          fontSize: '13px',
          whiteSpace: 'pre-wrap',
          wordBreak: 'break-word',
          margin: 0
        }}
      >
        {code}
      </pre>
    </div>
  );
}

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
        const code = part.replace(/```\w*\n?/g, '').replace(/```$/g, '').trim();
        return <CodeBlock key={idx} code={code} darkMode={darkMode} />;
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

  // Render images if present
  const renderImages = () => {
    if (!message.images || message.images.length === 0) return null;

    return (
      <div style={{
        display: 'flex',
        flexWrap: 'wrap',
        gap: '8px',
        marginBottom: message.content ? '8px' : 0
      }}>
        {message.images.map((img, idx) => (
          <img
            key={idx}
            src={`data:${img.type};base64,${img.data}`}
            alt={`Attached screenshot ${idx + 1}`}
            style={{
              maxWidth: '300px',
              maxHeight: '200px',
              borderRadius: '8px',
              border: `1px solid ${darkMode ? '#4b5563' : '#d1d5db'}`,
              cursor: 'pointer'
            }}
            onClick={() => {
              // Open image in new tab for full view
              const newTab = window.open();
              if (newTab) {
                newTab.document.write(`<img src="data:${img.type};base64,${img.data}" style="max-width: 100%; height: auto;" />`);
              }
            }}
          />
        ))}
      </div>
    );
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
        {renderImages()}
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

// Extract ConnectWise ticket ID from session data
function extractCWTicketId(session) {
  if (!session) return '';

  // Parse incidentContext if it's a JSON string
  let context = session.incidentContext || {};
  if (typeof context === 'string') {
    try {
      context = JSON.parse(context);
    } catch {
      context = {};
    }
  }
  const explicitFields = [
    context.cwTicketId,
    context.connectwiseTicketId,
    context.externalTicketId,
    context.ticketId,
    context.cw_ticket_id,
    session.cwTicketId,
    session.externalTicketId
  ];

  for (const field of explicitFields) {
    if (field && String(field).trim()) {
      return String(field).trim();
    }
  }

  // Check incident tags/labels for ticket number (primary source)
  // Tags can be in various locations depending on the data structure:
  // - context.properties.tags / context.tags (generic)
  // - context.properties.labels / context.labels (Sentinel API format)
  // - context.incident.labels (nested incident object format from AlertTriageAssistant)
  // Sentinel uses 'labels' while some systems use 'tags'
  const tags = context.properties?.tags || context.tags || context.properties?.labels || context.labels || context.incident?.labels || [];
  if (Array.isArray(tags) && tags.length > 0) {
    // Find tags that contain a number (potential ticket IDs)
    const numberedTags = tags
      .map(tag => {
        // Handle different tag/label formats:
        // - Simple string: "12345"
        // - Object with labelName: { labelName: "12345" } (Sentinel format)
        // - Object with name: { name: "12345" }
        // - Object with value: { value: "12345" }
        const tagStr = typeof tag === 'string' ? tag : tag?.labelName || tag?.name || tag?.value || '';
        const match = tagStr.match(/(\d+)/);
        return match ? match[1] : null;
      })
      .filter(Boolean);

    // Only auto-populate if exactly one numbered tag exists
    if (numberedTags.length === 1) {
      return numberedTags[0];
    }
    // If multiple numbered tags, don't guess - return empty
    if (numberedTags.length > 1) {
      return '';
    }
  }

  // Fallback: Try to extract from incident title using common patterns
  const title = session.incidentTitle || '';
  if (title) {
    // Pattern: "CW#12345" or "CW# 12345" or "CW 12345"
    const cwPattern = /\bCW\s*#?\s*(\d+)/i;
    // Pattern: "Ticket #12345" or "Ticket: 12345" or "Ticket 12345"
    const ticketPattern = /\bTicket\s*[:#]?\s*(\d+)/i;
    // Pattern: "[12345]" at start or end
    const bracketPattern = /^\[(\d+)\]|\[(\d+)\]$/;
    // Pattern: "#12345" at start
    const hashPattern = /^#(\d+)/;

    for (const pattern of [cwPattern, ticketPattern, bracketPattern, hashPattern]) {
      const match = title.match(pattern);
      if (match) {
        // Return the first captured group that exists
        return match[1] || match[2] || '';
      }
    }
  }

  // Check incident context for nested ticket references
  if (context.properties?.externalTicketId) {
    return String(context.properties.externalTicketId).trim();
  }
  if (context.properties?.ticketNumber) {
    return String(context.properties.ticketNumber).trim();
  }

  return '';
}

// ConnectWise Actions Panel Component
function ConnectWisePanel({ darkMode, apiBaseUrl, session, onSuccess, onError }) {
  const [ticketId, setTicketId] = useState('');
  const [isExpanded, setIsExpanded] = useState(false);
  const [loading, setLoading] = useState(false);
  const [statusMessage, setStatusMessage] = useState(null);
  const [noteText, setNoteText] = useState('');
  const [autoDetected, setAutoDetected] = useState(false);

  // Auto-populate ticket ID from session data
  useEffect(() => {
    if (session && !ticketId) {
      const detectedId = extractCWTicketId(session);
      if (detectedId) {
        setTicketId(detectedId);
        setAutoDetected(true);
      }
    }
  }, [session]);

  // Clear status message after 3 seconds
  useEffect(() => {
    if (statusMessage) {
      const timer = setTimeout(() => setStatusMessage(null), 3000);
      return () => clearTimeout(timer);
    }
  }, [statusMessage]);

  // Handle API call with loading state
  const handleCWAction = async (action, body) => {
    if (!ticketId.trim()) {
      setStatusMessage({ type: 'error', text: 'Enter a ConnectWise ticket ID first' });
      return;
    }

    setLoading(true);
    setStatusMessage(null);

    try {
      const response = await fetch(`${apiBaseUrl}/ConnectWise/${action}`, {
        method: action === 'ticket' && !body ? 'GET' : (action === 'ticket' ? 'PATCH' : 'POST'),
        headers: { 'Content-Type': 'application/json' },
        body: body ? JSON.stringify({ ticketId: ticketId.trim(), ...body }) : undefined
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || `Request failed: ${response.status}`);
      }

      setStatusMessage({ type: 'success', text: getSuccessMessage(action, body) });
      if (onSuccess) onSuccess(action, data);

      // Clear note text after successful note submission
      if (action === 'note') setNoteText('');

    } catch (err) {
      const errorMsg = err.message || 'Operation failed';
      setStatusMessage({ type: 'error', text: errorMsg });
      if (onError) onError(err);
    } finally {
      setLoading(false);
    }
  };

  // Generate success message based on action
  const getSuccessMessage = (action, body) => {
    switch (action) {
      case 'note':
        return 'Note added';
      case 'ticket':
        if (body.status && body.type) return `Updated to ${body.status} / ${body.type}`;
        if (body.status) return `Status: ${body.status}`;
        if (body.type) return `Type: ${body.type}`;
        return 'Ticket updated';
      default:
        return 'Success';
    }
  };

  // Button style helper
  const getButtonStyle = (isActive = false, isSmall = false) => ({
    padding: isSmall ? '4px 8px' : '6px 12px',
    fontSize: isSmall ? '11px' : '12px',
    fontWeight: '500',
    borderRadius: '6px',
    border: `1px solid ${darkMode ? '#4b5563' : '#d1d5db'}`,
    backgroundColor: isActive
      ? (darkMode ? '#3b82f6' : '#2563eb')
      : (darkMode ? '#374151' : '#ffffff'),
    color: isActive
      ? '#ffffff'
      : (darkMode ? '#e5e7eb' : '#374151'),
    cursor: loading ? 'not-allowed' : 'pointer',
    opacity: loading ? 0.5 : 1,
    transition: 'all 0.15s',
    whiteSpace: 'nowrap'
  });

  if (!isExpanded) {
    return (
      <div style={{
        padding: '8px 20px',
        backgroundColor: darkMode ? '#1f2937' : '#f9fafb',
        borderTop: `1px solid ${darkMode ? '#374151' : '#e5e7eb'}`
      }}>
        <button
          onClick={() => setIsExpanded(true)}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            padding: '8px 12px',
            fontSize: '12px',
            fontWeight: '500',
            borderRadius: '6px',
            border: `1px solid ${darkMode ? '#4b5563' : '#d1d5db'}`,
            backgroundColor: darkMode ? '#374151' : '#ffffff',
            color: darkMode ? '#e5e7eb' : '#374151',
            cursor: 'pointer',
            width: '100%',
            justifyContent: 'center'
          }}
        >
          <span style={{ fontSize: '14px' }}>🔗</span>
          <span>ConnectWise Actions</span>
          <span style={{ marginLeft: 'auto', fontSize: '10px' }}>▼</span>
        </button>
      </div>
    );
  }

  return (
    <div style={{
      backgroundColor: darkMode ? '#1f2937' : '#f9fafb',
      borderTop: `1px solid ${darkMode ? '#374151' : '#e5e7eb'}`
    }}>
      {/* Header */}
      <div
        onClick={() => setIsExpanded(false)}
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '10px 20px',
          cursor: 'pointer',
          borderBottom: `1px solid ${darkMode ? '#374151' : '#e5e7eb'}`
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ fontSize: '14px' }}>🔗</span>
          <span style={{
            fontSize: '12px',
            fontWeight: '600',
            color: darkMode ? '#e5e7eb' : '#374151'
          }}>
            ConnectWise Actions
          </span>
        </div>
        <span style={{
          fontSize: '10px',
          color: darkMode ? '#9ca3af' : '#6b7280',
          transform: 'rotate(180deg)'
        }}>▼</span>
      </div>

      {/* Content */}
      <div style={{ padding: '12px 20px' }}>
        {/* Ticket ID Input */}
        <div style={{ marginBottom: '12px' }}>
          <label style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            fontSize: '11px',
            fontWeight: '600',
            color: darkMode ? '#9ca3af' : '#6b7280',
            marginBottom: '4px'
          }}>
            <span>Ticket ID</span>
            {autoDetected && ticketId && (
              <span style={{
                fontSize: '10px',
                fontWeight: '500',
                color: '#10b981',
                backgroundColor: darkMode ? 'rgba(16, 185, 129, 0.15)' : 'rgba(16, 185, 129, 0.1)',
                padding: '1px 6px',
                borderRadius: '4px'
              }}>
                auto-detected
              </span>
            )}
          </label>
          <input
            type="text"
            value={ticketId}
            onChange={(e) => {
              setTicketId(e.target.value);
              setAutoDetected(false); // Clear auto-detected flag on manual edit
            }}
            placeholder="Enter CW ticket #"
            style={{
              width: '100%',
              padding: '8px 12px',
              fontSize: '13px',
              borderRadius: '6px',
              border: `1px solid ${autoDetected && ticketId ? '#10b981' : (darkMode ? '#4b5563' : '#d1d5db')}`,
              backgroundColor: darkMode ? '#374151' : '#ffffff',
              color: darkMode ? '#f3f4f6' : '#1f2937',
              outline: 'none',
              boxSizing: 'border-box'
            }}
          />
        </div>

        {/* Status Buttons */}
        <div style={{ marginBottom: '12px' }}>
          <label style={{
            display: 'block',
            fontSize: '11px',
            fontWeight: '600',
            color: darkMode ? '#9ca3af' : '#6b7280',
            marginBottom: '6px'
          }}>
            Set Status
          </label>
          <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
            {CW_STATUSES.map(status => (
              <button
                key={status}
                onClick={() => handleCWAction('ticket', { status })}
                disabled={loading || !ticketId.trim()}
                style={getButtonStyle(false, true)}
                onMouseEnter={(e) => {
                  if (!loading && ticketId.trim()) {
                    e.target.style.backgroundColor = darkMode ? '#4b5563' : '#f3f4f6';
                  }
                }}
                onMouseLeave={(e) => {
                  e.target.style.backgroundColor = darkMode ? '#374151' : '#ffffff';
                }}
              >
                {status}
              </button>
            ))}
          </div>
        </div>

        {/* Type/Classification Buttons */}
        <div style={{ marginBottom: '12px' }}>
          <label style={{
            display: 'block',
            fontSize: '11px',
            fontWeight: '600',
            color: darkMode ? '#9ca3af' : '#6b7280',
            marginBottom: '6px'
          }}>
            Set Type (Classification)
          </label>
          <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
            {CW_TYPES.map(type => (
              <button
                key={type}
                onClick={() => handleCWAction('ticket', { type })}
                disabled={loading || !ticketId.trim()}
                style={{
                  ...getButtonStyle(false, true),
                  backgroundColor: type === 'True Positive'
                    ? (darkMode ? '#991b1b' : '#fecaca')
                    : type === 'False Positive'
                    ? (darkMode ? '#065f46' : '#d1fae5')
                    : type === 'Benign Positive'
                    ? (darkMode ? '#1e40af' : '#dbeafe')
                    : (darkMode ? '#374151' : '#ffffff'),
                  color: type === 'True Positive'
                    ? (darkMode ? '#fecaca' : '#991b1b')
                    : type === 'False Positive'
                    ? (darkMode ? '#6ee7b7' : '#065f46')
                    : type === 'Benign Positive'
                    ? (darkMode ? '#93c5fd' : '#1e40af')
                    : (darkMode ? '#e5e7eb' : '#374151'),
                  borderColor: type === 'True Positive'
                    ? (darkMode ? '#dc2626' : '#f87171')
                    : type === 'False Positive'
                    ? (darkMode ? '#10b981' : '#34d399')
                    : type === 'Benign Positive'
                    ? (darkMode ? '#3b82f6' : '#60a5fa')
                    : (darkMode ? '#4b5563' : '#d1d5db')
                }}
              >
                {type}
              </button>
            ))}
          </div>
        </div>

        {/* Add Note */}
        <div style={{ marginBottom: '8px' }}>
          <label style={{
            display: 'block',
            fontSize: '11px',
            fontWeight: '600',
            color: darkMode ? '#9ca3af' : '#6b7280',
            marginBottom: '4px'
          }}>
            Add Internal Note
          </label>
          <div style={{ display: 'flex', gap: '8px' }}>
            <input
              type="text"
              value={noteText}
              onChange={(e) => setNoteText(e.target.value)}
              placeholder="Enter note text..."
              style={{
                flex: 1,
                padding: '8px 12px',
                fontSize: '13px',
                borderRadius: '6px',
                border: `1px solid ${darkMode ? '#4b5563' : '#d1d5db'}`,
                backgroundColor: darkMode ? '#374151' : '#ffffff',
                color: darkMode ? '#f3f4f6' : '#1f2937',
                outline: 'none'
              }}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && noteText.trim() && ticketId.trim() && !loading) {
                  handleCWAction('note', { text: noteText.trim(), internal: true });
                }
              }}
            />
            <button
              onClick={() => handleCWAction('note', { text: noteText.trim(), internal: true })}
              disabled={loading || !ticketId.trim() || !noteText.trim()}
              style={{
                ...getButtonStyle(false, false),
                opacity: (!ticketId.trim() || !noteText.trim() || loading) ? 0.5 : 1
              }}
            >
              Add
            </button>
          </div>
        </div>

        {/* Status Message */}
        {statusMessage && (
          <div style={{
            padding: '8px 12px',
            borderRadius: '6px',
            fontSize: '12px',
            backgroundColor: statusMessage.type === 'success'
              ? (darkMode ? 'rgba(16, 185, 129, 0.1)' : 'rgba(16, 185, 129, 0.1)')
              : (darkMode ? 'rgba(239, 68, 68, 0.1)' : 'rgba(239, 68, 68, 0.1)'),
            color: statusMessage.type === 'success'
              ? (darkMode ? '#6ee7b7' : '#059669')
              : (darkMode ? '#f87171' : '#dc2626'),
            border: `1px solid ${statusMessage.type === 'success'
              ? (darkMode ? '#10b981' : '#34d399')
              : (darkMode ? '#ef4444' : '#f87171')}`
          }}>
            {statusMessage.type === 'success' ? '✓' : '⚠'} {statusMessage.text}
          </div>
        )}

        {/* Loading Indicator */}
        {loading && (
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            padding: '8px 0',
            fontSize: '12px',
            color: darkMode ? '#9ca3af' : '#6b7280'
          }}>
            <span style={{ animation: 'pulse 1.5s ease-in-out infinite' }}>⏳</span>
            <span>Updating ConnectWise...</span>
          </div>
        )}
      </div>
    </div>
  );
}

// Initial analysis display component
function InitialAnalysis({ analysis, darkMode }) {
  const [expanded, setExpanded] = useState(true);

  if (!analysis) return null;

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
  // Get sessionId from route params
  const { sessionId: routeSessionId } = useParams();

  // Use route param, prop, or fallback to URL search params
  const sessionId = routeSessionId || propSessionId || (() => {
    const params = new URLSearchParams(window.location.search);
    return params.get('sessionId') || params.get('session');
  })();

  // State
  const [session, setSession] = useState(null);
  const [messages, setMessages] = useState([]);
  const [inputValue, setInputValue] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [initialLoading, setInitialLoading] = useState(true);
  const [pendingImages, setPendingImages] = useState([]); // Array of { data: base64, type: mediaType }

  // Refs
  const messagesEndRef = useRef(null);
  const inputRef = useRef(null);
  const inputContainerRef = useRef(null);

  // Scroll to bottom of messages
  const scrollToBottom = useCallback(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, []);

  // Handle paste event for images
  const handlePaste = useCallback((e) => {
    const items = e.clipboardData?.items;
    if (!items) return;

    for (const item of items) {
      if (item.type.startsWith('image/')) {
        e.preventDefault();
        const file = item.getAsFile();
        if (!file) continue;

        // Check file size (max 20MB for Claude vision)
        if (file.size > 20 * 1024 * 1024) {
          setError('Image too large. Maximum size is 20MB.');
          return;
        }

        // Convert to base64
        const reader = new FileReader();
        reader.onload = (event) => {
          const base64Data = event.target.result;
          // Extract the base64 content and media type
          const matches = base64Data.match(/^data:([^;]+);base64,(.+)$/);
          if (matches) {
            const [, mediaType, data] = matches;
            // Only allow supported image types
            const supportedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
            if (supportedTypes.includes(mediaType)) {
              setPendingImages(prev => [...prev, { data, type: mediaType }]);
            } else {
              setError(`Unsupported image type: ${mediaType}. Supported: JPEG, PNG, GIF, WebP`);
            }
          }
        };
        reader.onerror = () => {
          setError('Failed to read image from clipboard');
        };
        reader.readAsDataURL(file);
      }
    }
  }, []);

  // Remove a pending image
  const removePendingImage = useCallback((index) => {
    setPendingImages(prev => prev.filter((_, i) => i !== index));
  }, []);

  // Attach paste listener to the document when component is mounted
  // This allows pasting screenshots anywhere when the chat is visible
  useEffect(() => {
    const handleDocumentPaste = (e) => {
      // Only handle paste if this component's input or container is focused/active
      // or if the active element is within our component
      const container = inputContainerRef.current;
      if (container && (container.contains(document.activeElement) || document.activeElement === document.body)) {
        handlePaste(e);
      }
    };

    document.addEventListener('paste', handleDocumentPaste);
    return () => document.removeEventListener('paste', handleDocumentPaste);
  }, [handlePaste]);

  // Fetch session on mount
  useEffect(() => {
    if (!sessionId) {
      setError('No session ID provided. Please access this page with a valid session.');
      setInitialLoading(false);
      return;
    }

    async function fetchSession() {
      try {
        const response = await fetch(`${apiBaseUrl}/TriageSession?sessionId=${sessionId}`);

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
  const sendMessage = useCallback(async (messageText, images = []) => {
    // Allow sending if there's text OR images
    if ((!messageText.trim() && images.length === 0) || loading || !session) return;

    // Build user message with optional images
    const userMessage = {
      role: 'user',
      content: messageText.trim(),
      images: images.length > 0 ? images : undefined
    };

    // Optimistically add user message
    setMessages(prev => [...prev, userMessage]);
    setInputValue('');
    setPendingImages([]);
    setLoading(true);
    setError(null);

    try {
      // Build request body with message and optional images
      const requestBody = { message: messageText.trim() };
      if (images.length > 0) {
        requestBody.images = images;
      }

      const response = await fetch(`${apiBaseUrl}/TriageSession?sessionId=${sessionId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestBody)
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
      setPendingImages(images);
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
    sendMessage(inputValue, pendingImages);
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
        {/* Skip initial analysis messages (first 2) if initialAnalysis card is shown */}
        {(() => {
          const displayMessages = session.initialAnalysis && messages.length >= 2
            ? messages.slice(2)  // Skip initial prompt/response pair
            : messages;

          if (displayMessages.length === 0 && !session.initialAnalysis) {
            return (
              <div style={{
                textAlign: 'center',
                padding: '40px 20px',
                color: darkMode ? '#6b7280' : '#9ca3af'
              }}>
                <div style={{ fontSize: '32px', marginBottom: '12px' }}>&#x1F4AC;</div>
                <div>Ask follow-up questions about this incident</div>
              </div>
            );
          }

          return displayMessages.map((msg, idx) => (
            <ChatMessage key={idx} message={msg} darkMode={darkMode} />
          ));
        })()}

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

      {/* ConnectWise Actions Panel */}
      <ConnectWisePanel
        darkMode={darkMode}
        apiBaseUrl={apiBaseUrl}
        session={session}
        onSuccess={(action, data) => {
          console.log('ConnectWise action success:', action, data);
        }}
        onError={(err) => {
          console.error('ConnectWise action error:', err);
        }}
      />

      {/* Quick Actions */}
      {(() => {
        const incidentType = detectIncidentType(session.incidentTitle);
        const quickActions = QUICK_ACTIONS_BY_TYPE[incidentType] || QUICK_ACTIONS_BY_TYPE.general;
        const typeLabel = INCIDENT_TYPE_LABELS[incidentType] || INCIDENT_TYPE_LABELS.general;

        return (
          <div style={{
            padding: '12px 20px',
            backgroundColor: darkMode ? '#1f2937' : '#f9fafb',
            borderTop: `1px solid ${darkMode ? '#374151' : '#e5e7eb'}`
          }}>
            {/* Type Label */}
            <div style={{
              fontSize: '11px',
              fontWeight: '600',
              color: darkMode ? '#9ca3af' : '#6b7280',
              marginBottom: '8px',
              display: 'flex',
              alignItems: 'center',
              gap: '6px'
            }}>
              <span>{typeLabel.icon}</span>
              <span>{typeLabel.label}</span>
            </div>

            {/* Action Buttons */}
            <div style={{
              display: 'flex',
              gap: '8px',
              flexWrap: 'wrap'
            }}>
              {quickActions.map(action => (
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
          </div>
        );
      })()}

      {/* Input Area with Paste Support */}
      <div
        ref={inputContainerRef}
        style={{
          backgroundColor: darkMode ? '#1f2937' : '#f9fafb',
          borderTop: `1px solid ${darkMode ? '#374151' : '#e5e7eb'}`
        }}
      >
        {/* Pending Images Preview */}
        {pendingImages.length > 0 && (
          <div style={{
            padding: '12px 20px 0 20px',
            display: 'flex',
            flexWrap: 'wrap',
            gap: '8px'
          }}>
            {pendingImages.map((img, idx) => (
              <div
                key={idx}
                style={{
                  position: 'relative',
                  display: 'inline-block'
                }}
              >
                <img
                  src={`data:${img.type};base64,${img.data}`}
                  alt={`Pending screenshot ${idx + 1}`}
                  style={{
                    height: '60px',
                    borderRadius: '6px',
                    border: `2px solid ${darkMode ? '#3b82f6' : '#2563eb'}`,
                    objectFit: 'cover'
                  }}
                />
                <button
                  type="button"
                  onClick={() => removePendingImage(idx)}
                  style={{
                    position: 'absolute',
                    top: '-6px',
                    right: '-6px',
                    width: '20px',
                    height: '20px',
                    borderRadius: '50%',
                    border: 'none',
                    backgroundColor: darkMode ? '#ef4444' : '#dc2626',
                    color: '#ffffff',
                    fontSize: '12px',
                    fontWeight: 'bold',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    lineHeight: 1
                  }}
                  title="Remove image"
                >
                  &times;
                </button>
              </div>
            ))}
            <div style={{
              display: 'flex',
              alignItems: 'center',
              fontSize: '12px',
              color: darkMode ? '#9ca3af' : '#6b7280',
              marginLeft: '8px'
            }}>
              {pendingImages.length} image{pendingImages.length !== 1 ? 's' : ''} attached
            </div>
          </div>
        )}

        {/* Paste hint */}
        <div style={{
          padding: '4px 20px',
          fontSize: '11px',
          color: darkMode ? '#6b7280' : '#9ca3af'
        }}>
          Tip: Paste screenshots directly (Ctrl/Cmd+V)
        </div>

        <form
          onSubmit={handleSubmit}
          style={{
            padding: '8px 20px 16px 20px',
            display: 'flex',
            gap: '12px'
          }}
        >
          <input
            ref={inputRef}
            type="text"
            value={inputValue}
            onChange={(e) => setInputValue(e.target.value)}
            placeholder={pendingImages.length > 0 ? "Add a message about the screenshot(s)..." : "Ask a follow-up question..."}
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
            disabled={loading || (!inputValue.trim() && pendingImages.length === 0)}
            style={{
              padding: '10px 20px',
              fontSize: '14px',
              fontWeight: '600',
              borderRadius: '8px',
              border: 'none',
              backgroundColor: loading || (!inputValue.trim() && pendingImages.length === 0)
                ? (darkMode ? '#374151' : '#e5e7eb')
                : '#3b82f6',
              color: loading || (!inputValue.trim() && pendingImages.length === 0)
                ? (darkMode ? '#6b7280' : '#9ca3af')
                : '#ffffff',
              cursor: loading || (!inputValue.trim() && pendingImages.length === 0) ? 'not-allowed' : 'pointer',
              transition: 'background-color 0.15s'
            }}
            onMouseEnter={(e) => {
              if (!loading && (inputValue.trim() || pendingImages.length > 0)) {
                e.target.style.backgroundColor = '#2563eb';
              }
            }}
            onMouseLeave={(e) => {
              if (!loading && (inputValue.trim() || pendingImages.length > 0)) {
                e.target.style.backgroundColor = '#3b82f6';
              }
            }}
          >
            {loading ? 'Sending...' : 'Send'}
          </button>
        </form>
      </div>
    </div>
  );
}
