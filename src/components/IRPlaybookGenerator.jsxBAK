import React, { useState } from 'react';
import ReactMarkdown from 'react-markdown';

export default function IRPlaybookGenerator({ darkMode }) {
  const [alertType, setAlertType] = useState('');
  const [incidentDetails, setIncidentDetails] = useState('');
  const [playbook, setPlaybook] = useState(null);
  const [isGenerating, setIsGenerating] = useState(false);

  const alertCategories = [
    { value: 'malware', label: 'Malware Detection' },
    { value: 'phishing', label: 'Phishing/Credential Theft' },
    { value: 'ransomware', label: 'Ransomware' },
    { value: 'lateral-movement', label: 'Lateral Movement' },
    { value: 'privilege-escalation', label: 'Privilege Escalation' },
    { value: 'data-exfiltration', label: 'Data Exfiltration' },
    { value: 'suspicious-signin', label: 'Suspicious Sign-In' },
    { value: 'brute-force', label: 'Brute Force Attack' },
    { value: 'command-control', label: 'Command & Control Activity' },
    { value: 'persistence', label: 'Persistence Mechanism' },
    { value: 'insider-threat', label: 'Insider Threat' },
    { value: 'custom', label: 'Custom Scenario' }
  ];

  const generatePlaybook = async () => {
    setIsGenerating(true);
    setPlaybook(null);

    try {
      const functionUrl = 'https://threatdefender-functions-befyasdqduhsa8at.eastus-01.azurewebsites.net/api/irplaybook';
      
      const prompt = `You are an expert SOC analyst creating an incident response playbook. Generate a comprehensive, actionable playbook for the following scenario:

**Alert Type:** ${alertCategories.find(c => c.value === alertType)?.label || alertType}

**Incident Details:**
${incidentDetails || 'Standard detection scenario'}

Create a structured playbook with the following sections:

# 1. Executive Summary
Brief overview of the threat and immediate actions needed.

# 2. Initial Triage (First 15 minutes)
- Quick assessment steps
- Severity classification criteria
- Immediate containment actions if needed

# 3. Investigation Steps
Detailed step-by-step investigation process including:
- What to look for in logs
- Key indicators of compromise
- Timeline reconstruction
- Scope determination

# 4. KQL Investigation Queries
Provide specific Microsoft Sentinel KQL queries for:
- Initial detection validation
- Lateral movement detection
- Timeline analysis
- Affected assets identification
- User activity review

# 5. Containment Actions
Immediate actions to stop the attack:
- Account actions (disable, reset)
- Device isolation
- Network segmentation
- Application blocks

# 6. Eradication Steps
How to remove the threat:
- Malware removal procedures
- Account cleanup
- Configuration changes
- Persistence removal

# 7. Recovery & Remediation
Steps to restore normal operations:
- System restoration
- Access restoration
- Monitoring enhancement

# 8. Post-Incident Activities
- Evidence preservation
- Lesson learned documentation
- Rule tuning recommendations
- Preventive measures

Make it specific to Microsoft Defender/Sentinel ecosystem. Include realistic examples and be action-oriented for MSSP analysts.`;

      const response = await fetch(functionUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          originalQuery: prompt,
          updatedQuery: "Generate playbook"
        })
      });

      if (!response.ok) {
        throw new Error(`Worker request failed: ${response.status}`);
      }

      const data = await response.json();
      const playbookContent = data.content[0].text;
      setPlaybook(playbookContent);
    } catch (error) {
      console.error("Error generating playbook:", error);
      setPlaybook("Failed to generate playbook. Please try again.");
    } finally {
      setIsGenerating(false);
    }
  };

  const exportPlaybook = () => {
    const timestamp = new Date().toISOString().split('T')[0];
    const alertLabel = alertCategories.find(c => c.value === alertType)?.label || alertType;
    
    const htmlContent = `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>IR Playbook - ${alertLabel}</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 1000px; margin: 40px auto; padding: 20px; line-height: 1.6; }
    h1 { color: #dc2626; border-bottom: 3px solid #dc2626; padding-bottom: 10px; }
    h2 { color: #1e40af; margin-top: 30px; border-left: 4px solid #1e40af; padding-left: 15px; }
    h3 { color: #374151; margin-top: 20px; }
    .header { background: #fee2e2; padding: 20px; border-left: 4px solid #dc2626; margin-bottom: 30px; border-radius: 4px; }
    .metadata { background: #f3f4f6; padding: 15px; border-radius: 8px; margin-bottom: 20px; }
    pre { background: #1f2937; color: #f9fafb; padding: 15px; border-radius: 8px; overflow-x: auto; }
    code { font-family: 'Courier New', monospace; }
    ul, ol { margin: 10px 0; padding-left: 25px; }
    li { margin: 5px 0; }
    .warning { background: #fef3c7; border-left: 4px solid #f59e0b; padding: 15px; margin: 15px 0; border-radius: 4px; }
    .info { background: #dbeafe; border-left: 4px solid #3b82f6; padding: 15px; margin: 15px 0; border-radius: 4px; }
    .footer { margin-top: 50px; padding-top: 20px; border-top: 2px solid #e5e7eb; text-align: center; color: #6b7280; }
  </style>
</head>
<body>
  <div class="header">
    <h1>🛡️ Incident Response Playbook</h1>
    <h2 style="margin-top: 10px; border: none; padding: 0;">${alertLabel}</h2>
  </div>
  
  <div class="metadata">
    <p><strong>Generated:</strong> ${new Date().toLocaleString()}</p>
    <p><strong>Organization:</strong> eGroup Enabling Technologies - ThreatHunter MSSP</p>
    <p><strong>Alert Category:</strong> ${alertLabel}</p>
  </div>

  ${playbook.replace(/\n/g, '<br>').replace(/# /g, '<h2>').replace(/## /g, '<h3>')}

  <div class="footer">
    <p><strong>ThreatDefender Incident Response System</strong></p>
    <p>eGroup Enabling Technologies | ThreatHunter MSSP Team</p>
    <p style="font-size: 12px; margin-top: 10px;">This playbook is a guide. Adapt procedures based on specific incident context and organizational policies.</p>
  </div>
</body>
</html>`;

    const blob = new Blob([htmlContent], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `IR-Playbook-${alertLabel.replace(/\s+/g, '-')}-${timestamp}.html`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleReset = () => {
    setAlertType('');
    setIncidentDetails('');
    setPlaybook(null);
  };

  return (
    <div className={`min-h-screen p-6 ${darkMode ? 'bg-gray-900' : 'bg-gray-50'}`}>
      <div className="max-w-6xl mx-auto">
        <div className="mb-8 flex items-center justify-between">
          <div>
            <h1 className={`text-3xl font-bold mb-2 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
              🚨 ThreatDefender - IR Playbook Generator
            </h1>
            <p className={darkMode ? 'text-gray-400' : 'text-gray-600'}>
              Generate incident response playbooks powered by AI
            </p>
          </div>
        </div>

        {!playbook ? (
          <div className={`rounded-lg shadow p-8 ${darkMode ? 'bg-gray-800' : 'bg-white'}`}>
            <h2 className={`text-xl font-bold mb-6 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
              Generate Playbook
            </h2>

            <div className="space-y-6">
              <div>
                <label className={`block text-sm font-semibold mb-2 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                  Alert Type / Incident Category
                </label>
                <select
                  value={alertType}
                  onChange={(e) => setAlertType(e.target.value)}
                  className={`w-full p-3 border rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent ${
                    darkMode 
                      ? 'bg-gray-900 border-gray-700 text-gray-300' 
                      : 'bg-white border-gray-300 text-gray-900'
                  }`}
                >
                  <option value="">Select an alert type...</option>
                  {alertCategories.map(cat => (
                    <option key={cat.value} value={cat.value}>{cat.label}</option>
                  ))}
                </select>
              </div>

              <div>
                <label className={`block text-sm font-semibold mb-2 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                  Incident Details (Optional)
                </label>
                <textarea
                  value={incidentDetails}
                  onChange={(e) => setIncidentDetails(e.target.value)}
                  placeholder="Add any specific context: affected users, systems, timeline, initial observations, etc."
                  className={`w-full h-48 p-3 border rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent ${
                    darkMode 
                      ? 'bg-gray-900 border-gray-700 text-gray-300' 
                      : 'bg-white border-gray-300 text-gray-900'
                  }`}
                />
              </div>

              <button
                onClick={generatePlaybook}
                disabled={!alertType || isGenerating}
                className="w-full px-6 py-4 bg-red-600 text-white rounded-md font-semibold hover:bg-red-700 disabled:bg-gray-300 disabled:cursor-not-allowed transition text-lg"
              >
                {isGenerating ? '⚡ Generating Playbook...' : '🚨 Generate IR Playbook'}
              </button>
            </div>
          </div>
        ) : (
          <>
            <div className={`rounded-lg shadow overflow-hidden mb-6 ${darkMode ? 'bg-gray-800' : 'bg-white'}`}>
              <div className={`p-6 border-b ${darkMode ? 'bg-gray-900 border-gray-700' : 'bg-red-50 border-red-200'}`}>
                <h2 className={`text-2xl font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                  Generated Playbook
                </h2>
                <p className={`mt-2 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                  {alertCategories.find(c => c.value === alertType)?.label}
                </p>
              </div>

              <div className={`p-6 prose max-w-none ${
                darkMode ? 'text-gray-300 prose-invert prose-headings:text-white' : 'text-gray-800'
              }`}>
                <ReactMarkdown
                  components={{
                    h1: ({node, ...props}) => <h1 className={`text-2xl font-bold mt-6 mb-4 pb-2 border-b-2 ${darkMode ? 'text-red-400 border-red-600' : 'text-red-600 border-red-300'}`} {...props} />,
                    h2: ({node, ...props}) => <h2 className={`text-xl font-bold mt-6 mb-3 ${darkMode ? 'text-blue-400' : 'text-blue-600'}`} {...props} />,
                    h3: ({node, ...props}) => <h3 className={`text-lg font-semibold mt-4 mb-2 ${darkMode ? 'text-gray-200' : 'text-gray-800'}`} {...props} />,
                    pre: ({node, ...props}) => <pre className="bg-gray-900 text-gray-100 p-4 rounded-lg overflow-x-auto my-4" {...props} />,
                    code: ({node, inline, ...props}) => inline 
                      ? <code className={`px-1 py-0.5 rounded ${darkMode ? 'bg-gray-700' : 'bg-gray-200'}`} {...props} />
                      : <code {...props} />,
                    ul: ({node, ...props}) => <ul className="list-disc pl-6 my-3 space-y-1" {...props} />,
                    ol: ({node, ...props}) => <ol className="list-decimal pl-6 my-3 space-y-1" {...props} />,
                  }}
                >
                  {playbook}
                </ReactMarkdown>
              </div>
            </div>

            <div className="flex gap-4 flex-wrap">
              <button
                onClick={handleReset}
                className="px-6 py-3 bg-gray-600 text-white rounded-md font-semibold hover:bg-gray-700 transition"
              >
                ← New Playbook
              </button>
              <button
                onClick={exportPlaybook}
                className="px-6 py-3 bg-green-600 text-white rounded-md font-semibold hover:bg-green-700 transition"
              >
                📄 Export Playbook
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
