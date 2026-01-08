// /src/data/socPromptTemplates.js
// Pre-built SOC Documentation prompt templates for common security incidents
// These generate BOTH client-facing notes AND internal ticket notes

export const SOC_PROMPT_TEMPLATES = [
  {
    title: "Phishing Incident Documentation",
    description: "Generate client-facing summary and internal ticket notes for phishing/BEC incidents. Paste the incident details and get professional client communication plus casual internal notes.",
    category: "SOC Documentation",
    collection: "Incident Documentation",
    tags: ["phishing", "bec", "email", "social-engineering", "dual-output"],
    systemGuidance: `You are a senior SOC analyst helping document security incidents. You will generate TWO distinct outputs:

1. **CLIENT-FACING NOTES**: Professional, polished, and appropriate for sharing with the client's security team or management. Use formal language, avoid jargon where possible, focus on impact and remediation steps.

2. **INTERNAL TICKET NOTES**: Casual, technical, and meant for the internal SOC team. Include technical details, IOCs, timeline, analyst observations, and any "real talk" about the incident. Can use abbreviations and informal language.

Always maintain factual accuracy. Do not minimize or exaggerate the incident severity.`,
    userInstructions: `# Phishing/BEC Incident Documentation

Analyze the following incident and generate documentation:

{{context}}

---

## Generate the following sections:

### 📤 CLIENT-FACING NOTES
Write a professional summary suitable for sending to the client. Include:
- **Incident Summary**: 2-3 sentence overview
- **What Happened**: Clear explanation without excessive technical jargon
- **Impact Assessment**: What was/wasn't compromised
- **Actions Taken**: What the SOC team did to remediate
- **Recommendations**: Next steps for the client
- **Status**: Current state of the incident

### 📝 INTERNAL TICKET NOTES
Write casual internal notes for the SOC ticket. Include:
- **TL;DR**: One-liner summary
- **Timeline**: Key events with timestamps
- **Technical Details**: IOCs, email headers, URLs, file hashes
- **Analysis Notes**: Your observations, suspicions, things that stood out
- **Remediation Performed**: Specific actions taken
- **Follow-up Items**: Things to monitor or check later
- **Lessons Learned**: Anything to note for future incidents`,
    variables: [
      {
        name: "severity",
        label: "Severity Level",
        type: "enum",
        required: true,
        description: "The severity level of the incident",
        options: ["Low", "Medium", "High", "Critical"]
      },
      {
        name: "client_name",
        label: "Client Name",
        type: "string",
        required: false,
        description: "Client organization name (optional)"
      },
      {
        name: "affected_users",
        label: "Affected Users",
        type: "string",
        required: false,
        description: "Number or list of affected users"
      }
    ],
    modelSettings: { temperature: 0.4, maxTokens: 3000 }
  },
  {
    title: "Malware Detection Documentation",
    description: "Document malware/ransomware detections with client-ready summary and detailed internal notes. Handles endpoint detections, quarantined files, and remediation steps.",
    category: "SOC Documentation",
    collection: "Incident Documentation",
    tags: ["malware", "ransomware", "endpoint", "edr", "detection", "dual-output"],
    systemGuidance: `You are a senior SOC analyst documenting a malware detection incident. Generate TWO outputs:

1. **CLIENT-FACING NOTES**: Professional communication for the client. Explain what was detected, the risk level, and what actions were taken. Avoid causing unnecessary panic while being honest about the threat.

2. **INTERNAL TICKET NOTES**: Technical deep-dive for the SOC team. Include all IOCs, detection details, EDR actions, and your analysis of the malware behavior and potential impact.

Be precise with technical details. If information is missing, note what additional investigation is needed.`,
    userInstructions: `# Malware Detection Documentation

Analyze the following detection and generate documentation:

{{context}}

---

## Generate the following sections:

### 📤 CLIENT-FACING NOTES
Professional summary for the client:
- **Detection Summary**: What was detected and where
- **Threat Assessment**: How serious is this? What's the potential impact?
- **Containment Status**: Was the threat contained/quarantined/removed?
- **Affected Systems**: Which endpoints/users were involved
- **Actions Taken**: Remediation steps performed
- **Recommendations**: What the client should do (password resets, monitoring, etc.)
- **Current Status**: Is the threat fully remediated?

### 📝 INTERNAL TICKET NOTES
Technical notes for internal team:
- **TL;DR**: Quick summary
- **Detection Info**: Alert name, EDR platform, detection rule/signature
- **IOCs**: File hashes (MD5/SHA256), file paths, registry keys, network indicators
- **Malware Analysis**: Family, capabilities, known behaviors
- **Timeline**: Detection → Investigation → Remediation
- **EDR Actions**: What the EDR did automatically, what we did manually
- **Scope Check**: Other systems to check, lateral movement indicators
- **Follow-up**: Items to monitor, scheduled scans, user interviews
- **Notes**: Anything weird, false positive considerations, detection gaps`,
    variables: [
      {
        name: "severity",
        label: "Severity Level",
        type: "enum",
        required: true,
        description: "The severity level of the detection",
        options: ["Low", "Medium", "High", "Critical"]
      },
      {
        name: "detection_source",
        label: "Detection Source",
        type: "enum",
        required: false,
        description: "What system detected this?",
        options: ["CrowdStrike", "Defender", "SentinelOne", "Carbon Black", "Other EDR", "Email Gateway", "SIEM Alert"]
      },
      {
        name: "containment_status",
        label: "Containment Status",
        type: "enum",
        required: false,
        description: "Current containment state",
        options: ["Contained", "Quarantined", "Isolated", "Remediated", "Under Investigation"]
      }
    ],
    modelSettings: { temperature: 0.3, maxTokens: 3000 }
  },
  {
    title: "Suspicious Login/Access Documentation",
    description: "Document suspicious authentication events, impossible travel, brute force attempts, or unauthorized access. Generates client summary and detailed internal investigation notes.",
    category: "SOC Documentation",
    collection: "Incident Documentation",
    tags: ["authentication", "login", "brute-force", "impossible-travel", "unauthorized-access", "dual-output"],
    systemGuidance: `You are a senior SOC analyst documenting a suspicious authentication or access event. Generate TWO outputs:

1. **CLIENT-FACING NOTES**: Clear communication about the suspicious activity. Explain what triggered the alert, whether the account was compromised, and what security measures have been applied.

2. **INTERNAL TICKET NOTES**: Detailed investigation notes including IP analysis, geolocation data, authentication logs review, and your assessment of whether this is a true positive or false positive.

Be objective in your analysis. Distinguish between confirmed compromise and suspicious activity requiring further investigation.`,
    userInstructions: `# Suspicious Login/Access Documentation

Analyze the following authentication event and generate documentation:

{{context}}

---

## Generate the following sections:

### 📤 CLIENT-FACING NOTES
Professional summary for client:
- **Alert Summary**: What suspicious activity was detected
- **Account Affected**: Which user account(s) triggered the alert
- **Risk Assessment**: Was the account actually compromised?
- **Geographic Analysis**: Login locations and whether they're expected
- **Security Actions Taken**: Password resets, MFA enforcement, session revocation
- **Recommendations**: Steps the client/user should take
- **Status**: Current account security state

### 📝 INTERNAL TICKET NOTES
Detailed investigation notes:
- **TL;DR**: One-liner assessment
- **Alert Details**: Rule name, source system, raw alert data
- **Authentication Analysis**:
  - IP addresses involved (with geo and reputation)
  - User agent strings
  - Authentication methods (password, MFA, legacy auth)
  - Success/failure patterns
- **Timeline**: Login attempts with timestamps
- **Behavioral Analysis**: Normal vs. abnormal patterns for this user
- **Investigation Steps**: What we checked and what we found
- **Verdict**: True positive, false positive, or inconclusive (with reasoning)
- **Remediation Actions**: Exactly what we did
- **Follow-up**: Monitoring items, user verification needed`,
    variables: [
      {
        name: "severity",
        label: "Severity Level",
        type: "enum",
        required: true,
        description: "Alert severity",
        options: ["Low", "Medium", "High", "Critical"]
      },
      {
        name: "alert_type",
        label: "Alert Type",
        type: "enum",
        required: false,
        description: "Type of authentication alert",
        options: ["Impossible Travel", "Brute Force", "Password Spray", "Suspicious Location", "Legacy Auth", "Risky Sign-in", "Other"]
      },
      {
        name: "account_compromised",
        label: "Account Compromised?",
        type: "enum",
        required: false,
        description: "Assessment of compromise",
        options: ["Confirmed Compromised", "Likely Compromised", "Suspicious - Investigating", "Likely Benign", "False Positive"]
      }
    ],
    modelSettings: { temperature: 0.3, maxTokens: 3000 }
  },
  {
    title: "Data Exfiltration/DLP Documentation",
    description: "Document data loss prevention alerts, potential exfiltration events, or unauthorized data transfers. Includes client communication and internal investigation details.",
    category: "SOC Documentation",
    collection: "Incident Documentation",
    tags: ["dlp", "data-exfiltration", "data-loss", "insider-threat", "dual-output"],
    systemGuidance: `You are a senior SOC analyst documenting a potential data exfiltration or DLP event. This is sensitive - generate TWO outputs:

1. **CLIENT-FACING NOTES**: Professional, measured communication. Explain what was detected without assuming malicious intent. Focus on data protection and policy compliance. Be careful with accusations.

2. **INTERNAL TICKET NOTES**: Candid technical analysis. Include your honest assessment of intent (accidental vs. malicious), data sensitivity, and scope of potential exposure. Note if HR/Legal involvement may be needed.

Handle this topic with appropriate sensitivity as it may involve employee misconduct.`,
    userInstructions: `# Data Exfiltration/DLP Documentation

Analyze the following DLP event and generate documentation:

{{context}}

---

## Generate the following sections:

### 📤 CLIENT-FACING NOTES
Professional summary for client leadership:
- **Alert Summary**: What data movement was detected
- **Data Classification**: Type and sensitivity of data involved
- **User Involved**: Who triggered the alert (without accusatory language)
- **Destination**: Where the data was sent/copied to
- **Volume Assessment**: Amount of data involved
- **Business Impact**: Potential exposure or compliance implications
- **Actions Taken**: Blocking, investigation, containment
- **Recommendations**: Policy review, user training, technical controls
- **Next Steps**: What happens from here

### 📝 INTERNAL TICKET NOTES
Candid internal analysis:
- **TL;DR**: Quick summary with honest assessment
- **DLP Rule Triggered**: Which policy, what threshold
- **Data Details**:
  - File names/types
  - Data classification labels
  - Sensitive content detected
- **User Behavior Analysis**:
  - Historical DLP alerts for this user
  - Legitimate business need assessment
  - Intent assessment (accidental/negligent/malicious)
- **Exfiltration Vector**: USB, email, cloud upload, etc.
- **Timeline**: Activity sequence
- **Scope Investigation**: What else did this user access/transfer?
- **Evidence Preservation**: Screenshots, logs retained
- **HR/Legal Flag**: Does this need escalation?
- **Follow-up**: Monitoring, interview, policy enforcement`,
    variables: [
      {
        name: "severity",
        label: "Severity Level",
        type: "enum",
        required: true,
        description: "Severity based on data sensitivity",
        options: ["Low", "Medium", "High", "Critical"]
      },
      {
        name: "data_classification",
        label: "Data Classification",
        type: "enum",
        required: false,
        description: "Sensitivity level of data involved",
        options: ["Public", "Internal", "Confidential", "Highly Confidential", "PII", "PHI", "Financial", "Unknown"]
      },
      {
        name: "intent_assessment",
        label: "Intent Assessment",
        type: "enum",
        required: false,
        description: "Your assessment of user intent",
        options: ["Likely Accidental", "Negligent", "Policy Violation", "Potentially Malicious", "Under Investigation"]
      }
    ],
    modelSettings: { temperature: 0.3, maxTokens: 3000 }
  },
  {
    title: "Vulnerability/Patch Documentation",
    description: "Document critical vulnerability discoveries, patch status, or security advisory responses. Generates executive summary for client and technical details for internal tracking.",
    category: "SOC Documentation",
    collection: "Incident Documentation",
    tags: ["vulnerability", "cve", "patch", "security-advisory", "dual-output"],
    systemGuidance: `You are a senior SOC analyst documenting a vulnerability or patch management event. Generate TWO outputs:

1. **CLIENT-FACING NOTES**: Executive-friendly summary explaining the vulnerability, its risk to their environment, and the remediation plan. Translate CVE details into business impact.

2. **INTERNAL TICKET NOTES**: Technical details including CVE specifics, affected systems inventory, patch deployment status, and compensating controls. Include workarounds if patching is delayed.

Be accurate about severity - don't undersell critical vulnerabilities or oversell low-risk ones.`,
    userInstructions: `# Vulnerability/Patch Documentation

Analyze the following vulnerability information and generate documentation:

{{context}}

---

## Generate the following sections:

### 📤 CLIENT-FACING NOTES
Executive summary for client:
- **Vulnerability Overview**: What is this vulnerability (in plain terms)
- **CVE Details**: ID, CVSS score, severity rating
- **Business Risk**: What could happen if exploited in their environment
- **Affected Systems**: What's vulnerable in their infrastructure
- **Exploitation Status**: Is this being actively exploited in the wild?
- **Remediation Plan**: Patching timeline and approach
- **Interim Mitigations**: What's protecting them until patched
- **Recommended Actions**: What client should prioritize

### 📝 INTERNAL TICKET NOTES
Technical tracking notes:
- **TL;DR**: Vuln summary with priority
- **CVE Details**:
  - CVE ID and aliases
  - CVSS score breakdown
  - CWE classification
  - Attack vector and complexity
- **Affected Asset Inventory**: Systems identified as vulnerable
- **Exposure Assessment**: Internet-facing? Internal only?
- **Exploitation Intel**:
  - Known exploits/POCs
  - Active exploitation observed
  - Threat actor usage
- **Patch Status**:
  - Vendor patch availability
  - Deployment timeline
  - Systems patched vs pending
- **Compensating Controls**: WAF rules, network segmentation, monitoring
- **Testing Notes**: Any issues with the patch
- **Follow-up**: Verification scans, outlier systems`,
    variables: [
      {
        name: "severity",
        label: "Severity Level",
        type: "enum",
        required: true,
        description: "Vulnerability severity",
        options: ["Low", "Medium", "High", "Critical"]
      },
      {
        name: "cve_id",
        label: "CVE ID",
        type: "string",
        required: false,
        description: "CVE identifier (e.g., CVE-2024-1234)"
      },
      {
        name: "patch_status",
        label: "Patch Status",
        type: "enum",
        required: false,
        description: "Current patch deployment status",
        options: ["Not Available", "Available - Not Deployed", "In Progress", "Deployed - Partial", "Deployed - Complete"]
      }
    ],
    modelSettings: { temperature: 0.3, maxTokens: 3000 }
  },
  {
    title: "Generic Incident Documentation",
    description: "Flexible template for any security incident type. Generates professional client communication and detailed internal ticket notes. Customize with your incident context.",
    category: "SOC Documentation",
    collection: "Incident Documentation",
    tags: ["incident", "generic", "flexible", "dual-output"],
    systemGuidance: `You are a senior SOC analyst documenting a security incident. Generate TWO distinct outputs tailored to different audiences:

1. **CLIENT-FACING NOTES**: Professional, polished communication suitable for the client's security team, management, or stakeholders. Use clear language, focus on impact and resolution, and maintain a helpful, competent tone.

2. **INTERNAL TICKET NOTES**: Casual but thorough notes for the SOC team. Include technical details, your honest analysis, timeline, IOCs, and anything relevant for future reference. Feel free to use abbreviations and informal language.

Adapt your output to the specific incident type provided in the context.`,
    userInstructions: `# Security Incident Documentation

Analyze the following incident and generate comprehensive documentation:

**Incident Type:** {{incident_type}}
**Severity:** {{severity}}

{{context}}

---

## Generate the following sections:

### 📤 CLIENT-FACING NOTES
Professional summary for external stakeholders:
- **Incident Summary**: Clear overview of what occurred
- **Timeline**: Key events in chronological order
- **Impact Assessment**: What was affected and how
- **Root Cause**: What allowed this to happen (if determined)
- **Actions Taken**: Containment and remediation steps
- **Current Status**: Resolved, ongoing, monitoring
- **Recommendations**: Suggested improvements or follow-ups
- **Point of Contact**: Who to reach for questions

### 📝 INTERNAL TICKET NOTES
Detailed internal documentation:
- **TL;DR**: One-sentence summary
- **Detection**: How we found out, alert source
- **Investigation Timeline**: Detailed chronology with timestamps
- **Technical Details**: All relevant IOCs, logs, evidence
- **Analysis**: Your observations and conclusions
- **Remediation Log**: Exactly what was done, by whom, when
- **Gaps Identified**: Detection or process improvements needed
- **Follow-up Tasks**: Open items requiring attention
- **Lessons Learned**: What to do differently next time`,
    variables: [
      {
        name: "incident_type",
        label: "Incident Type",
        type: "enum",
        required: true,
        description: "Category of security incident",
        options: ["Phishing", "Malware", "Ransomware", "Unauthorized Access", "Data Breach", "DDoS", "Insider Threat", "Account Compromise", "Vulnerability Exploitation", "Policy Violation", "Other"]
      },
      {
        name: "severity",
        label: "Severity Level",
        type: "enum",
        required: true,
        description: "Incident severity",
        options: ["Low", "Medium", "High", "Critical"]
      },
      {
        name: "status",
        label: "Current Status",
        type: "enum",
        required: false,
        description: "Current incident status",
        options: ["Active - Investigating", "Active - Containing", "Active - Remediating", "Monitoring", "Resolved", "Closed"]
      }
    ],
    modelSettings: { temperature: 0.4, maxTokens: 3500 }
  },
  {
    title: "Shift Handoff Summary",
    description: "Generate end-of-shift handoff notes. Summarizes active incidents, ongoing investigations, and items needing follow-up for the incoming analyst.",
    category: "SOC Documentation",
    collection: "SOC Operations",
    tags: ["handoff", "shift", "transition", "summary", "dual-output"],
    systemGuidance: `You are a SOC analyst preparing shift handoff notes. Generate TWO outputs:

1. **FORMAL HANDOFF REPORT**: Professional summary suitable for documentation or management visibility. Clean, organized, and comprehensive.

2. **INFORMAL HANDOFF NOTES**: Casual notes for the incoming analyst - the "real talk" version with your honest takes, heads-ups, and context that might not go in formal docs.

Focus on actionable information. The incoming analyst needs to hit the ground running.`,
    userInstructions: `# Shift Handoff Summary

Generate handoff notes based on the following shift activity:

{{context}}

---

## Generate the following sections:

### 📤 FORMAL HANDOFF REPORT
Professional documentation:
- **Shift Coverage**: Date, time, analyst name
- **Shift Summary**: Overall activity level and notable events
- **Active Incidents**:
  - Incident ID, type, severity
  - Current status
  - Next steps required
- **Ongoing Investigations**: Items in progress
- **Escalations**: Anything escalated to management/client
- **Pending Items**: Tasks awaiting action or information
- **Monitoring Notes**: Anything requiring continued observation
- **Shift Statistics**: Alert count, incidents opened/closed

### 📝 INFORMAL HANDOFF NOTES
Real-talk for the next analyst:
- **How was the shift?**: Quick vibe check
- **Hot items**: What needs attention first
- **Heads up**: Things to watch out for
- **Almost done**: Items close to closure
- **Client context**: Any client-specific notes
- **Tool issues**: Any platform problems today
- **Random notes**: Anything else the next person should know`,
    variables: [
      {
        name: "shift_type",
        label: "Shift",
        type: "enum",
        required: false,
        description: "Which shift is ending",
        options: ["Day Shift", "Swing Shift", "Night Shift", "Weekend Coverage"]
      },
      {
        name: "activity_level",
        label: "Activity Level",
        type: "enum",
        required: false,
        description: "Overall shift activity",
        options: ["Quiet", "Normal", "Busy", "Slammed"]
      }
    ],
    modelSettings: { temperature: 0.5, maxTokens: 2500 }
  }
];

export default SOC_PROMPT_TEMPLATES;
