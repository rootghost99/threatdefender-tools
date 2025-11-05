# 🛡️ ThreatDefender Operations Suite  
**eGroup Enabling Technologies | ThreatHunter MSSP Team**

A web-based toolkit built by defenders, for defenders — empowering analysts to streamline investigation, response, and handoff workflows across Microsoft Sentinel and the Defender stack.

---

## ⚙️ Overview

**ThreatDefender Operations Suite** is an integrated set of tools designed to simplify and accelerate SOC operations.  
From KQL diffing to IR playbook generation, the suite helps analysts spend less time tab-switching and more time threat-hunting.

---

## 🚀 Features

### 🔍 **KQL Diff Viewer**
Compare two versions of Sentinel Analytic Rule queries with line-by-line highlighting.  
Includes:
- **Smart Diff Engine** to detect syntax and logic changes  
- **False Positive Checker** powered by pattern recognition  
- **AI Query Summary** to instantly explain query purpose and logic  
- **Exportable Report** for documentation and peer review  

> Ideal for rule reviews, tuning validation, and content version control.

---

### ⚔️ **IR Playbook Generator**
Quickly build structured incident response playbooks based on incident category and context.  
Provide details like affected users, IPs, or systems, and generate:
- Step-by-step **Response Procedures**
- Automated containment and recovery checklists
- Exportable reports for client or internal use  

> Consistent, fast, and audit-ready — every time.

---

### 🔄 **SOC Shift Handoff**
Generate standardized shift handoff reports in seconds.  
Include ongoing incidents, key investigations, and alerts of note to ensure smooth transitions.  

> Built for multi-analyst SOC environments where communication matters.

---

### 🌐 **Threat Intel Lookup**
Real-time IOC enrichment and correlation from sources like AlienVault OTX, VirusTotal, Defender TI, AbuseIPDB, Greynoise and Shodan.
Turn raw indicators into actionable insights.

---

### 📚 **Prompt Gallery**
A centralized library of reusable AI prompts for security analysis workflows.
Features include:
- **Browse & Search** - Find the right prompt for your task (triage, forensics, client communication)
- **Dynamic Variables** - Fill in context-specific details like usernames, IPs, or severity levels
- **Run & Export** - Execute prompts with incident data and copy results to tickets or emails
- **Audit Trail** - Track all prompt executions with full usage statistics and accountability
- **Custom Prompts** - Create and edit prompts with Markdown support and variable definitions

> Streamline repetitive analysis tasks with AI-powered prompts while maintaining full audit compliance.

---

## 🧠 Vision

> “The best security operations are the ones where humans and automation work in sync.”  
ThreatDefender bridges that gap — giving analysts practical tools that **amplify human intuition** with **structured automation**.

---

## 🧩 Tech Stack

| Layer | Technology |
|-------|-------------|
| Frontend | React + Tailwind CSS |
| Backend | Azure Functions (Node.js) |
| Storage | Azure Table Storage |
| AI | Azure OpenAI (GPT-4) |
| Integration | Microsoft Sentinel, Defender APIs, Threat Intel APIs |
| Hosting | Azure Static Web Apps |

---

## 🧑‍💻 License

This project is maintained by eGroup Enabling Technologies – ThreatDefender MSSP Team.
© 2025. All Rights Reserved.
