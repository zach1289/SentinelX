# SentinelX
End-to-End Automated SOC &amp; Threat Response Framework (Wazuh, Suricata/Snort, Splunk, n8n, VT, ANY.RUN, Palo Alto API)

---

## 🧩 Overview  

**SentinelX** is a fully automated **Security Operations Center (SOC) Lab Framework** that combines **SIEM**, **SOAR**, **IDS/IPS**, and **EDR** technologies into one integrated ecosystem.  

It demonstrates advanced **threat detection**, **incident response**, **threat intelligence enrichment**, and **AI-assisted firewall auditing** — all orchestrated through **n8n**, **Wazuh**, **Suricata**, **Snort**, and **Splunk**.  

This project turns complex manual investigations into **automated, intelligent, real-time workflows**, ideal for showcasing professional SOC analyst, automation engineer, and cybersecurity researcher skills.

---

## 🧠 Architecture Overview  

```
              ┌────────────────────────────┐
              │        Palo Alto FW        │
              │  Rule Audit via API + AI   │
              └────────────┬───────────────┘
                           │
             ┌─────────────▼────────────────┐
             │       Splunk SIEM            │
             │ Log Ingestion + Correlation  │
             │  (Wazuh, Suricata, Snort)    │
             └─────────────┬────────────────┘
                           │
             ┌─────────────▼───────────────┐
             │         n8n SOAR Engine      │
             │  Automation, Enrichment, IR  │
             └─────────────┬───────────────┘
                           │
             ┌─────────────▼───────────────┐
             │ External Integrations:       │
             │ VirusTotal, ANY.RUN, Slack,  │
             │ Gmail, ServiceNow            │
             └──────────────────────────────┘
```

---

## ⚙️ Core Components  

| Component | Purpose | Key Features |
|------------|----------|---------------|
| **Wazuh** | SIEM & EDR | Log collection, endpoint alerts, file integrity, rule-based triggers |
| **Suricata / Snort** | IDS/IPS | Network intrusion detection, DNS/HTTP/TLS inspection |
| **Splunk** | SIEM Analytics | Log correlation, dashboards, alert creation |
| **n8n** | SOAR | Automated alert enrichment, workflow orchestration |
| **Palo Alto API + Python** | Firewall Analysis | Pulls rule data, AI-assisted risk analysis |
| **VirusTotal / ANY.RUN / Slack / Gmail / ServiceNow** | Integrations | Threat intel, sandbox analysis, real-time alerts |

---

## 🔄 End-to-End Workflow Summary  

### **1️⃣ Firewall Intelligence Audit (AI-Driven)**  
- Fetches all **Palo Alto firewall rules** via API.  
- Python script analyzes hit counts, timestamps, and address objects.  
- AI agent flags **unused, risky, or misconfigured rules**.  
- Outputs **HTML audit report** with remediation tips.

### **2️⃣ SSH Brute-Force Detection & Response**  
- **Splunk** searches for repeated failed SSH logins.  
- Triggers an **n8n webhook** with alert JSON payload.  
- **n8n workflow** performs:
  - GeoIP + VirusTotal lookup  
  - Slack & Gmail alerts  
  - Optional firewall block via Palo Alto API

### **3️⃣ Malicious Domain Lookup Automation**  
- **Suricata** monitors DNS logs → Splunk alert triggers webhook.  
- n8n queries **VirusTotal** for domain reputation.  
- If **“Suspicious”**, it:
  - Sends HTML email alert  
  - Posts to Slack channel  
  - Opens **ServiceNow** incident automatically  

### **4️⃣ Malware Analysis Pipeline**  
- **Wazuh** detects suspicious file creation.  
- File is transferred via SSH → **ANY.RUN sandbox** submission.  
- Fetches IOC report + analysis summary.  
- n8n integrates the data into Splunk dashboards and alerts.

### **5️⃣ Web Attack Analytics (Apache Log Detection)**  
- Splunk ingests Apache `access.log`.  
- Detects:
  - Brute-force login attempts  
  - SQL Injection (SQLi)  
  - XSS & LFI patterns  
  - Recon/scanning behavior  
- Visualizes attack trends by IP, URL, and user-agent.

### **6️⃣ Endpoint & EDR Integration (Wazuh + Defender)**  
- Wazuh collects system and Defender logs from Linux/Windows endpoints.  
- Custom correlation rule triggers on:
  - Bursts of 404/401 or 5xx errors  
  - Suspicious process creation  
- Alerts visualized in Wazuh + sent to n8n for enrichment.

---

## 🧰 Tech Stack  

| Category | Tool / Framework |
|-----------|------------------|
| IDS/IPS | Suricata, Snort |
| SIEM | Splunk, Wazuh |
| SOAR | n8n |
| Scripting | Python, Bash |
| Firewall API | Palo Alto Networks |
| Threat Intel | VirusTotal, ANY.RUN |
| Notifications | Slack, Gmail |
| Ticketing | ServiceNow |
| Visualization | Splunk Dashboards, HTML Reports |

---

## 📁 Project Structure  

```
SentinelX/
│
├── detection/
│   ├── suricata_rules/
│   ├── snort_rules/
│   └── wazuh_custom_rules/
│
├── splunk/
│   ├── dashboards/
│   ├── saved_searches/
│   └── alert_queries/
│
├── automation/
│   ├── n8n_workflows/
│   ├── python_scripts/
│   └── webhook_payloads/
│
├── reports/
│   ├── firewall_audit.html
│   ├── malware_analysis.html
│   └── domain_reputation_summary.html
│
├── docs/
│   ├── architecture_diagram.png
│   ├── setup_steps.md
│   └── demo_walkthrough.md
│
└── README.md
```

---

## 🧩 Example Use Case

**Scenario:**  
An attacker tries multiple SSH logins → Suricata logs the attempts → Splunk flags them → n8n enriches IP → VirusTotal flags it as malicious → SentinelX:  
- Sends Slack alert ✅  
- Emails analyst ✅  
- Blocks IP via Palo Alto ✅  
- Opens incident ticket ✅  
All automatically — within seconds.

---

## 📊 Dashboards & Reports  

| Visualization | Description |
|----------------|-------------|
| 🔹 **Splunk “Attack Trends” Dashboard** | Real-time view of brute-force, SQLi, and DNS anomalies |
| 🔹 **Firewall Audit HTML Report** | AI summary of redundant or risky firewall rules |
| 🔹 **Malware Sandbox Analysis Report** | ANY.RUN extracted IOCs and risk scores |
| 🔹 **SOC Summary Dashboard** | Unified view of Wazuh, Suricata, Splunk alerts |

*(Add screenshots here after setup)*

---

## 🧱 Installation Steps (High-Level)  

1. **Deploy core services:** Wazuh, Suricata/Snort, Splunk, n8n (separate VMs/containers).  
2. **Wire ingestion:** Suricata/Snort → Splunk; Wazuh agents → Wazuh; Apache logs → Splunk.  
3. **n8n webhooks:** Receive Splunk/Wazuh alerts for SSH brute force, DNS anomalies, malware events.  
4. **Enrichment & IR:** VirusTotal, ANY.RUN, Slack, Gmail, ServiceNow actions.  
5. **Firewall Audit:** Run Python script against Palo Alto API → generate `reports/firewall_audit.html`.  
6. **Dashboards:** Import Splunk dashboards from `/splunk/dashboards`.

---

## 🧠 AI & Automation Highlights  
- **AI-driven rule audit:** Analyzes Palo Alto configurations with natural language risk interpretation.  
- **SOAR logic:** Conditional automation using n8n nodes (HTTP → Function → Slack/Email).  
- **Dynamic enrichment:** Real-time VirusTotal lookups & sandbox results added to Splunk.  

---

## 🏆 Key Learning Outcomes  
✅ SOC automation using open-source tools  
✅ SIEM correlation and alerting (Splunk + Wazuh)  
✅ SOAR orchestration (n8n workflows)  
✅ IDS/IPS deployment and tuning (Suricata, Snort)  
✅ Threat intelligence enrichment (VirusTotal, ANY.RUN)  
✅ Firewall auditing and AI-driven analysis  
✅ Incident lifecycle management (Slack + ServiceNow)

---

## 📘 Future Enhancements  
- Integrate **MITRE ATT&CK technique mapping** for every detection.  
- Automate deployments using **Ansible playbooks**.  
- Add **ELK Stack alternative** for open-source flexibility.  
- Include **Phishing simulation detection** module.

---

## 📸 Screenshot Placeholders  

```
/docs/screenshots/
├── splunk_dashboard.png
├── wazuh_alerts.png
├── n8n_workflow.png
└── firewall_audit_report.png
```

---

## 🔐 Disclaimer  
This project is for **educational and research purposes only.**  
Do **not** deploy automation that modifies production systems without authorization.

---

## 👨‍💻 Author  
**Zachary Yevdayev** — Cybersecurity Analyst | SOC Automation Engineer  
📫 GitHub : https://github.com/zach1289  
💼 LinkedIn : https://linkedin.com/in/zachary-yevdayev-692765112
