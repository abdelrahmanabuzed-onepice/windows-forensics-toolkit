# Windows Forensics & Incident Response Toolkit 🔍🛡️
### Lightweight System Auditing, Event Telemetry & Indicator Defanging for Windows

[![Platform: Windows](https://img.shields.io/badge/Platform-Windows_10%2F11%2FServer-blue.svg)](https://microsoft.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A clean, standalone incident response and forensics toolkit engineered in Python and PowerShell. It assists system administrators and security analysts in triaging host defenses, inspecting running processes for anomalous execution, parsing failed logon events, and defanging threat indicators for reporting.

---

## ⚡ Features

- **🛡️ Defense Posture Audit:** Verifies Windows Defender real-time protection and firewall profile status.
- **⚡ Process Telemetry:** Scans active processes and flags suspicious command-line execution patterns (e.g. encoded commands, download strings, execution policy bypasses).
- **📋 Event Log Auditing:** Parses Windows Security events to surface failed logon bursts (Event ID 4625).
- **🔒 Indicator Defanging:** Safely sanitizes malicious URLs, domains, and IP addresses to prevent accidental click-throughs in security reports.

---

## 📦 Project Structure

```
windows-forensics-toolkit/
├── event_auditor.py       # Windows Event Log analysis
├── process_sentinel.py    # Active process inspection and flag detection
├── system_hardening.py    # Defender and Firewall posture check
├── file_defanger.py       # Indicator sanitization (URL/IP defanger)
├── main.py                # Unified CLI runner
└── requirements.txt       # Dependencies (uses Python stdlib)
```

---

## 🛠️ Usage

```bash
# Run complete system audit
python main.py --audit-all

# Check running processes
python main.py --processes

# Defang an indicator for reporting
python main.py --defang "http://malicious-domain.com/payload.exe"
```

---

## 👤 Author
**Abdelrahman Abouzed**  
- GitHub: [@abdelrahmanabuzed-onepice](https://github.com/abdelrahmanabuzed-onepice)  
- Email: [abdelrahman.abuzed@gmail.com](mailto:abdelrahman.abuzed@gmail.com)
