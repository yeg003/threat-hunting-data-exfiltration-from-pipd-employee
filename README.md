# Threat Hunting Scenario: Data Exfiltration from PIP'd Employee

Welcome to a hands-on threat hunting scenario using Microsoft Defender for Endpoint (MDE) and KQL. This project simulates an insider threat investigation involving a disgruntled employee suspected of data theft.

## 📘 Scenario Summary
An employee placed on a Performance Improvement Plan (PIP) is suspected of attempting to steal sensitive data before leaving the company. As the threat hunter, your goal is to determine if any malicious activity took place using Defender logs and map the activity to MITRE ATT&CK.

## 🎯 Objective
- Detect file compression of sensitive data
- Identify suspicious script execution
- Confirm or rule out data exfiltration to external servers

## 🛠️ Tools & Data Sources
- **Microsoft Defender for Endpoint**
- **Advanced Hunting via KQL**
- **Tables used:**
  - `DeviceFileEvents`
  - `DeviceProcessEvents`
  - `DeviceNetworkEvents`

## 🧠 Key Findings
- 7-Zip silently installed via PowerShell
- Multiple `.zip` archives of employee data were created
- Outbound encrypted connections occurred moments later
- PowerShell used `-ExecutionPolicy Bypass` to execute a script

## 🧩 Mapped MITRE ATT&CK Techniques
| Tactic             | Technique                      | ID         |
|--------------------|--------------------------------|------------|
| Execution          | PowerShell                     | T1059.001  |
| Collection         | Archive via Utility            | T1560.001  |
| Command & Control  | Encrypted Channel (HTTPS)      | T1071.001  |
| Exfiltration       | Exfiltration Over C2 Channel   | T1041      |

## 🧾 Use This Project To Demonstrate
- Practical use of KQL for endpoint detection
- Ability to correlate behavior across multiple log sources
- End-to-end response workflow including mitigation and prevention
- Documentation and presentation of threat hunts

---

> 📎 For full details, see the [final threat hunt report](./report/final_threat_hunt_report.md)
