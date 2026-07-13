# Incident Report — BTL-2026-006

*NIST SP 800-61r2 aligned. Blue Team Lab hunting session #6.*

## 1. Incident Identification

| Field | Value |
|---|---|
| **Report ID** | BTL-2026-006 |
| **Detection timestamp (UTC)** | 2026-07-13T14:51:24Z |
| **Analyst** | Claude (autonomous via SSH) |
| **Status** | **Closed** |
| **Confidence** | **High** — 2 alerts differentiated by rule chain |

## 2. Categorization

| Field | Value |
|---|---|
| **Attack vector** | External (SSH) |
| **Threat actor** | Simulated |
| **NIST category** | Malicious Code (persistence installation) |
| **MITRE tactic** | **Persistence** (TA0003), **Defense Evasion** (sub-rule) |
| **MITRE technique** | **T1543.003 — Windows Service** |
| **Reference** | https://attack.mitre.org/techniques/T1543/003/ |

## 3. Prioritization

| Dim | Value | Justification |
|---|---|---|
| Functional | Low | Simulation |
| Information | None | |
| Recoverability | Regular | `sc delete` |
| **Priority** | **High** (from LOLBIN sub-rule) | Service persistence + LOLBIN = high-fidelity attacker signal |

## 4. Detection & Analysis

**Sensor**: Windows Security EID **4697**. Prereq: `auditpol /set /subcategory:"Security System Extension" /success:enable` (mặc định OFF, enable trong session).

**Rule chain**: 60000 → 60003 → 60103 → **100102 (level 10)** — mọi service create. Sub-rule **100112 (level 14)** escalate nếu binary là LOLBIN.

**Hunt DSL**:
```json
{"query":{"bool":{"must":[{"terms":{"rule.id":["100102","100112"]}},{"range":{"@timestamp":{"gte":"..."}}}]}}}
```

**Findings**: 2 alerts.

| Time | Rule | Level | serviceName | serviceFileName | Verdict |
|---|---|---|---|---|---|
| 14:51:24Z | 100102 | 10 | BTLab_Sess06B_Benign | `C:\Windows\System32\notepad.exe` | Info (any service install) |
| 14:51:25Z | **100112** | **14** | BTLab_Sess06B_Evil | **`cmd.exe /c echo evil`** | 🔴 LOLBIN persistence |

## 5. Timeline

| T | Actor | Action | Source |
|---|---|---|---|
| T+0 | labuser | sc create BTLab_Sess06B_Benign notepad.exe | 4697 |
| T+1s | labuser | sc create BTLab_Sess06B_Evil cmd.exe | 4697 → **100112** |
| T+3s | labuser | sc delete both | 4699 (not covered) |

## 6. Scope

- **Host**: win-ep-01
- **User**: labuser
- **IOCs** (behavioral):
  - Service names `BTLab_Sess06B_*`
  - Binary `cmd.exe /c echo evil` (LOLBIN)
- **Enrichment**: skip (no hash/IP/domain)

## 7. Containment/Eradication

- **Contain**: `sc stop <name>`, isolate host
- **Eradicate**: `sc delete`, review other services for LOLBIN binaries (`Get-Service | Get-CimInstance -ClassName Win32_Service | Where PathName -match "(cmd|powershell|wscript|rundll32|regsvr32)"`)
- **Recover**: reset service ACLs, GPO baseline audit

## 8. Post-Incident

- **✅ Rule works — no debug** (Windows Security chain).
- **Prereq audit enabled** in session (default OFF on fresh Win).
- **Detection gap**: rule không cover EID 4699 (service DELETED). Attacker cleanup nhanh → no artifact — thêm rule con level 8.
- **Improvement**: match `serviceFileName` path là `%TEMP%` hoặc `%APPDATA%` → escalate level 15 (attacker dropper).

## 9. Communications

Level 14 → auto-page SOC lead.

## 10. References

- MITRE: https://attack.mitre.org/techniques/T1543/003/
- Rule: `wazuh-rules/local_rules.xml` — 100102 + 100112
- EID 4697 Microsoft: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4697
