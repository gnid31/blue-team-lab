# Incident Report — BTL-2026-008

*NIST SP 800-61r2 aligned. Session #8 — T1562.001 Disable Defender.*

## 1. Incident Identification

| Field | Value |
|---|---|
| **Report ID** | BTL-2026-008 |
| **Detection timestamp (UTC)** | 2026-07-13T14:55:53Z |
| **Analyst** | Claude |
| **Status** | **Closed** |
| **Confidence** | **High** — 3 alerts, cmdline explicit |

## 2. Categorization

| Field | Value |
|---|---|
| **Attack vector** | External (SSH) |
| **NIST category** | Malicious Code — defense evasion |
| **MITRE tactic** | **Defense Evasion** (TA0005) |
| **MITRE technique** | **T1562.001 — Impair Defenses: Disable or Modify Tools** |
| **Reference** | https://attack.mitre.org/techniques/T1562/001/ |

## 3. Prioritization

| Dim | Value | Justification |
|---|---|---|
| Functional | Medium | AV disabled = other malicious code có thể chạy không bị chặn |
| Information | None (direct) | |
| Recoverability | Regular | Re-enable Defender ngay |
| **Priority** | **Critical** | Level 14, always page |

## 4. Detection & Analysis

**Sensor**: Sysmon EID **1** (Process Create).

**Rule chain**: 60000 → 60004 → 61600 → sysmon_event1 group → **100107 (custom, level 14)**.

**Trigger**:
```powershell
powershell.exe -Command "Set-MpPreference -DisableRealtimeMonitoring $true"
powershell.exe -Command "Set-MpPreference -DisableRealtimeMonitoring $false"   # cleanup
```

**Findings**: **3 alerts level 14 T1562.001**.

| Time | commandLine |
|---|---|
| 14:55:53Z | Wrapper: `powershell.exe -c " # S09: T1562.001 disable Defender ... Set-MpPreference -DisableRealtimeMonitoring $true ..."` |
| 14:55:54Z | Inner: `Set-MpPreference -DisableRealtimeMonitoring $true` |
| 14:55:59Z | Cleanup: `Set-MpPreference -DisableRealtimeMonitoring $false` (VẪN fire vì regex match `Set-MpPreference.*Disable`) |

Regex trigger: `Set-MpPreference\s.*(?:Disable|-D\w*Realtime)`

**⚠ Observation**: rule fire cả trên **cleanup command** (`$false`) — false positive giả tạo. Cleanup thực chất là RE-ENABLE Defender, không nên trigger. Cần refinement.

## 5. Timeline

| T | Actor | Action | Impact |
|---|---|---|---|
| T+0 | labuser | Wrapper PS → inner PS | 100107 fire (wrapper cmdline) |
| T+1s | inner PS | `Set-MpPreference -DisableRealtimeMonitoring $true` | 100107 fire (attacker action) |
| T+5s | labuser | Cleanup: same command với `$false` | 100107 fire (**false positive** — re-enable) |

## 6. Scope

- **Host**: win-ep-01
- **Real-time monitoring**: **disabled trong ~5s** giữa session
- **IOCs**:
  - commandLine pattern `Set-MpPreference.*Disable`
  - Parent = sshd-session.exe (unusual)
- **Enrichment**: hash powershell.exe = clean (behavior detection)

## 7. Containment/Eradication

- **Contain**: verify Defender re-enabled: `Get-MpPreference | Select DisableRealtimeMonitoring` (should return `False`)
- **Investigate**:
  - Timeline: giữa disable + re-enable, attacker có drop malware nào không? Grep 92213 alert trong window đó
  - Check `Get-MpThreatDetection` — Defender ghi threat history bất kể real-time có OFF hay không
- **Eradicate**: kill process nếu còn active; scan full với `Start-MpScan -ScanType FullScan`
- **Recover**: reset Defender preferences to default; audit sudo/admin group

## 8. Post-Incident

- **✅ Rule 100107 fire — nhờ preemptive fix if_group=sysmon_event1** (lesson từ session 1 áp dụng).
- **⚠ Refinement needed**: regex hiện match cả `$false` (re-enable). Fix:
  ```xml
  <field name="win.eventdata.commandLine" type="pcre2">
    (?i)Set-MpPreference\s.*Disable\w*\s*\$?true
  </field>
  ```
- **Coverage extension** (đề xuất):
  - Match `wmic /namespace:\\root\Microsoft\Windows\Defender path MSFT_MpPreference call ...` (WMI-based bypass)
  - Match `netsh advfirewall set allprofiles state off` (firewall disable)
- **Prevention**:
  - Set Defender vào **Tamper Protection** mode — chặn `Set-MpPreference` thay đổi từ non-admin
  - Enforce Attack Surface Reduction rules

## 9. Communications

Level 14 → auto-page SOC + IT admin (nếu disable ≥ 5 phút → escalate CISO).

## 10. References

- MITRE T1562.001: https://attack.mitre.org/techniques/T1562/001/
- Rule: `wazuh-rules/local_rules.xml` — 100107
- Microsoft Defender: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/enable-attack-surface-reduction
