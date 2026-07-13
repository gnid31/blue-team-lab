# Incident Report — BTL-2026-002

*NIST SP 800-61r2 aligned. Blue Team Lab hunting session #2.*

---

## 1. Incident Identification (NIST §3.2.7)

| Field | Value |
|---|---|
| **Report ID** | BTL-2026-002 |
| **Detection timestamp (UTC)** | 2026-07-13T14:09:35Z |
| **Report timestamp (UTC)** | 2026-07-13T14:15:00Z |
| **Analyst / Handler** | Claude (Kali autonomous via SSH) |
| **Status** | **Closed** (Atomic simulation) |
| **Confidence** | **High** — MITRE tag confirmed, targetObject exactly khớp autorun path |

---

## 2. Incident Categorization (NIST §2.1)

| Field | Value |
|---|---|
| **Attack vector** | External (SSH remote command execution) |
| **Threat actor** | **Simulated** (Blue Team Lab trigger via SSH from Kali) |
| **NIST incident category** | Malicious Code / Unauthorized Access (persistence installation) |
| **MITRE ATT&CK Tactic** | **Persistence** (TA0003) |
| **MITRE ATT&CK Technique** | **T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder** |
| **MITRE reference** | https://attack.mitre.org/techniques/T1547/001/ |

---

## 3. Incident Prioritization (NIST §3.2.6)

| Dimension | Value | Justification |
|---|---|---|
| **Functional Impact** | **Low** | Simulation — no real payload. Nếu real: Medium (persistence + reboot survival) |
| **Information Impact** | **None** | Không có data access trong hành vi này |
| **Recoverability** | **Regular** | Xoá 1 registry value là đủ recover |
| **Overall Priority** | **Medium** | Persistence technique = escalate ngay khi phát hiện, dù chưa có evidence data compromise |

---

## 4. Detection & Analysis (NIST §3.2)

### 4.1. Detection method

- **Automated**: Wazuh custom rule `100108` matched
- **Sensor**: Sysmon EventID 13 (RegistryEvent — SetValue), channel `Microsoft-Windows-Sysmon/Operational`
- **Manager**: Wazuh 4.9.2 tại `43.228.215.234`
- **Rule chain**: `60000` → `60004` (sysmon channel) → `61600` → `61615` (EID 13 parent) → `92300` (built-in "Run key modified") → `92302` (level 6, `reg.exe` image) → **`100108`** (custom, level 12, T1547.001 mapping)

### 4.2. Hypothesis

> Nếu attacker ghi vào registry autorun key (`Run`, `RunOnce`, `RunServices`, `Winlogon\Shell`, `Winlogon\Userinit`), Sysmon EID 13 phải capture với `targetObject` chứa path key và `details` chứa binary được set → rule 100108 escalate level 12 với MITRE T1547.001.

### 4.3. Hunt queries

**OpenSearch DSL**:
```json
POST /wazuh-alerts-*/_search
{
  "size": 20,
  "sort": [{"@timestamp": "asc"}],
  "query": {
    "bool": {
      "must": [
        { "match": { "rule.id": "100108" }},
        { "range": { "@timestamp": {
            "gte": "2026-07-13T14:09:30Z",
            "lte": "2026-07-13T14:10:30Z"
        }}}
      ]
    }
  }
}
```

**Dashboard KQL**:
```
rule.id : "100108" AND @timestamp >= "2026-07-13T14:09:30Z"
```

**Broad autorun hunt** (không phụ thuộc rule custom):
```
data.win.system.eventID : "13" AND data.win.eventdata.targetObject : *CurrentVersion*Run*
```

### 4.4. Findings

| Metric | Value |
|---|---|
| Alert count (rule 100108) | **1** |
| Custom rule fired | 100108 ✅ level 12 |
| Related built-in rule | 92300 (level 0, silent) + 92302 (chain parent, level 6) |
| Highest severity level | 12 |
| MITRE tag confirmed | T1547.001 ✅ |

**Alert 1 — 2026-07-13T14:09:35.749Z** (rule 100108 lvl 12):
```json
{
  "rule": {
    "level": 12,
    "mitre": {"id": ["T1547.001"]},
    "description": "T1547.001 - Autorun key modified: HKU\\S-1-5-21-...\\...\\CurrentVersion\\Run\\BTLab_v6 = cmd.exe /c calc.exe by C:\\Windows\\system32\\reg.exe"
  },
  "data": {"win": {"eventdata": {
    "image": "C:\\Windows\\system32\\reg.exe",
    "targetObject": "HKU\\S-1-5-21-4188382834-1221911911-931124274-1001\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\BTLab_v6",
    "details": "cmd.exe /c calc.exe",
    "processGuid": "{77b11330-f19f-6a54-bf0a-000000000500}",
    "user": "WIN-EP-01\\labuser"
  }}}
}
```

Note: HKCU (per-user hive) trong Sysmon log được represent bằng **HKU\<UserSID>** format. SID `S-1-5-21-4188382834-1221911911-931124274-1001` = labuser trên win-ep-01.

---

## 5. Chronology / Timeline (NIST §3.2.5)

| Timestamp (UTC) | Actor | Action | Source | Notes |
|---|---|---|---|---|
| 2026-07-13T14:09:34Z | Analyst (Kali) | SSH command dispatch to labuser@win-ep-01 | ssh | Automated |
| 2026-07-13T14:09:35.7Z | labuser | Spawn `reg.exe add HKCU\...\Run\BTLab_v6` | Sysmon EID 1 | (rule 92041, 92213 fire on side effects) |
| **2026-07-13T14:09:35.749Z** | reg.exe | Registry SetValue on `\...\Run\BTLab_v6 = cmd.exe /c calc.exe` | Sysmon EID 13 | 🔴 **Rule 100108 fires** |
| 2026-07-13T14:09:45Z | labuser | Cleanup — `reg delete` (KHÔNG generate EID 13 SetValue) | — | Cleanup event ID 14 (RegistryEvent Key Deleted) — chưa cover bởi rule custom |
| 2026-07-13T14:09:46Z | System | SSH session close | Windows Security 4634 | |

**Time-to-detect (TTD)**: ~1 giây (event → indexer). Rất nhanh vì filebeat flush aggressive.

---

## 6. Scope (NIST §3.2.7)

### 6.1. Affected systems

| Hostname | IP | OS | Role | Impact |
|---|---|---|---|---|
| win-ep-01 | 192.168.154.164 | Windows 10/11 | Lab endpoint | Simulation — no real persistence remained after cleanup |

### 6.2. Affected users / accounts

| Account | Role | Notes |
|---|---|---|
| WIN-EP-01\labuser | Local Administrator | HKCU hive của labuser bị modify — chỉ ảnh hưởng khi labuser next login |

### 6.3. Affected data

- **PII exposed**: No
- **Confidential business data**: No
- **Credentials / secrets**: No
- **Registry integrity**: Temporary breach — value `BTLab_v6` được ghi rồi xoá

### 6.4. Indicators of Compromise (IOCs)

| Type | Value | Source field | Notes |
|---|---|---|---|
| **Registry path** | `HKU\S-1-5-21-...\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\BTLab_v6` | data.win.eventdata.targetObject | Autorun value name lạ |
| **Payload command** | `cmd.exe /c calc.exe` | data.win.eventdata.details | Command chạy tại logon |
| **Process image** | `C:\Windows\system32\reg.exe` | data.win.eventdata.image | reg.exe = LOLBIN cho persistence |
| **User SID** | `S-1-5-21-4188382834-1221911911-931124274-1001` | targetObject prefix | labuser |
| **Process GUID** | `{77b11330-f19f-6a54-bf0a-000000000500}` | data.win.eventdata.processGuid | Sysmon unique process ID — dùng để pivot |

### 6.5. TI Enrichment (VT / AbuseIPDB)

**Không applicable**. IOC của session này là **registry path + command string**, không phải hash/IP/domain. Không có endpoint TI provider chuẩn cho registry value.

**Enrichment tool skip**: `enrich.py` extract IOC theo regex — registry path không match hash/IP/domain regex → không có verdict.

**Bài học**: enrichment tool cần mở rộng cho **behavioral IOC** (autorun key name, service name pattern) nếu muốn tự động hoá triage cho persistence technique.

---

## 7. Containment, Eradication, Recovery (NIST §3.3, §3.4)

### 7.1. Containment strategy

- **Short-term** (nếu real):
  - `reg query "HKU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"` → dump all keys tìm suspicious
  - Snapshot registry hive: `reg export "HKU\<SID>\SOFTWARE" C:\evidence\user_hive.reg`
  - Isolate host qua active-response
- **Long-term**:
  - Set restricted permissions trên autorun keys via GPO
  - Enable Wazuh **FIM** (file integrity monitoring) mở rộng sang registry paths

### 7.2. Eradication actions

- [x] Cleanup thực hiện — `reg delete HKCU\...\Run\BTLab_v6 /f` (session cleanup)
- Nếu real: kill process nếu autorun đã kích hoạt (`Get-Process | Where { $_.Path -like "*calc*" } | Stop-Process`)
- Scan hive cho các key khác được attacker ghi cùng phiên

### 7.3. Recovery actions

- [ ] Verify không còn autorun trái phép: `reg query HKU\<SID>\...\Run`
- [ ] Nếu binary autorun được chạy: check process spawned, kill nếu còn active
- [ ] Reset user profile (extreme case)

### 7.4. Verification

- Query `rule.id : 100108 AND agent.name : win-ep-01 AND @timestamp >= "now-1h"` — expect only 1 (session test)
- Manual: reg query trên labuser Run key — expect empty

---

## 8. Post-Incident Activity (NIST §3.5)

### 8.1. Lessons learned

- **Time-to-detect (TTD)**: **~1 giây** — excellent (Sysmon EID 13 → agent → filebeat → indexer chain rất nhanh cho registry).
- **Rule bug (đã fix trong session này)**:
  - Rule 100108 ban đầu dùng `<if_sid>61615</if_sid>` + `<field win.eventdata.targetObject>` với regex backslash — không fire dù event match logic.
  - Thử `<if_group>sysmon_event_13</if_group>` — vẫn không fire.
  - Fix cuối: `<if_sid>92302</if_sid>` (chain từ built-in rule đã fire) + không cần thêm field constraint (built-in đã filter chính xác).
- **Root cause probably**: Wazuh rule engine ưu tiên **child-of-most-specific-parent** khi có nhiều rule cạnh tranh trên cùng chain. Chain từ 92302 (chuyên biệt cho reg.exe modifying Run key) an toàn hơn `if_group` chung.

### 8.2. Detection improvements

- [x] **Rule 100108 fix**: chain từ 92302, level 12 (escalate từ 92302 level 6). Commit `[current HEAD]`.
- [ ] **Coverage gap**: rule hiện tại chain từ 92302 chỉ bắt khi attacker dùng **`reg.exe`**. Nếu attacker dùng:
  - PowerShell: `New-ItemProperty -Path HKCU:\...\Run` → EID 13 nhưng image = `powershell.exe` → 92302 không fire → **100108 miss**
  - Native API (regedit.exe, direct RegSetValue) → tương tự miss
- **Suggested rule extension** (rule 100118 chẳng hạn):
  ```xml
  <rule id="100118" level="12">
    <if_sid>92300</if_sid>          <!-- direct chain from Run-key regex parent -->
    <field name="win.eventdata.image" type="pcre2">(?i)powershell\.exe$|regedit\.exe$|wmic\.exe$</field>
    <description>T1547.001 - Autorun key modified via non-reg.exe LOLBIN</description>
  </rule>
  ```
- [ ] **Follow-up detection**: nếu autorun key trỏ đến binary trong `%TEMP%`, `%APPDATA%`, `C:\Users\Public\` → escalate level 14 (rất khả năng malware)
- [ ] **Correlation**: alert nếu ≥3 autorun key được thêm trong ≤5 phút → attack chain đang chạy

### 8.3. Prevention measures

- [ ] **Group Policy — Restrict user hive Run key modification**: block non-admin user from writing HKCU\...\Run (via Software Restriction Policy)
- [ ] **AppLocker**: whitelist chương trình được autorun (block cmd.exe / powershell.exe từ Run key)
- [ ] **Regular baseline audit**: dump `HKLM\...\Run` + `HKU\...\Run` cho mọi user weekly, diff vs baseline
- [ ] **Autoruns.exe** scan định kỳ (Sysinternals) — export vs baseline

---

## 9. Communications Log (NIST §2.3.4)

*Simulation — no real notification chain.*

Trong production: rule level 12 = auto-page on-call SOC. Nếu correlate với alert khác cùng user trong 30 phút (VD T1059.001 PowerShell) → escalate SOC lead + notify user's manager.

---

## 10. References & Attachments

- **Atomic test source**: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md
- **MITRE ATT&CK T1547.001**: https://attack.mitre.org/techniques/T1547/001/
- **Wazuh rule**: [`wazuh-rules/local_rules.xml`](../wazuh-rules/local_rules.xml) — rule id 100108
- **Rule FP profile**: [`wazuh-rules/RULES.md#rule-100108`](../wazuh-rules/RULES.md#rule-100108)
- **Sysinternals Autoruns**: https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns
- **NIST SP 800-61r2**: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf
- **Kill chain step**: Installation (persistence stage)
- **Related MITRE**: T1547 (parent — Boot/Logon Autostart), T1055 (Process Injection via loaded autorun binary)
