# Incident Report — BTL-2026-004

*NIST SP 800-61r2 aligned. Blue Team Lab hunting session #4.*
*First **cross-platform** session (Windows + Linux simultaneous).*

---

## 1. Incident Identification (NIST §3.2.7)

| Field | Value |
|---|---|
| **Report ID** | BTL-2026-004 |
| **Detection timestamp (UTC)** | 2026-07-13T14:18:52Z |
| **Report timestamp (UTC)** | 2026-07-13T14:25:00Z |
| **Analyst / Handler** | Claude (Kali autonomous via SSH → Win + Linux) |
| **Status** | **Closed** (Atomic simulation) |
| **Confidence** | **High** — 10 alerts, cross-platform confirmed, MITRE tag confirmed |

---

## 2. Incident Categorization (NIST §2.1)

| Field | Value |
|---|---|
| **Attack vector** | External (SSH remote command execution to 2 endpoints) |
| **Threat actor** | **Simulated** (Blue Team Lab trigger) |
| **NIST incident category** | Reconnaissance (per-host, post-compromise enumeration) |
| **MITRE ATT&CK Tactic** | **Discovery** (TA0007) |
| **MITRE ATT&CK Technique** | **T1087.001 — Account Discovery: Local Account** |
| **MITRE reference** | https://attack.mitre.org/techniques/T1087/001/ |

---

## 3. Incident Prioritization (NIST §3.2.6)

| Dimension | Value | Justification |
|---|---|---|
| **Functional Impact** | **None** | Read-only enumeration, không thay đổi system |
| **Information Impact** | **Low** | Attacker biết danh sách user local (không phải credential) |
| **Recoverability** | **Regular** | Không cần recovery — không có compromise |
| **Overall Priority** | **Low** | Nhưng **CRITICAL nếu correlate** với phishing/exploit trước đó → attack chain đang tiến triển |

**Note**: level 5 rule (thấp) là intentional — discovery ĐỘC LẬP thường FP cao (admin/helpdesk cũng chạy). Escalate chỉ khi correlate.

---

## 4. Detection & Analysis (NIST §3.2)

### 4.1. Detection method

- **Automated (Windows)**: rule `100105` matched — Sysmon EID 1, image = `net.exe|net1.exe|whoami.exe|quser.exe|nltest.exe`
- **Automated (Linux)**: rule `100115` matched — auditd `execve` of `whoami|id|getent|w|who|lastlog`
- **Rule chain (Win)**: `60000 → 60004 → 61600 → sysmon_event1 group → 100105` (custom, level 5)
- **Rule chain (Linux)**: `80700` (auditd parent) → `100115` (custom, level 5)

### 4.2. Hypothesis

> Nếu attacker sau khi vào host thực hiện enumeration local account (`net user`, `whoami /all`, `id`, `getent passwd`), Sysmon EID 1 (Win) hoặc auditd execve (Linux) sẽ ghi process create với binary name khớp danh sách → rule 100105/100115 fire level 5 T1087.001.

### 4.3. Hunt queries

**OpenSearch DSL — combined query**:
```json
POST /wazuh-alerts-*/_search
{
  "size": 20,
  "sort": [{"@timestamp": "asc"}],
  "query": {
    "bool": {
      "must": [
        { "terms": { "rule.id": ["100105", "100115"] }},
        { "range": { "@timestamp": { "gte": "2026-07-13T14:18:50Z" }}}
      ]
    }
  }
}
```

**Dashboard KQL** (cross-platform):
```
rule.mitre.id : "T1087.001"
```

**Broader hunt** (bao gồm tool discovery khác):
```
data.win.eventdata.originalFileName : ("net.exe" OR "whoami.exe" OR "quser.exe") 
  OR data.audit.exe : /whoami OR data.audit.exe : /id
```

### 4.4. Findings

| Metric | Value |
|---|---|
| Total alerts | **10** (5 Windows + 5 Linux) |
| Rule 100105 (Windows) | 5 alerts, level 5 ✅ |
| Rule 100115 (Linux) | 5 alerts, level 5 ✅ |
| Highest severity level | 5 (intentional low — anti-FP) |
| MITRE tag confirmed | T1087.001 ✅ |
| Cross-platform coverage | ✅ Confirmed |

**Windows alerts (5, agent=win-ep-01)**:

| Timestamp | originalFileName | commandLine |
|---|---|---|
| 14:18:52.595Z | net.exe | `"C:\Windows\system32\net.exe" user` |
| 14:18:52.621Z | net1.exe | `C:\Windows\system32\net1 user` |
| 14:18:52.633Z | net.exe | `"C:\Windows\system32\net.exe" localgroup administrators` |
| 14:18:52.633Z | net1.exe | `C:\Windows\system32\net1 localgroup administrators` |
| 14:18:52.653Z | whoami.exe | `"C:\Windows\system32\whoami.exe" /all` |

**Chi tiết**: `net.exe user` spawn `net1.exe` (Windows compat wrapper) → 2 alert cho mỗi lệnh `net` (parent + child). Không phải bug — đó là design của Windows.

**Linux alerts (5, agent=linux-ep-01)**:

| Timestamp | exe | uid | auid | Notes |
|---|---|---|---|---|
| 14:18:53.728Z | /usr/bin/id | **0** | 1000 | uid=0 = spawn qua service context |
| 14:18:53.770Z | /usr/bin/whoami | 1000 | 1000 | user context |
| 14:18:53.777Z | /usr/bin/id | 1000 | 1000 | user context |
| 14:18:53.790Z | /usr/bin/getent | 1000 | 1000 | |
| 14:18:53.797Z | /usr/bin/w | 1000 | 1000 | |

**Chi tiết**: `auid=1000` là loginuid (immutable) = user `gnid`. `uid=0` trong entry đầu là spawn qua service (có thể bash profile). Rule vẫn fire đúng vì key=execve match.

---

## 5. Chronology / Timeline (NIST §3.2.5)

| Timestamp (UTC) | Actor | Action | Source | Notes |
|---|---|---|---|---|
| 14:18:51Z | Analyst (Kali) | Parallel SSH dispatch to both endpoints | ssh | Windows + Linux đồng thời |
| 14:18:52.595Z–.653Z | labuser (Win) | `net user`, `net localgroup administrators`, `whoami /all` | Sysmon EID 1 x5 | 🔴 **Rule 100105 fires 5x** |
| 14:18:53.728Z–.797Z | gnid (Linux) | `whoami`, `id`, `getent passwd`, `w` | auditd execve x5 | 🔴 **Rule 100115 fires 5x** |
| 14:18:53Z | Both | Session end | 4634 / SSH close | |

**Windows-Linux gap**: 1.1 giây giữa Windows last event và Linux first event — do SSH dispatch tuần tự (Win xong → Linux).

**TTD**:
- Windows: **~0.2s** (Sysmon → filebeat rất nhanh)
- Linux: **~1s** (auditd tail → wazuh-agent)

---

## 6. Scope (NIST §3.2.7)

### 6.1. Affected systems

| Hostname | IP | OS | Impact |
|---|---|---|---|
| win-ep-01 | 192.168.154.164 | Windows 10/11 | Enumeration confirmed |
| linux-ep-01 | 192.168.154.166 | Ubuntu 22.04.5 | Enumeration confirmed |

### 6.2. Affected users / accounts

| Account | Host | Notes |
|---|---|---|
| labuser | win-ep-01 | Enumerator |
| gnid | linux-ep-01 | Enumerator |

### 6.3. Affected data

- **Enumerated on Windows**: local user list (net user), Administrators group members, token integrity (whoami /all)
- **Enumerated on Linux**: /etc/passwd entries, active user sessions (w), current user identity (id)

Không phải data breach — nhưng lộ thông tin recon giúp attacker chọn target tiếp.

### 6.4. Indicators of Compromise (IOCs)

Discovery không tạo file/network artifact truyền thống. IOC dạng **behavioral**:

| Type | Value | Source |
|---|---|---|
| Process name | `net.exe`, `net1.exe`, `whoami.exe` | data.win.eventdata.originalFileName |
| Process name | `/usr/bin/id`, `/usr/bin/whoami`, `/usr/bin/getent`, `/usr/bin/w` | data.audit.exe |
| Command line pattern | `user`, `localgroup`, `/all`, `/domain` | data.win.eventdata.commandLine |
| User running (Win) | `WIN-EP-01\labuser` | data.win.eventdata.user |
| User running (Linux) | uid=1000, auid=1000 (gnid) | data.audit.uid / auid |

### 6.5. TI Enrichment

**Không applicable**. Discovery không có hash/IP/domain để query VT/AbuseIPDB.

**Alternative enrichment idea**: query internal HR/IAM để verify user chạy discovery có được authorize không. Ngoài scope tool hiện tại.

---

## 7. Containment, Eradication, Recovery (NIST §3.3, §3.4)

### 7.1. Containment strategy

Discovery không cần isolate ngay lập tức (read-only, không thay đổi system). Nhưng cần:

- **Short-term**: monitor closer — nếu cùng user chạy thêm rule khác (100101 PS, 100107 disable AV, 100108 persistence) trong 30 phút → escalate.
- **Long-term**:
  - Deploy `AppLocker` block user chạy `net.exe user` từ non-standard path
  - Restrict `whoami /all` trong PowerShell Constrained Language mode

### 7.2. Eradication actions

Discovery-only → không cần eradicate. Nhưng cần **audit trail**:
- Ghi lại timestamp, user, và command đã chạy vào SIEM long-term storage
- Preserve raw event XML cho post-incident review

### 7.3. Recovery actions

Không cần recovery cho discovery đơn lẻ.

### 7.4. Verification

- Grep alert cùng user trong 24h — expect chỉ session này (bounded scope)
- `Get-EventLog -LogName Security` không có subsequent EID 4624 từ IP lạ (ensuring no lateral yet)

---

## 8. Post-Incident Activity (NIST §3.5)

### 8.1. Lessons learned

- **✅ Cross-platform rule work correctly**: 100105 (Win Sysmon) + 100115 (Linux auditd) cùng technique T1087.001 fire đúng.
- **✅ Rule 100105 fix áp dụng preemptive**: Trước Session 04, đã đổi rule 100105 từ `<if_sid>61603</if_sid>` sang `<if_group>sysmon_event1</if_group>` + `originalFileName` **dựa trên lesson từ Session 01**. **Không cần debug** trong session này → tiết kiệm 30 phút.
- **✅ Level 5 = correct choice**: discovery low-level giúp giảm alert fatigue. Analyst chỉ xem khi correlate.
- **⚠ Windows `net.exe → net1.exe` duplicate**: mỗi lệnh `net user` tạo 2 process create → 2 alert. Không phải bug, nhưng có thể tune bằng cách match `net1.exe` với `<field parentImage="net.exe">` để skip.
- **⚠ Linux uid=0 first alert anomaly**: 1 event có `uid=0 auid=1000` — cần investigate nguyên nhân (spawn qua PAM script?).

### 8.2. Detection improvements

- [ ] **Correlation rule** (đề xuất — level 12):
  ```xml
  <rule id="100125" level="12" frequency="5" timeframe="300">
    <if_matched_sid>100105</if_matched_sid>
    <same_user/>
    <description>T1087.001 - Rapid account discovery: 5+ discovery commands within 5 min</description>
  </rule>
  ```
  → Alert cao khi user chạy nhiều discovery trong ngắn hạn = attacker recon.
- [ ] **Suppress net1.exe duplicate**:
  ```xml
  <rule id="100135" level="0">
    <if_sid>100105</if_sid>
    <field name="win.eventdata.originalFileName">^net1\.exe$</field>
    <field name="win.eventdata.parentImage" type="pcre2">(?i)\\net\.exe$</field>
    <description>net1.exe spawned by net.exe — suppress duplicate</description>
  </rule>
  ```
- [ ] **PowerShell discovery**: rule hiện tại không bắt `Get-LocalUser`, `Get-ADUser`, `Get-LocalGroupMember`. Cần rule con:
  ```xml
  <rule id="100136" level="5">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.originalFileName" type="pcre2">(?i)^(powershell|pwsh)\.exe$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)(Get-LocalUser|Get-ADUser|Get-LocalGroupMember|Get-DomainController)</field>
    <description>T1087.001 - Account discovery via PowerShell cmdlet</description>
  </rule>
  ```
- [ ] **Linux — bash builtin `getent`, `compgen`**: chạy trong shell không spawn `execve` (builtin, không tạo child process) → auditd không log → miss. Alternative: monitor `/etc/passwd` open syscall (read).

### 8.3. Prevention measures

- **Windows**: enforce PowerShell Constrained Language cho non-admin; block LOLBINs (net.exe, whoami.exe) qua AppLocker.
- **Linux**: monitor `/etc/passwd`, `/etc/group` với `-p r` audit rule (đã có key=recon, nên fire nếu attacker cat passwd).
- **Both**: analyst training để nhận diện discovery patterns trong log — many-in-short-time signal.

---

## 9. Communications Log (NIST §2.3.4)

*Simulation — no real notification.*

Real prod: level 5 = không auto-page, chờ correlation. Nếu 100125 (correlation rule đề xuất) fire → page L1 analyst.

---

## 10. References & Attachments

- **Atomic test T1087.001**: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.001/T1087.001.md
- **MITRE ATT&CK T1087.001**: https://attack.mitre.org/techniques/T1087/001/
- **Wazuh rules**: [`wazuh-rules/local_rules.xml`](../wazuh-rules/local_rules.xml) — rules 100105, 100115
- **Rule FP profile**: [`wazuh-rules/RULES.md#rule-100105`](../wazuh-rules/RULES.md#rule-100105)
- **Rule debugging appendix**: [`docs/04-detection-rules.md#9-appendix-rule-debugging-lessons`](../docs/04-detection-rules.md#9-appendix--rule-debugging-lessons-từ-phase-6-hunting-sessions)
- **NIST SP 800-61r2**: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf
- **Kill chain**: Actions on Objectives (post-compromise recon)
- **Related MITRE**: T1087 (parent — Account Discovery), T1069.001 (Local Groups), T1033 (System Owner/User)
