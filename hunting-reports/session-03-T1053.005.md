# Incident Report — BTL-2026-003

*NIST SP 800-61r2 aligned. Blue Team Lab hunting session #3.*

---

## 1. Incident Identification (NIST §3.2.5)

| Field | Value |
|---|---|
| **Report ID** | BTL-2026-003 |
| **Detection timestamp (UTC)** | 2026-07-13T14:14:49Z |
| **Report timestamp (UTC)** | 2026-07-13T14:20:00Z |
| **Analyst / Handler** | Claude (Kali autonomous via SSH) |
| **Status** | **Closed** (Atomic simulation) |
| **Confidence** | **High** — 1 alert, MITRE tag confirmed, task content decoded từ XML |

---

## 2. Incident Categorization (NIST §3.2.1)

| Field | Value |
|---|---|
| **Attack vector** | External (SSH remote command execution) |
| **Threat actor** | **Simulated** (Blue Team Lab trigger) |
| **NIST incident category** | Malicious Code / Unauthorized Access (persistence) |
| **MITRE ATT&CK Tactic** | **Persistence + Execution + Privilege Escalation** (multi-tactic — MITRE cho phép cùng technique cover nhiều tactic) |
| **MITRE ATT&CK Technique** | **T1053.005 — Scheduled Task/Job: Scheduled Task** |
| **MITRE reference** | https://attack.mitre.org/techniques/T1053/005/ |

---

## 3. Incident Prioritization (NIST §3.2.6)

| Dimension | Value | Justification |
|---|---|---|
| **Functional Impact** | **Low** | Simulation. Real: Medium (task chạy tự động → có thể trở nên attack chain autonomous) |
| **Information Impact** | **None** | Không có data access trong task này |
| **Recoverability** | **Regular** | `schtasks /delete` là đủ |
| **Overall Priority** | **Medium** | Persistence + potential SYSTEM privilege → cần escalate ngay |

---

## 4. Detection & Analysis (NIST §3.2)

### 4.1. Detection method

- **Automated**: Wazuh custom rule `100104` matched
- **Sensor**: Windows Security channel EventID **4698** ("A scheduled task was created")
- **Prereq audit config**: `auditpol /set /subcategory:"Other Object Access Events" /success:enable` — trước session này CHƯA bật (0 event historical). Ta enable ngay trong session.
- **Rule chain**: `60000` → `60003` (win security) → `60103` (Windows Security-Auditing) → **`100104`** (custom, level 10, EID 4698)

### 4.2. Hypothesis

> Nếu attacker tạo scheduled task (qua `schtasks.exe`, `Register-ScheduledTask`, Task Scheduler UI, hoặc COM API), Windows Security EID 4698 sẽ ghi với `taskName`, `taskContent` (XML), `subjectUserName` → rule 100104 phải fire level 10 với MITRE T1053.005.

### 4.3. Hunt queries

**OpenSearch DSL**:
```json
POST /wazuh-alerts-*/_search
{
  "size": 20,
  "query": {
    "bool": {
      "must": [
        { "match": { "rule.id": "100104" }},
        { "range": { "@timestamp": { "gte": "2026-07-13T14:14:40Z" }}}
      ]
    }
  }
}
```

**Dashboard KQL**:
```
rule.id : "100104" AND @timestamp >= "2026-07-13T14:14:40Z"
```

**Broad hunt across time**:
```
data.win.system.eventID : "4698" AND agent.name : "win-ep-01"
```

### 4.4. Findings

| Metric | Value |
|---|---|
| Alert count | **1** |
| Custom rule fired | 100104 ✅ level 10 |
| Highest severity level | 10 |
| MITRE tag confirmed | T1053.005 ✅ (multi-tactic: Execution, Persistence, Privilege Escalation) |
| False positives concurrent | 0 |

**Alert — 2026-07-13T14:14:49.869Z**:
```json
{
  "rule": {
    "id": "100104", "level": 10,
    "mitre": {"id": ["T1053.005"], "tactic": ["Execution","Persistence","Privilege Escalation"]},
    "description": "T1053.005 - Scheduled Task created: \\BTLab_Session03 by labuser"
  },
  "data": {"win": {
    "system": {"eventID": "4698"},
    "eventdata": {
      "taskName": "\\BTLab_Session03",
      "subjectUserName": "labuser",
      "subjectUserSid": "S-1-5-21-4188382834-1221911911-931124274-1001",
      "clientProcessId": "1204",
      "parentProcessId": "6424",
      "taskContent": "<Task ...><Triggers><LogonTrigger>...<Actions Context=\"Author\"><Exec><Command>cmd.exe</Command><Arguments>/c echo BLUE_LAB</Arguments>..."
    }
  }}
}
```

**Decoded `taskContent` (từ XML)**:
- **Trigger**: `<LogonTrigger>` — chạy khi user login
- **Enabled**: true
- **Action**: `Exec → cmd.exe /c echo BLUE_LAB`
- **Principal**: `WIN-EP-01\labuser` với `LogonType=InteractiveToken`, `RunLevel=LeastPrivilege`

Không SYSTEM privilege → giảm severity chút. Nếu `RunLevel=HighestAvailable` với admin token → escalate lên Critical.

---

## 5. Chronology / Timeline (NIST §3.2.5)

| Timestamp (UTC) | Actor | Action | Source | Notes |
|---|---|---|---|---|
| 2026-07-13T14:14:48Z | Analyst (Kali) | SSH dispatch | ssh | Automated |
| 2026-07-13T14:14:49.5Z | labuser | Chạy `auditpol /set` để enable audit | (không log) | Prereq setup |
| 2026-07-13T14:14:49.6Z | labuser | `schtasks /create /tn "BTLab_Session03" /tr "cmd.exe /c echo BLUE_LAB" /sc onlogon /f` | (spawn schtasks.exe) | |
| **2026-07-13T14:14:49.869Z** | Task Scheduler service | Register task via COM API | Windows Security 4698 | 🔴 **Rule 100104 fires** |
| 2026-07-13T14:14:52Z | labuser | `schtasks /delete /tn "BTLab_Session03" /f` | (should also 4699 delete event) | Cleanup |
| 2026-07-13T14:14:52Z | SSH | Session close | Windows Security 4634 | |

**TTD**: **~1 giây** — Windows Security channel flush nhanh.

---

## 6. Scope (NIST §3.2.4)

### 6.1. Affected systems

| Hostname | IP | OS | Role | Impact |
|---|---|---|---|---|
| win-ep-01 | 192.168.154.164 | Windows 10/11 | Lab endpoint | Simulation — task xóa ngay sau tạo |

### 6.2. Affected users / accounts

| Account | Role | Notes |
|---|---|---|
| WIN-EP-01\labuser | Local Administrator | Task tạo trong context user, không SYSTEM |

### 6.3. Affected data

- **PII / Confidential**: None
- **System integrity**: Temporary — task existed briefly

### 6.4. Indicators of Compromise (IOCs)

| Type | Value | Source field | Notes |
|---|---|---|---|
| **Task name** | `\BTLab_Session03` | data.win.eventdata.taskName | Prefix `\` = root folder Task Scheduler |
| **Task action** | `cmd.exe /c echo BLUE_LAB` | taskContent XML `<Exec><Command>` | Payload — trivial trong lab |
| **Trigger** | `LogonTrigger` | taskContent XML | Chạy khi user login (persistence trigger) |
| **User SID** | `S-1-5-21-...-1001` | subjectUserSid | labuser |
| **Client Process ID** | 1204 | clientProcessId | schtasks.exe PID (attacker tool) |
| **Parent Process ID** | 6424 | parentProcessId | Có thể là sshd-session.exe con của labuser SSH session |

### 6.5. TI Enrichment

**Không applicable**. IOC là task metadata, không phải hash/IP/domain.

**Pivot recommendation**: dùng `parentProcessId` join với Sysmon EID 1 để tìm process cha (attacker's shell). Có thể correlate với session 01/02 nếu là cùng attacker chain.

---

## 7. Containment, Eradication, Recovery (NIST §3.3)

### 7.1. Containment strategy

- **Short-term** (real):
  - `schtasks /query /fo LIST /v` → enumerate ALL tasks, tìm suspicious
  - Backup task XML: `schtasks /query /xml /tn "\\BTLab_Session03" > C:\evidence\suspicious_task.xml`
  - Isolate host qua Wazuh active-response
- **Long-term**:
  - Enable **audit "Other Object Access Events"** VĨNH VIỄN (đã enable trong session này, cần verify persist qua reboot)
  - GPO: restrict user tạo scheduled task ngoài `%SystemRoot%\...`

### 7.2. Eradication actions

- [x] Cleanup thực hiện — `schtasks /delete /tn BTLab_Session03 /f`
- Real: kill process nếu task đã trigger (`Get-Process | Where { $_.Path -like "*evil*" } | Stop-Process`)
- Delete cả folder task nếu attacker tạo custom folder: `schtasks /delete /tn "\Attacker\*" /f`

### 7.3. Recovery actions

- [ ] Verify: `schtasks /query /tn "\BTLab_Session03"` — expect "ERROR: The system cannot find the file specified"
- [ ] Audit ALL scheduled tasks vs baseline (Autoruns.exe hoặc `Get-ScheduledTask` full dump)
- [ ] Reset user session token nếu compromise sâu

### 7.4. Verification

- Query `rule.id : 100104 AND agent.name : win-ep-01 AND @timestamp >= "now-1h"` — expect 1 (session)
- Không có 4698 event mới → không có task khác đang được tạo lén

---

## 8. Post-Incident Activity (NIST §3.4)

### 8.1. Lessons learned

- **Time-to-detect (TTD)**: **~1 giây** — Windows Security channel + rule chain đơn giản = detect gần như real-time.
- **✅ Rule 100104 hoạt động NGAY LẦN ĐẦU** — khác biệt lớn so với session 01 (T1059.001) và 02 (T1547.001) phải debug rule chain.

**Quan trọng — rút ra pattern**:

| Data source | Rule chain cần | Có bug trước đây? |
|---|---|---|
| **Sysmon EID N** | Phức tạp — không dùng `<if_sid>61603/61615</if_sid>` được | ✗ Yes (sessions 1, 2) |
| **Windows Security 4XXX** | Đơn giản — `<if_sid>60103</if_sid>` + `<field win.system.eventID>^4XXX$</field>` | ✓ No |

Xem `docs/04-detection-rules.md` §9 (Appendix — Rule debugging lessons) để chi tiết.

- **Prereq audit enablement**: audit "Other Object Access Events" default DISABLED trên fresh Windows. Nếu attacker tạo task trước khi bạn enable audit → EID 4698 KHÔNG log → rule không có input → detection miss. **Enable audit ngay khi setup endpoint là bắt buộc**.

### 8.2. Detection improvements

- [ ] **Enrichment nội bộ**: extract `taskContent` XML → parse `<Command>`, `<Arguments>`, `<Trigger>` type → gán severity dựa trên:
  - Command là LOLBIN (cmd, powershell, wmic, mshta, rundll32) → level 14
  - Trigger là `BootTrigger` hoặc `TimeTrigger` (không cần user login) → level 12
  - `<RunLevel>HighestAvailable</RunLevel>` + admin token → level 14
- [ ] **Correlation**: rule level 15 nếu ≥2 task được tạo trong 5 phút bởi cùng user (mass persistence)
- [ ] **Follow-up**: monitor EID 4699 (task deleted) — nếu attacker cleanup nhanh cùng session → forensic evidence gap. Tạo rule level 8 alert "Scheduled Task deleted within 1 minute of creation" → suspicious cleanup.

### 8.3. Prevention measures

- [ ] **GPO — Task Scheduler policy**: cho phép user tạo task chỉ trong `\User\...` folder, không cho tạo ngoài
- [ ] **AppLocker**: block `schtasks.exe` cho non-admin (chỉ IT dùng)
- [ ] **Weekly baseline dump**: `Get-ScheduledTask | Export-Clixml baseline.xml` → diff với current mỗi tuần
- [ ] **Sigma rule community**: import Sigma T1053.005 rules cho coverage rộng hơn (chuyển đổi Sigma → Wazuh via `sigmac`)

---

## 9. Communications Log (NIST §3.2.7)

*Simulation — no real notification chain.*

Trong production: level 10 = escalate SOC lead, thông báo user's manager nếu task chạy binary lạ.

---

## 10. References & Attachments

- **Atomic test source**: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md
- **MITRE ATT&CK T1053.005**: https://attack.mitre.org/techniques/T1053/005/
- **Windows Event 4698 reference**: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4698
- **Wazuh rule**: [`wazuh-rules/local_rules.xml`](../wazuh-rules/local_rules.xml) — rule id 100104
- **Rule FP profile**: [`wazuh-rules/RULES.md#rule-100104`](../wazuh-rules/RULES.md#rule-100104)
- **Rule debugging appendix**: [`docs/04-detection-rules.md#9-appendix-rule-debugging-lessons`](../docs/04-detection-rules.md#9-appendix--rule-debugging-lessons-từ-phase-6-hunting-sessions)
- **Kill chain step**: Installation (persistence)
- **Related MITRE**: T1053 (parent), T1547 (autorun — session 02), T1055 (via loaded scheduled task binary)
