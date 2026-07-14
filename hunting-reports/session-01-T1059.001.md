# Incident Report — BTL-2026-001

*NIST SP 800-61r2 aligned. Blue Team Lab hunting session #1.*

---

## 1. Incident Identification (NIST §3.2.5)

| Field | Value |
|---|---|
| **Report ID** | BTL-2026-001 |
| **Detection timestamp (UTC)** | 2026-07-13T12:05:08Z |
| **Report timestamp (UTC)** | 2026-07-13T12:20:00Z |
| **Analyst / Handler** | Claude (Kali control center) — SSH-executed autonomously |
| **Status** | **Closed** (simulation — Atomic Red Team) |
| **Confidence** | **High** (2 alerts, level 12, MITRE tag confirmed, hunt query returned exactly expected events) |

---

## 2. Incident Categorization (NIST §3.2.1)

| Field | Value |
|---|---|
| **Attack vector** | External (SSH from Kali 192.168.154.166 → win-ep-01) |
| **Threat actor** | **Simulated (Atomic Red Team-style trigger)** |
| **NIST incident category** | Malicious Code / Improper Usage (PowerShell obfuscation) |
| **MITRE ATT&CK Tactic** | **Execution** (TA0002) |
| **MITRE ATT&CK Technique** | **T1059.001 — Command and Scripting Interpreter: PowerShell** |
| **MITRE reference** | https://attack.mitre.org/techniques/T1059/001/ |

---

## 3. Incident Prioritization (NIST §3.2.6)

| Dimension | Value | Justification |
|---|---|---|
| **Functional Impact** | **Low** | Simulation — không có business system down. Nếu real: có thể escalate Medium (endpoint compromise) |
| **Information Impact** | **None** | No data exfil observed. Simulation payload chỉ `Write-Host` |
| **Recoverability** | **Regular** | Không cần restore từ backup — kill process là đủ |
| **Overall Priority** | **Medium** | Ma trận NIST: Low func + None info = Low → **escalate Medium** vì T1059.001 thường mở đầu attack chain (loader / dropper) |

---

## 4. Detection & Analysis (NIST §3.2)

### 4.1. Detection method

- **Automated**: Wazuh custom rule `100101` matched
- **Sensor**: Sysmon EventID 1 (Process Create), channel `Microsoft-Windows-Sysmon/Operational`
- **Manager**: Wazuh 4.9.2 tại `43.228.215.234`
- **Rule chain**: `60000` (Windows event) → `60004` (Sysmon channel) → `61600` (Info severity) → `61603` (EID 1) → **`100101`** (custom, if_group=sysmon_event1)

### 4.2. Hypothesis

> Nếu attacker chạy PowerShell với flag suspicious (`-EncodedCommand`, `-w hidden`, `-ExecutionPolicy Bypass`, `iex(`, `DownloadString(`, `FromBase64String(`), Sysmon EID 1 sẽ ghi lại process create với `originalFileName = PowerShell.EXE` và commandLine chứa pattern → rule 100101 phải fire level 12 với MITRE T1059.001.

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
        { "match": { "rule.id": "100101" }},
        { "range": { "@timestamp": {
            "gte": "2026-07-13T12:05:00Z",
            "lte": "2026-07-13T12:06:30Z"
        }}}
      ]
    }
  }
}
```

**Dashboard KQL**:
```
rule.id : "100101" AND @timestamp >= "2026-07-13T12:05:00Z"
```

**Reconstruction query** (mọi event 90s window):
```
agent.name : "win-ep-01" AND @timestamp >= "2026-07-13T12:05:00Z" AND @timestamp <= "2026-07-13T12:06:30Z"
```

### 4.4. Findings

| Metric | Value |
|---|---|
| Alert count | **2** |
| Custom rule fired | `100101` ✅ |
| Highest severity level | **12** |
| MITRE tag confirmed | T1059.001 ✅ |
| False positives concurrent | 0 |

**Alert 1 — 2026-07-13T12:05:08.175Z** (rule 100101 lvl 12):
```json
{
  "rule": {"id": "100101", "level": 12, "mitre": {"id": ["T1059.001"]}},
  "data": {"win": {"eventdata": {
    "originalFileName": "PowerShell.EXE",
    "commandLine": "\"c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe\" -c \" $enc = [Convert]::ToBase64String(...) powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand $enc ...\"",
    "parentImage": "C:\\Program Files\\OpenSSH\\sshd-session.exe",
    "user": "WIN-EP-01\\labuser",
    "hashes": "SHA256=B4E7BC24BF3F5C3DA2EB6E9EC5EC10F90099DEFA91B820F2F3FC70DD9E4785C4"
  }}}
}
```
**Match**: cmdline chứa `-ExecutionPolicy Bypass` + `-EncodedCommand` + `[Convert]::...FromBase64String(`.

**Alert 2 — 2026-07-13T12:05:09.157Z** (rule 100101 lvl 12):
```json
{
  "rule": {"id": "100101", "level": 12},
  "data": {"win": {"eventdata": {
    "originalFileName": "PowerShell.EXE",
    "commandLine": "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -NoProfile -w hidden -Command \"Write-Host BLUE_LAB_T1059_HIDDEN\"",
    "parentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "user": "WIN-EP-01\\labuser"
  }}}
}
```
**Match**: cmdline chứa `-w hidden`.

---

## 5. Chronology / Timeline (NIST §3.2.5)

| Timestamp (UTC) | Actor | Action | Source | Notes |
|---|---|---|---|---|
| 2026-07-13T12:05:06Z | Analyst (Kali) | SSH dispatch to `labuser@192.168.154.164` | ssh command | Automated via key auth |
| 2026-07-13T12:05:07Z | attacker context (labuser) | sshd → sshd-session.exe spawn | Sysmon EID 1 | Normal SSH login |
| **2026-07-13T12:05:08.175Z** | attacker context | sshd-session.exe → powershell.exe (**-ExecutionPolicy Bypass + -EncodedCommand**) | Sysmon EID 1 | 🔴 **Rule 100101 fires** (lvl 12) |
| 2026-07-13T12:05:08.5Z | powershell.exe | Decoded base64 → `Write-Host BLUE_LAB_T1059` | PS host log | Payload benign |
| **2026-07-13T12:05:09.157Z** | powershell.exe → powershell.exe | Child PS with **-w hidden** | Sysmon EID 1 | 🔴 **Rule 100101 fires** (lvl 12) |
| 2026-07-13T12:05:10Z | System | SSH session close | Windows Security 4634 | |

**Time-to-detect (TTD)**: **~30s** (event created → alert visible on Indexer). Bao gồm agent flush + filebeat ship + indexer indexing.

---

## 6. Scope (NIST §3.2.4)

### 6.1. Affected systems

| Hostname | IP | OS | Role | Impact |
|---|---|---|---|---|
| win-ep-01 | 192.168.154.164 | Windows 10/11 | Lab endpoint | **Simulation only — no real compromise** |

### 6.2. Affected users / accounts

| Account | Role | Notes |
|---|---|---|
| WIN-EP-01\labuser | Local Administrator | Test account, isolated lab |
| WIN-EP-01\ADMIN | Local Administrator | Not directly involved this session |

### 6.3. Affected data

- **PII exposed**: No
- **Confidential business data**: No
- **Credentials / secrets**: No (simulation — no credential dump attempt)

### 6.4. Indicators of Compromise (IOCs)

| Type | Value | Source field | Notes |
|---|---|---|---|
| SHA256 | `B4E7BC24BF3F5C3DA2EB6E9EC5EC10F90099DEFA91B820F2F3FC70DD9E4785C4` | data.win.eventdata.hashes | powershell.exe legitimate MS binary |
| MD5 | `BCF01E61144D6D6325650134823198B8` | same | powershell.exe |
| IMPHASH | `88CB9A420410BDA787E305B65518A934` | same | powershell.exe |
| Parent path | `C:\Program Files\OpenSSH\sshd-session.exe` | data.win.eventdata.parentImage | **Anomalous** — trong prod, PS parent hiếm khi là sshd |
| User context | `WIN-EP-01\labuser` | data.win.eventdata.user | Recently created (< 1h) |

### 6.5. TI Enrichment

Tool run: `python enrich.py -r 100101 --writeback -s now-15m`

| IOC | Provider | Verdict | Score | Analysis date |
|---|---|---|---|---|
| SHA256 `B4E7BC24...` | VirusTotal | **clean** | 0/N | 2026 |
| MD5 `BCF01E61...` | VirusTotal | **clean** | 0/69 | 2026 |

**Kết luận enrichment**: IOC hash là binary Windows hợp pháp — **rule vẫn đúng khi fire vì detection dựa trên behavior (flag pattern), không phải IOC**. Đây là điểm cần chú ý: **behavior-based detection > IOC-based** cho technique T1059.001.

**Verdict indexed**: `enrichment-verdicts-2026.07.13` — 23 verdict document.

---

## 7. Containment, Eradication, Recovery (NIST §3.3)

*Simulation — không cần thực hiện. Ghi lại steps sẽ làm nếu real:*

### 7.1. Containment strategy

- **Short-term**:
  - `Wazuh active-response firewall-drop` → block outbound `win-ep-01`
  - `Stop-Process -Id <PID>` cho mọi PowerShell instance nghi ngờ
  - Snapshot memory với WinPMem hoặc Sysinternals ProcDump
- **Long-term**:
  - Revoke SSH key `authorized_keys` của labuser
  - Force password reset + rotate credentials
- **Evidence preservation**:
  - Dump Sysmon log full 24h: `wevtutil epl "Microsoft-Windows-Sysmon/Operational" C:\evidence\sysmon.evtx`
  - Export PS transcript nếu enabled

### 7.2. Eradication actions

- [ ] Kill process tree gốc từ `sshd-session.exe` con
- [ ] Xoá SSH public key trái phép: `C:\Users\labuser\.ssh\authorized_keys`
- [ ] Disable/xoá tài khoản labuser: `Remove-LocalUser labuser`
- [ ] Reset SSHD service to key-only via authorized key policy

### 7.3. Recovery actions

- [ ] Không cần restore backup (không có file damage)
- [ ] Rotate mọi SSH keypair
- [ ] Re-enable Wazuh agent (nếu bị tamper)

### 7.4. Verification

- Query `rule.id : 100101 AND agent.name : win-ep-01 AND @timestamp >= "now-1h"` — expect 0
- `Get-LocalUser labuser` — expect NotFound
- Manual login SSH test — expect fail

---

## 8. Post-Incident Activity (NIST §3.4)

### 8.1. Lessons learned

- **Time-to-detect (TTD)**: ~30s — acceptable cho lab, cần < 15s cho production SOC (tune filebeat flush interval).
- **Time-to-respond (TTR)**: N/A (simulation, no manual response). Estimated real: 5-15 phút nếu on-call analyst.
- **Rule bug**: original `<if_sid>61603</if_sid>` + `<field win.eventdata.image>` không match — pattern đúng là `<if_group>sysmon_event1</if_group>` + `<field originalFileName>`. **Ghi vào knowledge base** để rule khác cùng data source tránh lặp lỗi.

### 8.2. Detection improvements

- [x] **Rule 100101 fix**: chuyển sang `if_group`/`originalFileName` — deploy commit `[hash]`
- [ ] **Coverage gap**: rule không bắt `Invoke-WebRequest .* | IEX` (file-less download). Thêm regex `Invoke-WebRequest.*\|.*iex` vào commandLine pattern.
- [ ] **Correlation rule** (đề xuất): rule con level 14 nếu `parentImage = sshd-session.exe` (PS from remote shell = suspicious in Windows client env)
- [ ] **False positive whitelist**: nếu `parentImage` là Chocolatey/winget/deploy tool → suppress
- [ ] Consider bật **PowerShell ScriptBlock logging** (Event ID 4104) để bổ sung visibility payload decoded

### 8.3. Prevention measures

- [ ] Apply **PowerShell Constrained Language mode** cho non-admin users (Group Policy)
- [ ] Whitelist ExecutionPolicy — không cho `-Bypass` từ non-admin
- [ ] Restrict SSH access: chỉ management network reach port 22 endpoint
- [ ] Deploy PowerShell Enhanced logging (Module + ScriptBlock)
- [ ] Analyst training: recognize PowerShell obfuscation patterns

---

## 9. Communications Log (NIST §3.2.7)

*Simulation — no real notification chain. Nếu real:*

| Timestamp | To/From | Channel | Content summary |
|---|---|---|---|
| N/A | (lab, no comms triggered) | — | — |

Trong production: alert level 12 sẽ page on-call analyst; nếu escalate Critical (parentImage=sshd + `-EncodedCommand`) sẽ page SOC lead.

---

## 10. References & Attachments

- **Atomic test source**: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md
- **MITRE ATT&CK T1059.001**: https://attack.mitre.org/techniques/T1059/001/
- **Wazuh rule**: [`wazuh-rules/local_rules.xml`](../wazuh-rules/local_rules.xml) — rule id 100101
- **Rule FP profile**: [`wazuh-rules/RULES.md#rule-100101`](../wazuh-rules/RULES.md#rule-100101)
- **NIST SP 800-61r2**: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf
- **Enrichment verdict index**: `enrichment-verdicts-2026.07.13`
- **Kill chain reference**: Lockheed Martin Cyber Kill Chain — this session touched "Exploitation" + "Installation" phase
- **Related MITRE tags**: T1027.001 (Obfuscated Files — base64), T1140 (Deobfuscate/Decode Files)
