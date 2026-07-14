# Incident Report — BTL-2026-005

*NIST SP 800-61r2 aligned. Blue Team Lab hunting session #5.*
*⚠ **Rich false-positive case study** — session này chứng minh detection challenge cho technique T1003.008.*

---

## 1. Incident Identification (NIST §3.2.5)

| Field | Value |
|---|---|
| **Report ID** | BTL-2026-005 |
| **Detection timestamp (UTC)** | 2026-07-13T14:44:10Z |
| **Report timestamp (UTC)** | 2026-07-13T14:50:00Z |
| **Analyst / Handler** | Claude (Kali autonomous via SSH) |
| **Status** | **Closed** — 1 true positive + 7 expected false positives identified |
| **Confidence** | **High** cho true positive, sau khi phân tích context |

---

## 2. Incident Categorization (NIST §3.2.1)

| Field | Value |
|---|---|
| **Attack vector** | External (SSH to linux-ep-01) |
| **Threat actor** | **Simulated** (Blue Team Lab trigger) |
| **NIST incident category** | Malicious Code / Unauthorized Access — Credential Theft preparation |
| **MITRE ATT&CK Tactic** | **Credential Access** (TA0006) |
| **MITRE ATT&CK Technique** | **T1003.008 — OS Credential Dumping: /etc/passwd and /etc/shadow** |
| **MITRE reference** | https://attack.mitre.org/techniques/T1003/008/ |

---

## 3. Incident Prioritization (NIST §3.2.6)

| Dimension | Value | Justification |
|---|---|---|
| **Functional Impact** | **None** | Read-only, no system change |
| **Information Impact** | **Privacy Breach** (potential) | /etc/shadow chứa password hash — nếu attacker copy đi + crack offline = full credential compromise |
| **Recoverability** | **Extended** | Nếu hash bị exfil: **rotate password toàn bộ user** |
| **Overall Priority** | **High** | Credential Access technique + potential Privacy Breach → escalate |

---

## 4. Detection & Analysis (NIST §3.2)

### 4.1. Detection method

- **Automated**: rule `100100` matched
- **Sensor**: Linux auditd — audit rule `-w /etc/shadow -p rwa -k credential_read`
- **Prereq audit config**: `-p rwa` (read + write + attribute) trên /etc/shadow — **đã update trong Session 05 setup**
- **Rule chain**: `80700` (auditd generic) → **`100100`** (custom, level 12, key=credential_read)

### 4.2. Hypothesis

> Nếu attacker sau khi có root context (via sudo, exploit, hoặc post-compromise root) đọc `/etc/shadow` với ý định copy để crack offline → auditd sẽ log syscall `openat` (257) với `key=credential_read`, `file.name=/etc/shadow` → rule 100100 fires level 12.
>
> **Extended hypothesis (FP analysis)**: `/etc/shadow` được read hợp pháp bởi các system service để xác thực (sshd, sudo, PAM). Rule 100100 SẼ trigger cho các trường hợp này → cần post-filter theo `exe`.

### 4.3. Hunt queries

**OpenSearch DSL**:
```json
POST /wazuh-alerts-*/_search
{
  "query": {
    "bool": {
      "must": [
        { "match": { "rule.id": "100100" }},
        { "range": { "@timestamp": { "gte": "2026-07-13T14:44:00Z" }}}
      ]
    }
  }
}
```

**FP-filtered hunt** (chỉ true positive):
```
rule.id : "100100" 
  AND NOT data.audit.exe : ("/usr/sbin/sshd" OR "/usr/bin/sudo" OR "/usr/lib/systemd/systemd")
```

### 4.4. Findings

| Metric | Value |
|---|---|
| Total alerts | **8** |
| **True positives** | **1** (`cat /etc/shadow` — my actual trigger) |
| **False positives** | **7** (expected system activity) |
| Custom rule fired | 100100 ✅ level 12 |
| MITRE tag confirmed | T1003.008 ✅ |

**All 8 alerts breakdown**:

| # | Timestamp | exe | uid | auid | Verdict |
|---|---|---|---|---|---|
| 1 | 14:44:10.792 | `/usr/sbin/sshd` | 0 | 4294967295 | **FP** — SSH pre-auth password check |
| 2 | 14:44:10.800 | `/usr/sbin/sshd` | 0 | 4294967295 | **FP** — SSH auth flow (2nd read) |
| 3 | 14:44:10.827 | `/usr/sbin/sshd` | 0 | 1000 | **FP** — sshd post-auth session setup |
| 4 | 14:44:10.862 | `/usr/lib/systemd/systemd` | 0 | 4294967295 | **FP** — systemd user session init |
| 5 | 14:44:10.886 | `/usr/lib/systemd/systemd` | 0 | 1000 | **FP** — systemd continuing |
| 6 | 14:44:11.024 | `/usr/bin/sudo` | 1000 | 1000 | **FP** — sudo authenticating gnid (reads shadow for password validation) |
| 7 | **14:44:11.041** | **`/usr/bin/cat`** | **0** | **1000** | **🔴 TRUE POSITIVE** — gnid explicitly `sudo cat /etc/shadow` |
| 8 | 14:44:12.787 | `/usr/bin/sudo` | 1000 | 1000 | **FP** — second sudo (failed `less` attempt) |

**Sample true positive JSON**:
```json
{
  "rule": { "id": "100100", "level": 12, "mitre": {"id": ["T1003.008"]}},
  "data": { "audit": {
    "syscall": "257",          // openat
    "exe": "/usr/bin/cat",
    "uid": "0",                // running as root (post-sudo)
    "auid": "1000",            // original login user = gnid
    "key": "credential_read",
    "file": { "name": "/etc/shadow" }
  }}
}
```

---

## 5. Chronology / Timeline (NIST §3.2.5)

| Timestamp (UTC) | Actor | Action | Source | Verdict |
|---|---|---|---|---|
| 14:44:09Z | Analyst (Kali) | SSH command dispatch to gnid@linux-ep-01 | ssh | — |
| 14:44:10.792Z–.800Z | sshd | Read /etc/shadow (pre-auth password validation) | auditd | FP |
| 14:44:10.827Z | sshd | Read /etc/shadow (post-auth session) | auditd | FP |
| 14:44:10.862Z–.886Z | systemd | Read /etc/shadow (user session init) | auditd | FP |
| 14:44:11.024Z | gnid | `sudo cat ...` → sudo reads shadow for password check | auditd | FP |
| **14:44:11.041Z** | **cat (via sudo)** | **`cat /etc/shadow`** — attack trigger | **auditd** | **🔴 TRUE POSITIVE** |
| 14:44:12.787Z | gnid | Second `sudo` for `less` attempt (failed — less not installed) | auditd | FP |

**Attack chain reconstruction**: user `gnid` (uid 1000) ran `sudo cat /etc/shadow` — sudo auth check triggers FP #6, then spawned `cat` running as root (uid=0) with original login user auid=1000 → **event #7 = the actual credential read**.

**TTD**: ~1 giây từ syscall → indexer.

---

## 6. Scope (NIST §3.2.4)

### 6.1. Affected systems

| Hostname | IP | OS | Impact |
|---|---|---|---|
| linux-ep-01 | 192.168.154.166 | Ubuntu 22.04.5 | /etc/shadow was read; **content not exfiltrated** in this simulation |

### 6.2. Affected users / accounts

| Account | Role | Notes |
|---|---|---|
| gnid (uid 1000) | Sudo member | Executed sudo cat — authorized attacker context |
| root (uid 0) | System | cat process spawned via sudo |

### 6.3. Affected data

- **Credentials exposed**: **Potentially ALL user password hashes** (nếu cat output không đi `> /dev/null`).
- Trong session này: `sudo cat /etc/shadow > /dev/null` — output discarded → **no exfiltration**. Nhưng auditd log signal identical → detection cannot distinguish discard vs exfil.

### 6.4. Indicators of Compromise (IOCs)

**Behavior IOCs** (không phải hash/IP/domain):

| Type | Value | Source |
|---|---|---|
| Syscall | 257 (openat) | data.audit.syscall |
| Target file | `/etc/shadow` | data.audit.file.name |
| Process image (attacker) | `/usr/bin/cat` | data.audit.exe |
| Effective uid | 0 (root) | data.audit.uid |
| Login uid | 1000 (gnid) | data.audit.auid — attacker's original login |
| Audit key | credential_read | data.audit.key |

### 6.5. TI Enrichment

**Không applicable**. `/etc/shadow` là local file — không có external TI provider.

**Alternative context enrichment**:
- Sudo log: `/var/log/auth.log` grep `gnid.*COMMAND=/bin/cat /etc/shadow` — audit trail của sudo command
- Bash history: `~/.bash_history` của gnid — xem attacker chạy gì trước/sau

---

## 7. Containment, Eradication, Recovery (NIST §3.3)

### 7.1. Containment strategy

- **Short-term** (nếu real):
  - Isolate host qua Wazuh active-response `firewall-drop`
  - Kill process `cat` (đã kết thúc trong lab, but real attacker might be piping)
  - **Force logout gnid**: `pkill -KILL -u gnid` + revoke SSH key
- **Long-term**:
  - Remove gnid from sudo group (tối thiểu — cần review privilege)
  - Enable **auditd remote log** (`audisp-remote`) — attacker không thể xoá local audit
  - Investigate: attacker có exfil shadow file trước session này chưa? Grep 24h audit log

### 7.2. Eradication actions

- [ ] **Rotate ALL user passwords** ngay (assume compromised)
- [ ] Rotate SSH keys — force re-provision
- [ ] Force new password policy: longer + complexity + history
- [ ] Check for lateral movement: alerts từ `/etc/shadow` read trên host khác trong 24h

### 7.3. Recovery actions

- [ ] Fresh password reset cho mọi account trong /etc/shadow
- [ ] Force MFA setup nếu chưa có
- [ ] Backup + verify integrity /etc/shadow (compare hash với backup gần nhất)

### 7.4. Verification

- Grep alerts 24h: `rule.id : 100100 AND agent.name : linux-ep-01 AND NOT data.audit.exe : ("/usr/sbin/sshd" OR "/usr/bin/sudo" OR "/usr/lib/systemd/systemd")` — expect 0 sau eradication
- `auditctl -l` confirm audit rule vẫn active

---

## 8. Post-Incident Activity (NIST §3.4)

### 8.1. Lessons learned

- **✅ Rule 100100 hoạt động — không cần debug**: audit rule chain (`if_sid=80700`) đơn giản hơn Sysmon.
- **⚠ FP rate 7/8 = 87.5%**: rule trong current form KHÔNG PHÙ HỢP production — sẽ spam analyst với sshd/sudo/systemd noise.
- **Detection lesson quan trọng**: T1003.008 rất khó detect với audit rule đơn giản vì `/etc/shadow` được read hợp pháp bởi nhiều system component:
  - **sshd**: đọc để authenticate SSH login (mỗi login)
  - **sudo**: đọc để authenticate sudo command (mỗi sudo)
  - **systemd**: đọc trong user session init
  - **login/getty**: đọc khi console login
  - **passwd/chpasswd**: đọc khi thay đổi password
  - **cron**: có thể đọc để authenticate cronjobs user

### 8.2. Detection improvements — **critical for production**

**Fix 1** — Whitelist known-good readers:
```xml
<rule id="100100" level="12">
  <if_sid>80700</if_sid>
  <field name="audit.key">^credential_read$</field>
  <field name="audit.exe" negate="yes" type="pcre2">^/usr/(sbin/(sshd|nologin)|bin/(sudo|su|passwd|chpasswd|useradd|usermod|newusers|chsh|chfn|login)|lib/systemd/systemd(-[a-z]+)?)$</field>
  <description>T1003.008 - Suspicious read of /etc/shadow by $(audit.exe) [uid=$(audit.uid), auid=$(audit.auid)]</description>
  <mitre><id>T1003.008</id></mitre>
</rule>
```

Với whitelist này, chỉ 1/8 alert sẽ fire = 100% precision cho true positive.

**Fix 2** — Escalate nếu `cat/less/head/tail/dd/cp` đọc shadow (attacker's classic tools):
```xml
<rule id="100120" level="14">
  <if_sid>100100</if_sid>
  <field name="audit.exe" type="pcre2">/(cat|less|more|head|tail|dd|cp|hexdump|xxd|strings)$</field>
  <description>T1003.008 - CRITICAL: /etc/shadow read by common attacker tool $(audit.exe)</description>
</rule>
```

**Fix 3** — Track pipe operations (attacker often `cat /etc/shadow | ssh other-host`):
- Requires eBPF hook or `audit -a always,exit -S write -F path=/dev/tcp*` — advanced.

### 8.3. Prevention measures

- **Restrict sudo scope**: gnid không cần `sudo ALL` — dùng `sudoers.d/` để whitelist specific commands only.
- **SELinux/AppArmor**: MAC policy ngăn cat/less đọc /etc/shadow ngay cả với uid=0.
- **Password hashing algorithm**: verify /etc/shadow dùng `yescrypt` hoặc `sha512crypt` — không phải `md5crypt` (cracks nhanh với GPU).
- **File integrity monitoring**: audit `/etc/shadow` với `-p wa` để detect **write** (attacker set password mới) — đã có key=identity.
- **Read-only sensitive files**: mount `/etc` với `noexec` (không giúp cho read, nhưng ngăn attacker chạy script từ đó).

---

## 9. Communications Log (NIST §3.2.7)

*Simulation — no real notification.*

Real prod: **level 12 + credential access** = auto-page SOC lead. Nếu confirmed exfil (7.2 investigation) → page CISO + trigger password reset communication chain (email tất cả user 24h notice).

---

## 10. References & Attachments

- **Atomic test T1003.008**: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.008/T1003.008.md
- **MITRE ATT&CK T1003.008**: https://attack.mitre.org/techniques/T1003/008/
- **Wazuh rule**: [`wazuh-rules/local_rules.xml`](../wazuh-rules/local_rules.xml) — rule id 100100
- **Rule FP profile**: [`wazuh-rules/RULES.md#rule-100100`](../wazuh-rules/RULES.md#rule-100100)
- **Audit rule source**: [`auditd/wazuh-audit.rules`](../auditd/wazuh-audit.rules) — `-w /etc/shadow -p rwa -k credential_read`
- **NIST SP 800-61r2**: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf
- **Kill chain**: Actions on Objectives — Credential dumping
- **Related MITRE**: T1003 (parent OS Credential Dumping), T1552.001 (Credentials in Files), T1078 (Valid Accounts — post-crack)
