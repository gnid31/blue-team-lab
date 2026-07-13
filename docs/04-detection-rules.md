# Phase 4 — 10 Custom Detection Rules mapped MITRE ATT&CK

> Doc chi tiết cho người **chưa từng viết Wazuh rule**. Đọc từ trên xuống, không skip.

---

## 0. Kiến thức nền

### 0.1. Wazuh xử lý 1 event như thế nào?

Khi 1 dòng log đến Manager, nó đi qua **3 giai đoạn** trong process `wazuh-analysisd`:

```
   ┌──────────────────┐
   │ log line (text)  │  vd: type=SYSCALL msg=audit(...) key="priv_esc"
   └────────┬─────────┘
            │
   ┌────────▼─────────┐   1. PRE-DECODING
   │ pre-decoder      │   Tách timestamp, hostname, program-name
   │ (built-in)       │   Ví dụ: chương trình phát log = "audit"
   └────────┬─────────┘
            │
   ┌────────▼─────────┐   2. DECODING
   │ decoder          │   Chọn decoder khớp (audit / sysmon / apache / ...)
   │ (xml)            │   Regex parse text → field JSON: data.audit.key,
   └────────┬─────────┘                                     data.audit.exe, ...
            │
   ┌────────▼─────────┐   3. RULE MATCHING
   │ rule engine      │   Duyệt qua tất cả rule (built-in + custom).
   │ (xml)            │   Rule khớp → sinh alert level N, mô tả, MITRE tag.
   └────────┬─────────┘
            │
   ┌────────▼─────────┐
   │ alerts.json      │   → filebeat → indexer → Dashboard
   └──────────────────┘
```

**Điểm mấu chốt**: rule không match trực tiếp text — nó match **field đã decode**. Nên trước khi viết rule, phải biết decoder nào chạy và field JSON nào có sẵn.

### 0.2. Decoder có sẵn cho lab này

| Nguồn log | Decoder Wazuh dùng | Field JSON quan trọng |
|---|---|---|
| **auditd** (Linux) | `audit` (built-in) | `data.audit.key`, `data.audit.exe`, `data.audit.a0..a3`, `data.audit.euid`, `data.audit.command` |
| **Sysmon** (Windows) | `windows_eventchannel` (built-in) | `data.win.system.eventID`, `data.win.eventdata.image`, `data.win.eventdata.commandLine`, `data.win.eventdata.parentImage`, `data.win.eventdata.targetFilename` |
| **Windows Security** | `windows_eventchannel` | `data.win.system.eventID` (4624, 4697, 4698...), `data.win.eventdata.logonType`, `data.win.eventdata.subjectUserName` |

Tra chi tiết: https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/decoders.html

### 0.3. Cấu trúc rule XML

Mỗi rule là 1 khối XML như sau:

```xml
<group name="linux,mitre,execution,">
  <rule id="100101" level="8">
    <if_sid>80700</if_sid>                             <!-- 1. Parent rule (audit decoder rule) -->
    <field name="audit.key">^execve$</field>           <!-- 2. Field match, regex -->
    <field name="audit.exe">bash$|sh$|/dash$</field>
    <description>Suspicious shell execve on Linux (possible T1059)</description>
    <mitre>
      <id>T1059.004</id>                               <!-- 3. MITRE technique -->
    </mitre>
    <group>attack,execution,</group>                    <!-- 4. Extra tag -->
  </rule>
</group>
```

Ý nghĩa từng thuộc tính/tag:

| Element | Nghĩa |
|---|---|
| `<group name="...">` | Wrapper gom nhiều rule có chủ đề chung. Comma-separated tag để filter trên Dashboard |
| `<rule id="...">` | ID duy nhất trong toàn Manager. **Custom dùng dải `100100-100199`** (đã convention) |
| `level="0..15"` | Mức nghiêm trọng. **Level 0** = silent (chỉ log, không thành alert). Level 3–5 = info/notice. Level 7–9 = warning. Level 12+ = critical, page oncall |
| `<if_sid>N</if_sid>` | **Điều kiện**: chỉ chạy rule này khi rule N (built-in) đã match. Đây là cách gắn vào decoder chain. VD `80700` là rule audit generic |
| `<field name="X">regex</field>` | Match value của field JSON `X` bằng regex OSSEC (POSIX ERE) |
| `<match>text</match>` | Match substring trong `full_log` (raw). Ít tinh hơn `field`, chỉ dùng khi decoder không parse ra field |
| `<description>` | Text hiện trên Dashboard alert |
| `<mitre><id>T1059.004</id></mitre>` | Gán technique MITRE (multiple `<id>` ok) — Dashboard hiển thị link tới MITRE |
| `<options>no_full_log</options>` | Bỏ full_log khỏi alert để tiết kiệm dung lượng |
| `<frequency>` + `<timeframe>` | Rule kiểu correlation: đếm số event trong khoảng thời gian |

### 0.4. Rule ID nào an toàn?

- **1–99999**: dải Wazuh chính thức, không được dùng.
- **100000–120000**: dải **custom** khuyến nghị.
- Convention lab này: **`100100–100199`**.

Trùng ID → rule sau sẽ bị Wazuh **bỏ qua khi load** (Manager log warning).

### 0.5. File chứa rule custom

Trên Manager (VPS), file duy nhất bạn cần edit:

```
/var/ossec/etc/rules/local_rules.xml
```

Có sẵn khi cài Wazuh. Nội dung mặc định:

```xml
<!-- Local rules -->
<!-- Modify it at your will. -->

<group name="local,syslog,sshd,">
  <!-- Example rule commented out -->
</group>
```

Thêm rule mới vào đây, mỗi rule 1 `<group>` hoặc gom lại theo technique.

Toàn bộ rule built-in nằm ở `/var/ossec/ruleset/rules/*.xml` — **không sửa** file này (sẽ bị ghi đè khi upgrade). Chỉ đọc để tham chiếu.

### 0.6. Workflow phát triển rule

```
┌──────────────────────────────────────────────────────────────────┐
│  1. Sinh 1 event mẫu trên endpoint (VD: chạy `sudo whoami`)       │
│                                                                    │
│  2. Query indexer / xem Dashboard Discover → lấy raw JSON alert   │
│     hoặc dùng /var/ossec/logs/archives/archives.json (nếu logall) │
│                                                                    │
│  3. Xác định field cần match (data.audit.key, data.win....)       │
│                                                                    │
│  4. Viết rule XML → append vào local_rules.xml                    │
│                                                                    │
│  5. Test cú pháp:  sudo /var/ossec/bin/wazuh-logtest              │
│     — Đây là REPL, paste raw log vào, xem rule nào match          │
│                                                                    │
│  6. Restart manager:  sudo systemctl restart wazuh-manager        │
│                                                                    │
│  7. Reproduce event, verify alert xuất hiện trên Dashboard        │
│     với đúng rule.id, level, MITRE tag                             │
│                                                                    │
│  8. Tune false positive (dùng <if_sid>, <field negate>...)         │
└──────────────────────────────────────────────────────────────────┘
```

### 0.7. `wazuh-logtest` — tool test rule interactive

Trên Manager:

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Vào prompt. Paste 1 dòng raw log (ví dụ 1 dòng từ `/var/log/audit/audit.log`). Output sẽ báo:
- Decoder nào chạy
- Field decode được
- Rule nào match, level, description

Ưu điểm: test được **trước khi restart manager**, không phải reproduce event thật.

---

## 1. 10 technique cần detect

Danh sách khớp CV, mapping data source có sẵn trong lab:

| # | Rule ID | MITRE | Technique | Data source | EventID / audit key |
|---|---|---|---|---|---|
| 1 | 100100 | **T1003.008** | Credential dumping — read `/etc/shadow` | auditd | key=identity, path=/etc/shadow |
| 2 | 100101 | **T1059.001** | PowerShell suspicious cmdline | Sysmon | EventID 1 image=powershell.exe |
| 3 | 100102 | **T1543.003** | Windows Service Create | Windows Security | EventID 4697 |
| 4 | 100103 | **T1021.002** | Lateral movement via SMB | Windows Security | EventID 4624 LogonType=3 |
| 5 | 100104 | **T1053.005** | Scheduled Task creation | Windows Security | EventID 4698 |
| 6 | 100105 | **T1087.001** | Local account discovery | Sysmon / auditd | Sysmon EID1 image=net.exe cmdline user; auditd execve /usr/bin/id |
| 7 | 100106 | **T1550.002** | Pass-the-Hash | Windows Security | EventID 4624 LogonType=3 + AuthPkg=NTLM + non-network account |
| 8 | 100107 | **T1562.001** | Disable Defender / AV | Sysmon | EID1 image=sc.exe stop | EID13 registry Defender key |
| 9 | 100108 | **T1547.001** | Registry Run Key persistence | Sysmon | EventID 13 targetObject=...\CurrentVersion\Run |
| 10 | 100109 | **T1074.001** | Local data staging | Sysmon / auditd | Sysmon EID11 file in Temp/*.zip; auditd write /tmp/*.tar |

> **Lưu ý mapping**: MITRE ID có thể có sub-technique. Ví dụ T1003 (Credential Dumping) có T1003.001 (LSASS), T1003.008 (/etc/passwd,/etc/shadow). Chọn sub-technique **cụ thể nhất** để Dashboard hiển thị chính xác.

---

## 2. Cấu trúc file `local_rules.xml` đề xuất

```xml
<!-- ============================================================
     Blue Team Lab — Custom Detection Rules
     ID range: 100100 – 100199
     Author:   Tran Cong Dinh
     ============================================================ -->

<!-- ================= Group Linux (auditd) ==================== -->
<group name="linux,mitre,blue-team-lab,">
  <!-- Rule 100100: T1003.008 -->
  <!-- Rule 100105 (linux part): T1087.001 -->
  <!-- Rule 100109 (linux part): T1074.001 -->
</group>

<!-- ================= Group Windows (Sysmon + Security) ======= -->
<group name="windows,mitre,blue-team-lab,">
  <!-- Rule 100101: T1059.001 -->
  <!-- Rule 100102: T1543.003 -->
  <!-- Rule 100103: T1021.002 -->
  <!-- Rule 100104: T1053.005 -->
  <!-- Rule 100105 (windows part): T1087.001 -->
  <!-- Rule 100106: T1550.002 -->
  <!-- Rule 100107: T1562.001 -->
  <!-- Rule 100108: T1547.001 -->
  <!-- Rule 100109 (windows part): T1074.001 -->
</group>
```

Tùy bạn tổ chức. Có thể tách theo technique, mỗi technique 1 `<group>`.

---

## 3. 10 rule — template + giải thích chi tiết

Với mỗi rule dưới đây, tôi cho: **(a) mô tả technique, (b) event mẫu, (c) field cần match, (d) template XML, (e) cách test**.

### 3.1. Rule 100100 — T1003.008: Read `/etc/shadow`

**(a) Mô tả**: `/etc/shadow` chứa hash password của mọi user Linux. Attacker root/`shadow`-group đọc file này = ý định crack password offline (John/Hashcat). Non-root user thường không có quyền đọc; nếu có action `read` (`-p r`) → suspicious.

**(b) Event mẫu** (sau khi `sudo cat /etc/shadow`):
```
type=SYSCALL msg=audit(...): arch=c000003e syscall=257 success=yes
  auid=1000 uid=0 comm="cat" exe="/usr/bin/cat" key="identity"
```

> **Lưu ý**: audit rule ta có ở Phase 2 dùng `-p wa` (write, attribute) cho `/etc/shadow`. Muốn bắt **read**, cần thêm `-p r` vào audit rules. Xem `auditd/wazuh-audit.rules`, đổi dòng `-w /etc/shadow -p wa` thành `-w /etc/shadow -p rwa -k credential_read`.

**(c) Field**:
- `data.audit.key` = `credential_read`
- `data.audit.exe` — tên process đọc (cat, less, python, ...)

**(d) Template**:
```xml
<rule id="100100" level="12">
  <if_sid>80700</if_sid>
  <field name="audit.key">^credential_read$</field>
  <description>T1003.008 - Read of /etc/shadow by $(audit.exe) [uid=$(audit.uid)]</description>
  <mitre>
    <id>T1003.008</id>
  </mitre>
  <group>credential_access,</group>
</rule>
```

Ý nghĩa `$(audit.exe)` = biến, Wazuh replace bằng value field khi sinh alert. Giúp `description` tự động điền chi tiết.

**(e) Test**:
```bash
# Trên VM Linux
sudo cat /etc/shadow > /dev/null
# Chờ 10s
```
Dashboard: filter `rule.id: 100100 AND agent.name: linux-ep-01`.

---

### 3.2. Rule 100101 — T1059.001: PowerShell with suspicious flags

**(a)**: PowerShell thường là công cụ hợp lệ, nhưng các flag `-EncodedCommand`, `-nop`, `-w hidden`, `-ExecutionPolicy Bypass` là **đặc trưng** của reverse shell / dropper (Empire, Cobalt Strike, custom loader).

**(b) Event mẫu** (Sysmon EventID 1):
```json
{
  "data": {
    "win": {
      "system": {"eventID": "1"},
      "eventdata": {
        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "commandLine": "powershell.exe -nop -w hidden -EncodedCommand JABzAD..."
      }
    }
  }
}
```

**(c) Field**:
- `data.win.system.eventID` = `1`
- `data.win.eventdata.image` chứa `powershell.exe`
- `data.win.eventdata.commandLine` chứa 1 trong các flag suspicious

**(d) Template**:
```xml
<rule id="100101" level="12">
  <if_sid>61603</if_sid>                                <!-- 61603 = Sysmon Event 1 parent rule -->
  <field name="win.eventdata.image">powershell\.exe$|pwsh\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">
    (?i)-e(nc|ncodedcommand)?\s|\s-w\s+hidden|\s-nop|-executionpolicy\s+bypass|iex\s*\(
  </field>
  <description>T1059.001 - Suspicious PowerShell cmdline: $(win.eventdata.commandLine)</description>
  <mitre>
    <id>T1059.001</id>
  </mitre>
  <group>execution,</group>
</rule>
```

Chú ý:
- `<if_sid>61603</if_sid>` — parent Sysmon Event 1 rule (built-in). Không có → rule chạy chậm vì phải xét mọi event.
- `type="pcre2"` — dùng regex PCRE2 (mạnh hơn OSSEC regex). Cho phép `(?i)` case-insensitive, `\s`, `|`.
- Regex bắt: `-e`, `-encodedcommand`, `-w hidden`, `-nop`, `-executionpolicy bypass`, `iex(...)`.

**(e) Test**:
```powershell
# Trên VM Windows
powershell.exe -nop -w hidden -Command "Write-Host test"
```

---

### 3.3. Rule 100102 — T1543.003: New Windows Service

**(a)**: Attacker tạo Windows Service để persistence (chạy lại khi reboot với quyền SYSTEM). Windows Security Log EventID **4697** (A service was installed) là detect chính thức.

**(b) Event mẫu**:
```json
{
  "data": {
    "win": {
      "system": {"eventID": "4697", "channel": "Security"},
      "eventdata": {
        "serviceName": "EvilPersist",
        "serviceFileName": "cmd.exe /c powershell -enc ...",
        "serviceType": "0x10",
        "serviceStartType": "2",
        "subjectUserName": "ADMIN"
      }
    }
  }
}
```

**(c) Field**:
- `data.win.system.eventID` = `4697`
- `data.win.eventdata.serviceFileName` — path binary chạy khi service start
- `data.win.eventdata.serviceStartType` — 2 = Auto-start (persistence)

**(d) Template**:
```xml
<rule id="100102" level="10">
  <if_sid>60000</if_sid>                                <!-- Windows event parent -->
  <field name="win.system.eventID">^4697$</field>
  <description>T1543.003 - New Windows service installed: $(win.eventdata.serviceName) → $(win.eventdata.serviceFileName)</description>
  <mitre>
    <id>T1543.003</id>
  </mitre>
  <group>persistence,</group>
</rule>

<!-- Rule con: escalate nếu service chạy powershell/cmd (dấu hiệu malware) -->
<rule id="100112" level="14">
  <if_sid>100102</if_sid>
  <field name="win.eventdata.serviceFileName" type="pcre2">
    (?i)(powershell|cmd\.exe|wscript|cscript|mshta|rundll32)
  </field>
  <description>T1543.003 - Suspicious service binary (LOLBIN)</description>
  <mitre>
    <id>T1543.003</id>
  </mitre>
</rule>
```

**Kỹ thuật rule chain**: rule cha (100102) bắt mọi service install; rule con (100112) chỉ trigger nếu binary khả nghi. Cách này giữ visibility đầy đủ mà không quá noisy.

**(e) Test** (PowerShell Admin):
```powershell
sc.exe create TestBTLab binPath= "cmd.exe /c echo test" start= auto
# Trigger EventID 4697
sc.exe delete TestBTLab
```

---

### 3.4. Rule 100103 — T1021.002: SMB Lateral Movement

**(a)**: Attacker dùng SMB (port 445) để mount share hoặc chạy PsExec từ máy khác. Windows Security EventID **4624** LogonType `3` (Network) + package `NTLM`/`Kerberos` từ IP nội bộ = dấu hiệu.

**(b) Event mẫu**:
```json
{
  "data": {
    "win": {
      "system": {"eventID": "4624"},
      "eventdata": {
        "logonType": "3",
        "targetUserName": "administrator",
        "ipAddress": "192.168.154.150",
        "authenticationPackageName": "NTLM"
      }
    }
  }
}
```

**(c) Field**:
- `eventID` = `4624`
- `logonType` = `3` (network)
- `ipAddress` ∈ RFC1918 range (internal)

**(d) Template**:
```xml
<rule id="100103" level="8">
  <if_sid>60000</if_sid>
  <field name="win.system.eventID">^4624$</field>
  <field name="win.eventdata.logonType">^3$</field>
  <field name="win.eventdata.ipAddress" type="pcre2">
    ^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)
  </field>
  <description>T1021.002 - SMB network logon: $(win.eventdata.targetUserName) from $(win.eventdata.ipAddress)</description>
  <mitre>
    <id>T1021.002</id>
  </mitre>
  <group>lateral_movement,</group>
</rule>
```

**Tune false positive**: user hợp lệ (domain admin, file share) sẽ cũng trigger. Cách khắc phục:
- Thêm `<field name="win.eventdata.targetUserName" negate="yes">^(svc_backup|domain\\administrator)$</field>`
- Hoặc dùng `<frequency>` để chỉ alert khi cùng account login từ ≥3 host khác nhau trong 1h (correlation).

**(e) Test**:
```powershell
# Từ 1 máy khác trong VMware LAN, mount share
net use \\192.168.154.166\c$ /user:ADMIN <password>
```

---

### 3.5. Rule 100104 — T1053.005: Scheduled Task Created

**(a)**: Attacker tạo scheduled task để persistence. Windows Security EventID **4698** (A scheduled task was created).

**(b) Field**: `eventID=4698`, `taskName`, `taskContent` (XML).

**(c) Template**:
```xml
<rule id="100104" level="10">
  <if_sid>60000</if_sid>
  <field name="win.system.eventID">^4698$</field>
  <description>T1053.005 - Scheduled Task created: $(win.eventdata.taskName)</description>
  <mitre>
    <id>T1053.005</id>
  </mitre>
  <group>persistence,</group>
</rule>
```

**(d) Test**:
```powershell
schtasks /create /tn "BTLab_Test" /tr "cmd.exe" /sc onlogon
schtasks /delete /tn "BTLab_Test" /f
```

---

### 3.6. Rule 100105 — T1087.001: Account discovery

**(a)**: Attacker sau khi vào máy chạy `whoami`, `net user`, `id` để enum account. Bắt bằng Sysmon (Windows) hoặc auditd (Linux).

**Windows part**:
```xml
<rule id="100105" level="5">
  <if_sid>61603</if_sid>
  <field name="win.eventdata.image" type="pcre2">
    (?i)\\(net\.exe|net1\.exe|whoami\.exe|quser\.exe)$
  </field>
  <field name="win.eventdata.commandLine" type="pcre2">
    (?i)(user|localgroup|group|/domain)
  </field>
  <description>T1087.001 - Account discovery via $(win.eventdata.image)</description>
  <mitre>
    <id>T1087.001</id>
  </mitre>
  <group>discovery,</group>
</rule>
```

**Linux part**:
```xml
<rule id="100115" level="5">
  <if_sid>80700</if_sid>
  <field name="audit.key">^execve$</field>
  <field name="audit.exe" type="pcre2">/(whoami|id|getent)$</field>
  <description>T1087.001 - Account discovery: $(audit.exe) by uid=$(audit.uid)</description>
  <mitre>
    <id>T1087.001</id>
  </mitre>
  <group>discovery,</group>
</rule>
```

**Test**:
```powershell
whoami /all
net user
```
```bash
whoami
id
getent passwd
```

---

### 3.7. Rule 100106 — T1550.002: Pass-the-Hash

**(a)**: PTH = login network dùng NTLM hash thay password. Đặc trưng: EventID 4624, LogonType 3, package **NTLM** (thay vì Kerberos như logon domain thường), **subject** = machine account hoặc empty.

**(b) Template**:
```xml
<rule id="100106" level="14">
  <if_sid>60000</if_sid>
  <field name="win.system.eventID">^4624$</field>
  <field name="win.eventdata.logonType">^3$</field>
  <field name="win.eventdata.authenticationPackageName">^NTLM$</field>
  <field name="win.eventdata.logonProcessName" type="pcre2">^(NtLmSsp|User32|Kerberos)$</field>
  <field name="win.eventdata.targetUserName" negate="yes" type="pcre2">^(ANONYMOUS LOGON|.*\$)$</field>
  <description>T1550.002 - Possible Pass-the-Hash: user $(win.eventdata.targetUserName) via NTLM network logon</description>
  <mitre>
    <id>T1550.002</id>
  </mitre>
  <group>defense_evasion,lateral_movement,</group>
</rule>
```

**Tune**: match `<if_matched_sid>100103</if_matched_sid>` + frequency ≥ 5 lần / 5 phút để giảm noise nếu môi trường có multi-hop trust.

**(c) Test**: dùng `impacket-psexec` từ Kali (nếu setup được) — legit Windows use ít khi trigger.

---

### 3.8. Rule 100107 — T1562.001: Disable Defender / Security Tool

**(a)**: Attacker chạy `Set-MpPreference -DisableRealtimeMonitoring $true` hoặc `sc.exe stop WinDefend` để tắt AV.

**(b) Template (Sysmon EID 1)**:
```xml
<rule id="100107" level="14">
  <if_sid>61603</if_sid>
  <field name="win.eventdata.commandLine" type="pcre2">
    (?i)(Set-MpPreference\s.*Disable|sc(\.exe)?\s+(stop|delete)\s+(WinDefend|Sense|MpsSvc)|Uninstall-WindowsFeature\s+Windows-Defender)
  </field>
  <description>T1562.001 - Attempt to disable defense: $(win.eventdata.commandLine)</description>
  <mitre>
    <id>T1562.001</id>
  </mitre>
  <group>defense_evasion,</group>
</rule>
```

**Test**:
```powershell
# ⚠ chỉ chạy trên lab VM, không production
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableRealtimeMonitoring $false   # bật lại
```

---

### 3.9. Rule 100108 — T1547.001: Registry Run Key persistence

**(a)**: Ghi vào `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` hoặc `HKCU\...\Run` = program chạy tự động khi user login. Sysmon EventID **13** (RegistryEvent SetValue).

**(b) Template**:
```xml
<rule id="100108" level="12">
  <if_sid>61614</if_sid>                              <!-- 61614 = Sysmon Event 13 parent -->
  <field name="win.eventdata.targetObject" type="pcre2">
    (?i)\\CurrentVersion\\(Run|RunOnce|RunServices|RunServicesOnce|Explorer\\Run)\\
  </field>
  <description>T1547.001 - Autorun key modified: $(win.eventdata.targetObject) = $(win.eventdata.details)</description>
  <mitre>
    <id>T1547.001</id>
  </mitre>
  <group>persistence,</group>
</rule>
```

**Test**:
```powershell
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v BTLab /t REG_SZ /d "cmd.exe" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v BTLab /f
```

---

### 3.10. Rule 100109 — T1074.001: Local Data Staging

**(a)**: Attacker gom file lại trước exfil → tạo archive (`.zip`, `.rar`, `.tar.gz`) ở `%TEMP%` hoặc `/tmp`.

**Windows part** (Sysmon EID 11 FileCreate):
```xml
<rule id="100109" level="10">
  <if_sid>61613</if_sid>                              <!-- 61613 = Sysmon Event 11 parent -->
  <field name="win.eventdata.targetFilename" type="pcre2">
    (?i)\\(Temp|Windows\\Temp|AppData\\Local\\Temp)\\.+\.(zip|rar|7z|tar|gz)$
  </field>
  <description>T1074.001 - Archive created in Temp: $(win.eventdata.targetFilename)</description>
  <mitre>
    <id>T1074.001</id>
  </mitre>
  <group>collection,</group>
</rule>
```

**Linux part** (auditd execve `tar`/`zip` với target trong `/tmp`):
```xml
<rule id="100119" level="10">
  <if_sid>80700</if_sid>
  <field name="audit.key">^execve$</field>
  <field name="audit.exe" type="pcre2">/(tar|zip|gzip|7z)$</field>
  <field name="audit.a2" type="pcre2">/tmp/</field>
  <description>T1074.001 - Local staging: $(audit.exe) → /tmp</description>
  <mitre>
    <id>T1074.001</id>
  </mitre>
  <group>collection,</group>
</rule>
```

**Test**:
```powershell
Compress-Archive -Path C:\Windows\System32\drivers\etc\hosts -DestinationPath "$env:TEMP\loot.zip"
Remove-Item "$env:TEMP\loot.zip"
```
```bash
tar -czf /tmp/loot.tar.gz /etc/passwd
rm /tmp/loot.tar.gz
```

---

## 4. Deploy quy trình đầy đủ

### 4.1. Trên VPS

```bash
# Backup rule file
sudo cp /var/ossec/etc/rules/local_rules.xml /var/ossec/etc/rules/local_rules.xml.bak.$(date +%s)

# Edit (dùng nano/vim)
sudo nano /var/ossec/etc/rules/local_rules.xml

# → paste 10 rule (theo template ở section 3), save

# Kiểm tra XML syntax + rule load
sudo /var/ossec/bin/wazuh-analysisd -t
# → "OK" hoặc báo line lỗi

# Restart manager
sudo systemctl restart wazuh-manager
sudo systemctl is-active wazuh-manager   # → active
```

### 4.2. Verify rule đã load

```bash
# Trong wazuh-logtest, khi khởi động sẽ in số rule loaded
sudo /var/ossec/bin/wazuh-logtest
# → "wazuh-analysisd: INFO: Total rules enabled: 4000+"
# Xong Ctrl-D thoát
```

Hoặc query API:
```bash
curl -sk -u "wazuh:$WAZUH_API_PASS" \
  "https://localhost:55000/rules?rule_ids=100100,100101,100102,100103,100104,100105,100106,100107,100108,100109&pretty"
```

Kỳ vọng trả về 10 rule.

### 4.3. Test end-to-end mỗi rule

Xem bảng dưới. Với mỗi rule → chạy command test → chờ 15-30s → query Dashboard:

```bash
# Trên Kali/VPS
curl -sk -u "admin:$WAZUH_DASHBOARD_PASS" \
  -X POST "https://localhost:9200/wazuh-alerts-*/_search" \
  -H 'Content-Type: application/json' \
  -d '{"size":3,"sort":[{"@timestamp":"desc"}],"query":{"match":{"rule.id":"100101"}}}'
```

Đổi `rule.id` sang từng ID 100100–100109 để verify.

### 4.4. Commit rule vào repo

Sync file rule lên repo để version control:

```bash
# Trên VPS
sudo cat /var/ossec/etc/rules/local_rules.xml | tee /tmp/local_rules.xml > /dev/null

# Từ Kali
scp namth@43.228.215.234:/tmp/local_rules.xml wazuh-rules/local_rules.xml
git add wazuh-rules/local_rules.xml
git commit -m "phase4: add 10 custom detection rules mapped MITRE ATT&CK"
git push
```

---

## 5. Documenting mỗi rule (yêu cầu CV)

CV nêu: *"documented each rule's logic, data source, and false-positive profile"*. Tạo file `wazuh-rules/RULES.md`:

```markdown
# Custom Rules — Rule Catalog

## Rule 100101 — T1059.001 PowerShell Suspicious Cmdline

**Data source**: Sysmon EventID 1 (Process Create)

**Detection logic**:
Match khi `image` chứa `powershell.exe` hoặc `pwsh.exe` VÀ `commandLine`
chứa 1 trong các flag suspicious (`-EncodedCommand`, `-nop`, `-w hidden`,
`-ExecutionPolicy Bypass`, `iex(`).

**Level**: 12 (Critical)

**False positive profile**:
- Script deploy hợp lệ dùng `-nop` (nên whitelist theo `parentImage` = Ansible/SCCM).
- MSP tool: N-Able RMM dùng encoded command → whitelist `parentImage`.
- Log rotation script của Windows update: dùng `-w hidden` → whitelist theo `user` = SYSTEM.

**Suggested response**:
1. Isolate host qua Wazuh active-response
2. Grab commandLine đầy đủ, decode base64 nếu có `-e`
3. Query VirusTotal cho hash của parent process

**Test playbook**: `atomic/T1059.001.md`
```

Làm tương tự cho 10 rule.

---

## 6. Troubleshooting

| Triệu chứng | Nguyên nhân | Fix |
|---|---|---|
| Rule không match dù event có | Sai regex hoặc thiếu `type="pcre2"` | Test bằng `wazuh-logtest`, so field JSON |
| `wazuh-analysisd -t` báo "Invalid rule" | Sai XML (missing closing tag) | Đọc line number báo lỗi |
| Rule load OK nhưng alert không lên Dashboard | Level 0-2 = silent | Tăng level ≥3 |
| Alert đúng nhưng MITRE tag không hiện | Thiếu `<mitre><id>...</id></mitre>` | Thêm block |
| Rule bắt quá nhiều false positive | Regex quá lỏng | Thêm `<field negate="yes">`, hoặc `<if_sid>` cha strict hơn |
| Duplicate rule ID | Manager log warning, rule sau bị bỏ | Đổi ID |

---

## 7. Recap workflow cho Phase 4

```
1. Sinh event mẫu trên endpoint (nếu chưa có)
2. Query indexer → lấy raw JSON, xác định field
3. Viết rule XML → local_rules.xml
4. wazuh-logtest → paste raw log → xác minh match
5. systemctl restart wazuh-manager
6. Reproduce event → verify Dashboard
7. Tune false positive
8. Document RULES.md (logic, data source, FP profile)
9. Commit rule XML + RULES.md vào repo
```

Sau Phase 4, mỗi Sysmon/auditd event khớp technique MITRE sẽ tạo alert **có tag MITRE**, level đúng mức, mô tả chi tiết. Đây là **giá trị chính** của CV project — chuyển raw telemetry thành detection actionable.

---

## 8. Ghi log

Sau khi hoàn thành:

```
## 2026-XX-XX HH:MM | human | vps | phase4
- what: added 10 custom rules (100100-100109) to /var/ossec/etc/rules/local_rules.xml, restarted manager
- result: ok — 10 rule load thành công (wazuh-logtest xác nhận); test signal đủ 10 technique đã trigger alert đúng ID
- next: Phase 5 — Python IOC enrichment tool
```

Và commit `wazuh-rules/local_rules.xml` + `wazuh-rules/RULES.md` vào repo.
