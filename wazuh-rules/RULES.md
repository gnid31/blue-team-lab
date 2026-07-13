# Custom Rules — Rule Catalog

10 detection rules mapped MITRE ATT&CK, deployed tại `/var/ossec/etc/rules/local_rules.xml` trên Wazuh Manager. Dải ID `100100–100199`.

Mỗi rule dưới đây có: **logic**, **data source**, **level**, **false-positive profile**, **suggested response**, **test playbook**.

---

## Rule 100100 — T1003.008 Read of `/etc/shadow`

- **Data source**: auditd, key `credential_read`
- **Prereq**: audit rule `-w /etc/shadow -p rwa -k credential_read` (đã có trong `auditd/wazuh-audit.rules`)
- **Level**: 12 (critical)
- **Parent SID**: 80700

**Logic**:
Bất cứ syscall (`openat`, `read`) nào chạm `/etc/shadow` đều bắn audit event với `key=credential_read`. Rule match key này.

**False-positive profile**:
- User root chạy `passwd`, `chpasswd`, `useradd`, `usermod` — hợp lệ nhưng vẫn trigger. Whitelist theo `audit.exe`:
  ```xml
  <field name="audit.exe" negate="yes" type="pcre2">/(passwd|chpasswd|useradd|usermod|newusers)$</field>
  ```
- Backup tool (`rsync`, `tar`) khi backup toàn hệ thống. Whitelist theo `audit.auid` = uid của service account backup.
- PAM authenticator daemon (rare). Kiểm tra `audit.exe` = `/usr/sbin/sshd`, `/usr/bin/su`.

**Suggested response**:
1. Isolate host qua Wazuh active-response (network drop)
2. Query enrichment tool (Phase 5) — xem process `audit.exe` có hash malware trên VirusTotal
3. Kiểm tra `bash_history` của user với `audit.auid` trong 1h trước
4. Snapshot `/etc/shadow` để so sánh nếu bị copy đi

**Test playbook**:
```bash
sudo cat /etc/shadow > /dev/null
# Alert lên trong 15-30s
```

---

## Rule 100101 — T1059.001 Suspicious PowerShell cmdline

- **Data source**: Sysmon EventID 1 (Process Create), `image = powershell.exe / pwsh.exe`
- **Level**: 12 (critical)
- **Parent SID**: 61603

**Logic**:
Match nếu `commandLine` chứa 1 trong các flag/pattern đặc trưng malware:
- `-EncodedCommand` / `-enc` — base64-encoded payload
- `-w hidden` — hidden window (thường loader)
- `-nop` — no profile (skip AppLocker)
- `-ExecutionPolicy Bypass` — override ExecutionPolicy
- `iex(` — Invoke-Expression eval
- `DownloadString(` — pull remote script
- `FromBase64String(` — inline decode

**False-positive profile**:
- **Claude Desktop / Anthropic tools** — dùng `-Command "[System.Net.WebRequest]::..."`. Regex hiện tại **KHÔNG match** vì thiếu suspicious flag (đã kiểm chứng — rule 92029 built-in match, custom 100101 không match).
- Deploy tool (**Ansible**, **SCCM**, **N-Able RMM**) hay dùng `-nop -EncodedCommand`. Whitelist theo `parentImage`:
  ```xml
  <field name="win.eventdata.parentImage" negate="yes" type="pcre2">(?i)\\(ansible|sccm|n-able|nagios)\\</field>
  ```
- **Chocolatey / winget installers** — có thể dùng `-ExecutionPolicy Bypass`. Whitelist bằng `parentImage`.
- Windows Update script chính chủ (SYSTEM). Whitelist theo `user = SYSTEM` + `parentImage` chính xác.

**Suggested response**:
1. Grab full `commandLine`. Nếu chứa `-e`/`-enc`: `[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("$b64"))` để decode.
2. Query VirusTotal hash của parent process (Phase 5 enrichment).
3. Kill process, isolate host.
4. Yara scan `%TEMP%`, `%APPDATA%` tìm dropped file.

**Test playbook**:
```powershell
# Trên VM Windows
powershell.exe -nop -w hidden -Command "Write-Host BLUE_LAB_TEST"
```

---

## Rule 100102 — T1543.003 New Windows Service

- **Data source**: Windows Security EventID 4697
- **Level**: 10 (high)
- **Parent SID**: 60103
- **Sub-rule 100112** (level 14): escalate nếu service binary là **LOLBIN** (powershell/cmd/wscript/rundll32/regsvr32/certutil/bitsadmin)

**Logic**:
EventID 4697 = "A service was installed in the system". Trigger cho mọi service mới. Sub-rule chọn ra service có binary suspicious.

**False-positive profile**:
- Cài phần mềm hợp lệ (Chrome update, Adobe Reader, VS Code) — trigger 100102. Whitelist theo `serviceFileName` = path known publisher:
  ```xml
  <field name="win.eventdata.serviceFileName" negate="yes" type="pcre2">(?i)\\(Program Files|Program Files \(x86\))\\(Google|Adobe|Microsoft VS Code|...)\\</field>
  ```
- Windows Update tự cài service. `subjectUserName = SYSTEM` + `serviceFileName` trong `C:\Windows\System32\` = thường hợp lệ. Suppress bằng level 3.

**Suggested response**:
1. Kiểm tra `serviceFileName` — path lạ (`%TEMP%`, `C:\Users\Public\`, `%APPDATA%`) = suspicious cao.
2. `sc.exe qc <serviceName>` — xem full config service.
3. Hash binary, query VT.
4. Nếu 100112 trigger (LOLBIN): treat as confirmed persistence attempt — isolate ngay.

**Test playbook**:
```powershell
# Trigger 100102 (benign)
sc.exe create BTLabTest binPath= "C:\Windows\System32\notepad.exe" start= demand
sc.exe delete BTLabTest

# Trigger 100112 (LOLBIN escalation)
sc.exe create BTLabEvil binPath= "cmd.exe /c echo evil" start= auto
sc.exe delete BTLabEvil
```

---

## Rule 100103 — T1021.002 SMB Lateral Movement

- **Data source**: Windows Security EventID 4624, LogonType 3, source IP RFC1918
- **Level**: 8 (medium)
- **Parent SID**: 60106

**Logic**:
Network logon (LogonType=3) từ IP nội bộ (10/8, 172.16/12, 192.168/16), loại trừ service account (`SYSTEM`, `NETWORK SERVICE`, computer account `.*$`).

**False-positive profile**:
- **File share access hợp lệ** — nhân viên mount `\\server\share`. Rất khó phân biệt với PsExec chỉ qua Event 4624 lẻ tẻ. Cần correlation.
- **Domain replication** — DC replicate lẫn nhau. Whitelist theo `targetUserName = <domain>\<host>$`.
- **Monitoring tool** (Nagios NSCP, Zabbix agent) dùng account cụ thể. Whitelist theo `targetUserName`.
- **Backup** (Veeam, Acronis) mount share nightly. Whitelist theo IP source hoặc user.

Tune bằng correlation:
```xml
<rule id="100113" level="12" frequency="5" timeframe="600">
  <if_matched_sid>100103</if_matched_sid>
  <same_source_ip/>
  <description>T1021.002 - 5+ SMB logons from same IP in 10 min (potential PsExec/lateral tool)</description>
</rule>
```

**Suggested response**:
1. Query alerts từ cùng `ipAddress` trong 1h — nếu ≥5 host bị login = lateral movement chắc chắn.
2. `net view \\<source_ip>` để xem attacker cũng đang share gì.
3. Grab `authenticationPackageName` — nếu NTLM (không phải Kerberos) → dấu hiệu PtH (rule 100106).
4. Isolate cả source lẫn target.

**Test playbook**:
```powershell
# Từ máy khác trong LAN VMware
net use \\192.168.154.166\c$ /user:ADMIN <password>
net use \\192.168.154.166\c$ /delete
```

---

## Rule 100104 — T1053.005 Scheduled Task Created

- **Data source**: Windows Security EventID 4698
- **Level**: 10 (high)
- **Parent SID**: 60103

**Logic**:
EventID 4698 bắn khi task được tạo qua `schtasks.exe`, `Register-ScheduledTask`, Task Scheduler UI, hoặc API COM.

**False-positive profile**:
- **Windows Update** tạo task rất thường xuyên. Whitelist:
  ```xml
  <field name="win.eventdata.subjectUserName" negate="yes">^SYSTEM$</field>
  <field name="win.eventdata.taskName" negate="yes" type="pcre2">^\\Microsoft\\Windows\\</field>
  ```
- Office add-in, backup tool, driver updater — tạo task ở path riêng. Baseline 24h → whitelist path phổ biến.

**Suggested response**:
1. Xem `taskContent` (XML) — lấy `command`/`arguments`. Path lạ = suspicious.
2. Kiểm tra `trigger` — task chạy lúc nào? At logon / boot = persistence classic.
3. `schtasks /tn <name> /query /v /fo LIST` — full detail.
4. Nếu binary trong Temp/AppData: treat as malware.

**Test playbook**:
```powershell
schtasks /create /tn "BTLab_Test" /tr "cmd.exe /c echo test" /sc onlogon
schtasks /delete /tn "BTLab_Test" /f
```

---

## Rule 100105 — T1087.001 Account Discovery (Windows)

- **Data source**: Sysmon EventID 1, `image = net.exe / net1.exe / whoami.exe / quser.exe / nltest.exe`
- **Level**: 5 (notice)
- **Parent SID**: 61603

**Logic**:
Bắt process discovery với cmdline chứa `user` / `localgroup` / `group` / `/domain` / `/all` / `dclist`.

**False-positive profile**:
- Admin/helpdesk chạy `whoami /all` khi troubleshoot — rất thường. Level thấp (5) chủ yếu để build baseline, không alert lớn.
- Login script `net use` (mount drive) sẽ **không match** vì cmdline không chứa keyword `user|group`.
- **PowerShell profile** một số phiên bản gọi `whoami /groups` — whitelist theo `parentImage = powershell.exe` + `user = SYSTEM`.

**Suggested response**:
1. Không isolate ngay — chờ correlation với rule khác (100106, 100107) trong 30 min.
2. Nếu cùng `user` chạy nhiều rule discovery + persistence → escalate.
3. Baseline: user hay chạy discovery command này? Nếu không → suspicious.

**Test playbook**:
```powershell
whoami /all
net user
net localgroup administrators
```

---

## Rule 100106 — T1550.002 Pass-the-Hash indicator

- **Data source**: Windows Security EventID 4624, LogonType 3, `authenticationPackageName = NTLM`, `logonProcessName = NtLmSsp|User32`
- **Level**: 14 (critical, near-max)
- **Parent SID**: 60106

**Logic**:
Heuristic đơn giản: network logon (type 3) mà auth package là **NTLM** (không phải Kerberos như domain login thường), process là `NtLmSsp`. Loại trừ service account.

**False-positive profile**:
- **Workgroup / non-domain** environment: mọi SMB login đều NTLM. Rule sẽ noisy — chỉ dùng nếu môi trường có AD.
- **Linux client (Samba)** kết nối Windows share: có thể là NTLM. Whitelist theo `workstationName` known.
- **Legacy app** hardcode NTLM (RPC, DCOM cũ). Baseline + whitelist.
- **Cross-forest trust** (khi Kerberos fallback về NTLM) — rare, treat như case-by-case.

**Suggested response**:
1. So sánh `targetUserName` với `subjectUserName` — nếu account người dùng đăng nhập từ máy khác = suspicious.
2. Grab `ipAddress` + `workstationName`, xem host đó có gì bất thường (Rule 100101, 100107 gần đây?).
3. Force reset password của `targetUserName`, revoke Kerberos ticket.
4. Full memory dump máy source (nghi LSASS đã bị dump) → sang T1003.001.

**Test playbook**:
```
# Cần AD/domain lab để test đúng — không đơn giản
# Sử dụng impacket-psexec / crackmapexec từ Kali:
crackmapexec smb 192.168.154.166 -u ADMIN -H <NTLM_HASH>
```

---

## Rule 100107 — T1562.001 Disable Defender / AV

- **Data source**: Sysmon EventID 1, `commandLine` chứa Set-MpPreference disable / sc stop WinDefend / netsh firewall off / Uninstall-WindowsFeature Windows-Defender
- **Level**: 14 (critical)
- **Parent SID**: 61603

**Logic**:
Match cmdline patterns:
- `Set-MpPreference ... Disable*` / `-DisableRealtimeMonitoring`
- `sc.exe stop|delete|config WinDefend|Sense|MpsSvc|WdNisSvc`
- `Uninstall-WindowsFeature Windows-Defender`
- `Add-MpPreference -ExclusionPath` (add exclusion để bypass)
- `netsh advfirewall set ... state off`

**False-positive profile**:
- **IT script disable Defender khi cài phần mềm nặng** (SQL Server, Visual Studio) — hợp lệ nhưng vẫn phải audit. Nên vẫn giữ level 14 và whitelist theo `parentImage = <known deploy tool>`.
- Backup script `sc stop MpsSvc` trước snapshot (rare).
- Analyst chạy `Add-MpPreference -ExclusionPath` để test → kiểm chứng bằng user context.

**Suggested response**:
1. Confirm ngay `Get-MpPreference | fl` xem thực sự đã disable không.
2. Nếu đã disable: **re-enable** bằng `Set-MpPreference -DisableRealtimeMonitoring $false`.
3. Nếu là user không được quyền tắt AV → treat as compromised, isolate.
4. Query Defender history: `Get-MpThreatDetection`.

**Test playbook**:
```powershell
# ⚠ chỉ trong lab
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableRealtimeMonitoring $false
```

---

## Rule 100108 — T1547.001 Registry Run Key persistence

- **Data source**: Sysmon EventID 13 (RegistryEvent SetValue)
- **Level**: 12 (critical)
- **Parent SID**: 61615

**Logic**:
`targetObject` chứa 1 trong các autostart key:
- `\CurrentVersion\Run`
- `\CurrentVersion\RunOnce`
- `\CurrentVersion\RunServices`
- `\CurrentVersion\Winlogon\Shell` / `Userinit`
- HKLM và HKCU đều bắt

**False-positive profile**:
- **Ứng dụng chính chủ đặt autorun**: OneDrive, Dropbox, Skype, Discord — write vào `HKCU\...\Run`. Rất thường. Whitelist:
  ```xml
  <field name="win.eventdata.image" negate="yes" type="pcre2">(?i)\\(OneDrive|Dropbox|Discord|Slack|Skype|Zoom|Steam)\.exe$</field>
  ```
- **Installer** khi cài phần mềm mới. Whitelist theo `image = msiexec.exe`.
- **Windows Update** thi thoảng update RunOnce. Whitelist `image` trong `C:\Windows\System32\`.

**Suggested response**:
1. Xem `details` (value) — path binary autorun.
2. Nếu path là `%TEMP%`, `%APPDATA%\Roaming`, `C:\Users\Public` = suspicious cao.
3. Hash binary → VT (Phase 5).
4. `reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"` để xem full state.

**Test playbook**:
```powershell
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v BTLab /t REG_SZ /d "cmd.exe" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v BTLab /f
```

---

## Rule 100109 — T1074.001 Local Data Staging (Windows)

- **Data source**: Sysmon EventID 11 (FileCreate)
- **Level**: 10 (high)
- **Parent SID**: 61613
- **Path pattern**: file tạo trong `Temp` / `Windows\Temp` / `AppData\Local\Temp` / `ProgramData`, extension `.zip .rar .7z .tar .gz .cab .arj`

**Logic**:
Attacker gom loot vào archive trong staging directory trước khi exfil.

**False-positive profile**:
- **Update installer**: MSI/EXE unpack tạm vào Temp. Whitelist theo `image = msiexec.exe / setup.exe` trong Program Files.
- **Chocolatey / winget**: tải archive vào Temp. Whitelist `image`.
- **User manually zip file** — hiếm nhưng có. Whitelist theo `image = explorer.exe / 7zg.exe / winrar.exe`.
- **Google Chrome / Firefox download**: nếu file `.zip` được browser save vào Downloads (không phải Temp) → không match. OK.

**Suggested response**:
1. Kiểm tra `image` — tool tạo archive. `powershell.exe`, `cmd.exe`, `certutil.exe` → suspicious.
2. Ước lượng size archive: `Get-Item <path> | Select Length`. > 100MB = ưu tiên investigate.
3. So sánh timestamp với alert 100105 (discovery) — nếu discovery + staging cùng 1 user trong 1h → attack chain.
4. Grab archive để triage forensic.

**Test playbook**:
```powershell
Compress-Archive -Path C:\Windows\System32\drivers\etc\hosts -DestinationPath "$env:TEMP\btlab_loot.zip"
Remove-Item "$env:TEMP\btlab_loot.zip"
```

---

## Rule phụ (sub-rules)

| ID | Description | Trigger sau rule |
|---|---|---|
| **100112** | LOLBIN as service binary — escalate 100102 level 14 | 100102 |
| **100115** | Linux account discovery (auditd) — pair với 100105 | — |
| **100119** | Linux data staging (auditd tar/zip /tmp) — pair với 100109 | — |

---

## Tổng kết mapping MITRE

| Rule | MITRE | Tactic | Level |
|------|-------|--------|-------|
| 100100 | T1003.008 | Credential Access | 12 |
| 100101 | T1059.001 | Execution | 12 |
| 100102 | T1543.003 | Persistence | 10 |
| 100112 | T1543.003 | Persistence + Defense Evasion | 14 |
| 100103 | T1021.002 | Lateral Movement | 8 |
| 100104 | T1053.005 | Persistence | 10 |
| 100105 | T1087.001 | Discovery | 5 |
| 100115 | T1087.001 | Discovery | 5 |
| 100106 | T1550.002 | Defense Evasion + Lateral | 14 |
| 100107 | T1562.001 | Defense Evasion | 14 |
| 100108 | T1547.001 | Persistence | 12 |
| 100109 | T1074.001 | Collection | 10 |
| 100119 | T1074.001 | Collection | 10 |

Cover **6 tactic** trên **10 technique unique** — đúng như CV commit.
