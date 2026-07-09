# Phase 3 — Windows endpoint + Sysmon

**Mục tiêu**: cài Wazuh agent + Sysmon trên VM Win10/11 (VMware), verify Sysmon EventID vào SIEM.

**Prereq**: Phase 1 done. Wazuh Manager tại `43.228.215.234`.

---

## 1. Chuẩn bị VM Windows

- **OS**: Windows 10/11 Pro/Ent (Insider hoặc licensed ISO)
- **RAM**: ≥ 4GB, CPU 2 vCPU, Disk 60GB
- **Network**: NAT — cần ra Internet
- **Hostname**: `win-ep-01`

### GUI
Settings → System → About → Rename this PC → `win-ep-01` → reboot.

### CLI (PowerShell Admin)
```powershell
Rename-Computer -NewName "win-ep-01" -Restart
```

---

## 2. Cài Wazuh agent (Windows)

Lấy command từ Dashboard **Deploy new agent** (chọn Windows MSI). Ví dụ:

### CLI (PowerShell Admin trong VM)
```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.2-1.msi -OutFile "$env:tmp\wazuh-agent.msi"

msiexec.exe /i "$env:tmp\wazuh-agent.msi" /q `
  WAZUH_MANAGER='43.228.215.234' `
  WAZUH_AGENT_NAME='win-ep-01' `
  WAZUH_REGISTRATION_SERVER='43.228.215.234'

Start-Service WazuhSvc
Get-Service WazuhSvc
```

### GUI
1. Tải MSI từ https://packages.wazuh.com/4.x/windows/
2. Double-click, làm theo wizard
3. Ở tab **Manager IP**: nhập `43.228.215.234`, Agent name `win-ep-01`
4. Finish → Start service: `services.msc` → **Wazuh** → Start

---

## 3. Cài Sysmon

### CLI (PowerShell Admin)
```powershell
# Tải Sysmon từ Sysinternals
Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon.zip -OutFile "$env:tmp\Sysmon.zip"
Expand-Archive "$env:tmp\Sysmon.zip" -DestinationPath "C:\Sysmon" -Force

# Tải config SwiftOnSecurity (community standard)
Invoke-WebRequest -Uri https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml `
  -OutFile "C:\Sysmon\sysmonconfig.xml"

# Install với config
C:\Sysmon\Sysmon64.exe -accepteula -i C:\Sysmon\sysmonconfig.xml

# Verify
Get-Service Sysmon64
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 3
```

### GUI (Sysinternals Suite)
- Cần thao tác thủ công qua Explorer (download + extract + open CMD as admin) — chậm hơn CLI, không khuyến nghị.

---

## 4. Cấu hình Wazuh agent đọc Sysmon channel

Edit `C:\Program Files (x86)\ossec-agent\ossec.conf`, thêm trong `<ossec_config>`:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

### CLI (PowerShell Admin)
```powershell
Restart-Service WazuhSvc
```

### GUI
`services.msc` → **Wazuh** → Restart

---

## 5. Verify

### GUI (Dashboard trên Kali)
Wazuh menu → Agents → `win-ep-01` **Active**
Discover → filter `agent.name: win-ep-01 AND data.win.system.channel: "Microsoft-Windows-Sysmon/Operational"` → có event.

### Test event: chạy notepad
```powershell
notepad.exe
```
Sinh Sysmon Event ID 1 (Process Create) → hiển thị trong Discover trong 15–30s.

---

## Ghi log

```
## 2026-XX-XX HH:MM | human | win-ep | phase3
- what: enrolled win-ep-01, Sysmon installed with SwiftOnSecurity config, EventID 1 seen in SIEM
- result: ok
- next: Phase 4 — write 10 detection rules
```
