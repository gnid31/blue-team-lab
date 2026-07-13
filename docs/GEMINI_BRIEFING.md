# Briefing cho Gemini Agent (chạy trên VM Windows / Linux endpoint)

> **Đọc file này TRƯỚC KHI làm bất cứ thao tác nào trong repo.**

---

## 1. Bối cảnh

Bạn (Gemini Agent) đang cộng tác với **Claude Code (Anthropic)** — Claude chạy trên máy **Kali** làm control center, bạn chạy trên máy endpoint (Windows hoặc Linux VM). Cả hai cùng triển khai dự án **Blue Team Threat Hunting Lab** dựa trên CV của user Trần Công Định (sinh viên Học viện KTMM Hà Nội).

Người dùng (human) là **cầu nối** giữa Claude và Gemini — họ điều phối, các bạn không nói chuyện trực tiếp mà **chia sẻ trạng thái qua file `PROJECT_LOG.md` trong repo Git**:
- Repo GitHub: https://github.com/gnid31/blue-team-lab
- Local mount (Kali): `/home/kali/blue-team-lab/`
- Local mount (endpoint VM): user sẽ `git clone` về, hoặc bạn tự pull nếu có credential.

## 2. Vai trò phân chia

| Vai trò | Ai | Làm gì |
|---|---|---|
| **Control / architecture** | Claude (Kali) | Viết docs, thiết kế rules, code enrichment tool, verify từ Manager |
| **Endpoint operator** | Gemini (Win/Linux VM) | Thực hiện lệnh **trong VM**: install agent, config Sysmon/auditd, chạy Atomic Red Team, sinh telemetry |
| **Orchestrator** | Human | Chuyển context giữa 2 bên, quyết định deploy step |

## 3. Nguyên tắc cộng tác

1. **Đọc `PROJECT_LOG.md` đầu tiên** — luôn nắm trạng thái hiện tại trước khi làm.
2. **Sau MỖI action đáng kể** (install, config, restart service, chạy test), **append 1 entry** vào cuối `PROJECT_LOG.md` theo format:
   ```
   ## YYYY-MM-DD HH:MM | gemini | <host> | <phase>
   - what: <hành động cụ thể>
   - result: <ok / fail + chi tiết>
   - next: <bước kế tiếp>
   ```
   `<host>` = `win-ep` cho VM Windows, `linux-ep` cho VM Linux.
3. **Commit + push** log entry ngay sau khi ghi (`git add PROJECT_LOG.md && git commit -m "log: <host> <what>" && git push`), để Claude bên Kali `git pull` là thấy.
4. **Nếu Sysmon config, ossec.conf, rules XML thay đổi** — commit cả file đó vào repo (trừ secrets/cert).
5. **KHÔNG commit**: password, API key, agent enrollment key, cert `.pem`, `.env`, file có pattern `*.local`. Xem `.gitignore`.
6. **Docs philosophy**: mỗi step trong docs phải có cả **GUI + CLI equivalent** (đây là preference cứng của user). Nếu bạn thêm hướng dẫn mới vào docs, tuân thủ.
7. **Style docs**: viết cho người mới hoàn toàn, giải thích ý nghĩa từng flag/option, tránh giả định kiến thức. Xem `docs/02-linux-endpoint.md` làm mẫu.
8. **Trước khi chạy lệnh có tính phá hoại** (uninstall, format, rm -rf, disable service quan trọng, đóng port đang dùng), **hỏi human xác nhận trước**.

## 4. Kiến trúc hạ tầng

```
VPS 43.228.215.234 (Ubuntu 24.04)
├── Wazuh Manager 4.9.2  (port 1514, 1515)
├── Wazuh Indexer         (port 9200, localhost)
├── Wazuh Dashboard       (port 443, https://43.228.215.234)
└── Filebeat 7.10.2       (Manager→Indexer bridge)

VMware trên Kali:
├── linux-ep-01  (Ubuntu 22.04, 192.168.154.166) — agent 001, auditd
└── win-ep-01    (Windows 10/11)                 — agent 002, Sysmon
```

**Credentials Dashboard/API**: user giữ trong `.secrets.local` (không trong repo). Nếu cần, hỏi user.

## 5. Roadmap 6 phase

Đang ở đâu, xem bảng đầu `PROJECT_LOG.md`. Trạng thái tính đến khi tài liệu này viết:

| Phase | Status |
|---|---|
| 1. Wazuh AIO trên VPS | DONE |
| 2. Ubuntu endpoint + auditd | DONE |
| 3. Windows endpoint + Sysmon | **IN PROGRESS** (agent enrolled, Sysmon installed — cần config `ossec.conf` đọc Sysmon channel) |
| 4. 10 detection rules MITRE ATT&CK | TODO |
| 5. Python IOC enrichment (VT + AbuseIPDB) | TODO |
| 6. Atomic Red Team hunting reports | TODO |

## 6. Convention kỹ thuật

- **Custom Wazuh rule ID**: dải `100100 – 100199`
- **Wazuh version pin**: 4.9.2 — không mix major
- **Sysmon config**: bản SwiftOnSecurity fork (community standard), có thể tune sau
- **Rule XML** đặt tại `wazuh-rules/`, sync lên Manager `/var/ossec/etc/rules/local_rules.xml`
- **Test signal**: dùng **Atomic Red Team** (framework mimic technique MITRE, chạy được từ PowerShell)

## 7. Escalate khi nào?

- **Không hiểu ý task** → hỏi user, đừng tự đoán
- **Command lỗi liên tục** → paste full output cho user, đợi Claude phân tích
- **Cần thay đổi kiến trúc** (mở port mới, đổi rule ID range, đổi tool) → cần đồng thuận Claude + user

---

## 8. Task hiện tại của Gemini (Windows)

**Mục tiêu**: cấu hình `wazuh-agent` trên Windows đọc Sysmon channel → Manager thấy Event Sysmon từ `win-ep-01`.

**Prereq đã có** (verified from Manager side):
- Agent 002 `win-ep-01` **Active** trên Manager
- User confirm: **Sysmon đã cài xong**
- Wazuh agent đường dẫn mặc định: `C:\Program Files (x86)\ossec-agent\`

### Bước 1: verify Sysmon đang chạy + có channel

Mở **PowerShell as Administrator**:

```powershell
# Verify Sysmon service
Get-Service -Name "Sysmon*" | Format-Table -AutoSize

# Verify Sysmon event channel có event
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 3 |
  Select-Object TimeCreated, Id, LevelDisplayName, ProviderName
```

Ghi lại output (đặc biệt tên service — có thể là `Sysmon` hoặc `Sysmon64`) vào log entry.

### Bước 2: backup ossec.conf trước khi sửa

```powershell
$conf = "C:\Program Files (x86)\ossec-agent\ossec.conf"
Copy-Item $conf "$conf.bak.$(Get-Date -Format 'yyyyMMddHHmmss')"
```

### Bước 3: chèn `<localfile>` block cho Sysmon channel

Mở `ossec.conf` bằng Notepad với quyền Admin:

```powershell
notepad "C:\Program Files (x86)\ossec-agent\ossec.conf"
```

Tìm tag đóng cuối `</ossec_config>` và **thêm block sau ngay trước nó**:

```xml
<!-- Sysmon operational channel for MITRE-mapped detections -->
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

**Ý nghĩa từng element**:
- `<location>` — tên **Windows Event Channel** (không phải file). Wazuh subscribe qua Windows Event Log API.
- `<log_format>eventchannel</log_format>` — format bắt buộc cho Windows Event Log. Format này khiến Manager dùng decoder chuẩn parse XML event của Windows thành `data.win.eventdata.*`.

Lưu file và đóng Notepad.

### Bước 4: kiểm tra XML hợp lệ + restart service

```powershell
# Verify config (nếu sai XML, service sẽ fail start)
& "C:\Program Files (x86)\ossec-agent\wazuh-agent.exe" -t

# Restart service
Restart-Service WazuhSvc

# Verify service active
Get-Service WazuhSvc
```

### Bước 5: tail agent log để xem đang subscribe channel

```powershell
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 30 |
  Select-String -Pattern "Sysmon|eventchannel|error" -CaseSensitive:$false
```

Kỳ vọng thấy dòng đại loại:
```
INFO: Reading Windows event channel 'Microsoft-Windows-Sysmon/Operational'.
```

### Bước 6: sinh test event

```powershell
# Trigger Sysmon Event ID 1 (Process Create)
notepad.exe
Start-Sleep 2
Stop-Process -Name notepad -ErrorAction SilentlyContinue
```

### Bước 7: ghi PROJECT_LOG + commit

```powershell
cd <đường dẫn repo clone trên VM>
git pull
# edit PROJECT_LOG.md, append entry
git add PROJECT_LOG.md
git commit -m "log: win-ep sysmon channel enabled in wazuh-agent"
git push
```

Ví dụ entry:
```
## 2026-07-09 XX:XX | gemini | win-ep | phase3
- what: added <localfile> Microsoft-Windows-Sysmon/Operational block to ossec.conf, restarted WazuhSvc
- result: ok — service active, ossec.log confirms "Reading Windows event channel 'Microsoft-Windows-Sysmon/Operational'"
- next: Claude verify trên Manager rằng alert win-ep-01 có field data.win từ Sysmon
```

Sau khi Gemini push xong, **báo user** để Claude bên Kali verify từ phía Manager (query indexer).

---

## 9. Sau khi task này xong, đợi

Claude bên Kali sẽ:
1. `git pull` xem log entry
2. Query indexer verify alert Sysmon từ win-ep-01
3. Bắt đầu Phase 4 (viết detection rules) — sẽ đẩy rule XML vào repo, Gemini có thể được nhờ apply lên Manager hoặc test Atomic Red Team ở Phase 6.
