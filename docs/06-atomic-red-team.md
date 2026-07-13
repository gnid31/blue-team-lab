# Phase 6 — Atomic Red Team hunting sessions

> Doc chi tiết cho người **chưa từng chạy attack simulation**. Đọc từ đầu, không skip.

---

## 0. Kiến thức nền

### 0.1. Atomic Red Team là gì?

**Atomic Red Team** (viết tắt ART) là bộ khung open-source của **Red Canary** để **giả lập từng technique MITRE ATT&CK** theo đơn vị nhỏ nhất gọi là "atomic test".

Mỗi atomic test là **1 command / script** mô phỏng đúng hành vi của attacker cho 1 technique cụ thể. Ví dụ:

| Technique | Atomic test | Command mô phỏng |
|---|---|---|
| T1059.001 | `powershell -EncodedCommand ...` | Chạy PowerShell với base64 payload |
| T1547.001 | `reg add HKCU\...\Run` | Ghi autorun registry key |
| T1053.005 | `schtasks /create` | Tạo scheduled task |
| T1003.008 | `cat /etc/shadow` | Read shadow file |

**Không phải malware thật** — chỉ command chạy trong 1s rồi cleanup, mục đích là **sinh telemetry giống hệt attacker** để test detection.

### 0.2. Vì sao dùng ART trong Blue Team lab?

- Cần **input** để verify rule detect đúng. Không có ART thì phải chờ attack thật (không xảy ra).
- ART có **~1000+ atomic test** cover ~300 technique MITRE — nguồn signal dồi dào.
- Command chuẩn, có thể reproduce → so sánh detection between iteration.
- Có sẵn **cleanup** — không để lại rác trên host.

### 0.3. Invoke-AtomicRedTeam (PowerShell)

**Framework runner** trên Windows. Cài qua PowerShell 1 lệnh:
```powershell
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force
```

Sau khi cài xong:
```powershell
Import-Module Invoke-AtomicRedTeam
Invoke-AtomicTest T1059.001 -ShowDetails    # xem test có gì
Invoke-AtomicTest T1059.001 -TestNumbers 1   # chạy test số 1
Invoke-AtomicTest T1059.001 -TestNumbers 1 -Cleanup   # cleanup
```

### 0.4. Trên Linux

ART cũng chạy được trên Linux/macOS, nhưng runner khác (không phải PowerShell). Cách phổ biến:
- Clone repo `atomic-red-team` từ GitHub
- Đọc file `Txxxx.md` trong `atomics/Txxxx/` → chép command bash chạy tay
- Hoặc dùng `atomic_runner.py` (Python) không chính thức

Trong lab này Linux chỉ có 1-2 test → chép command tay đơn giản hơn.

### 0.5. Threat Hunting là gì?

**Hunt** = chủ động tìm dấu vết attacker trong log, **không đợi alert bắn**. Khác với **detection** (rule tự bắn) như sau:

| Detection (rule) | Hunt |
|---|---|
| Reactive — đợi rule match | Proactive — analyst đặt giả thuyết, query log |
| Tự động 24/7 | Manual, ad-hoc |
| Bỏ sót nếu rule thiếu | Phát hiện gap của rule |

**Workflow hunt**:
1. **Hypothesis** — "Nếu có attacker chạy PowerShell suspicious, log sẽ thấy `image=powershell.exe` + `commandLine` chứa `-EncodedCommand`"
2. **Query** — chạy DSL query trên Indexer
3. **Findings** — kết quả gì, có match hypothesis không?
4. **Reconstruct timeline** — dựng lại chuỗi event: parent process, child process, network, file created, registry
5. **IOC list** — extract hash/IP/domain từ event
6. **MITRE mapping** — technique nào, tactic gì
7. **Remediation** — nếu là thật, làm gì?

Phase 6 chạy **ART làm signal**, sau đó thực hành hunt như trên (dù biết trước sẽ tìm thấy).

## 1. Chọn 5 session cho lab

Chọn technique trải rộng tactic + có endpoint:

| # | Technique | Rule | Endpoint | Data source |
|---|---|---|---|---|
| **1** | T1059.001 — PowerShell Encoded | 100101 | win-ep-01 | Sysmon EID 1 |
| **2** | T1547.001 — Registry Run Key | 100108 | win-ep-01 | Sysmon EID 13 |
| **3** | T1053.005 — Scheduled Task | 100104 | win-ep-01 | Windows Security 4698 |
| **4** | T1087.001 — Account Discovery | 100105/100115 | cả 2 | Sysmon EID 1 + auditd execve |
| **5** | T1003.008 — /etc/shadow read | 100100 | linux-ep-01 | auditd |

## 2. Cài Invoke-AtomicRedTeam trên win-ep-01

**PowerShell as Administrator**:

```powershell
# 1. Bypass ExecutionPolicy cho session này
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

# 2. Add Defender exclusion cho ART folder (bắt buộc — nếu không Defender sẽ xoá script test)
Add-MpPreference -ExclusionPath "C:\AtomicRedTeam\"

# 3. Cài
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force

# 4. Verify
Import-Module Invoke-AtomicRedTeam
Get-Command -Module Invoke-AtomicRedTeam
Invoke-AtomicTest T1059.001 -ShowDetails | Select-Object -First 30
```

Sau bước này, `C:\AtomicRedTeam\atomics\` chứa toàn bộ test.

> **Cảnh báo Defender**: một số ART test bị Defender quarantine trước khi chạy. Exclusion path ở trên giải quyết. Sau khi lab xong nên **remove exclusion**:
> ```powershell
> Remove-MpPreference -ExclusionPath "C:\AtomicRedTeam\"
> ```

## 3. Cấu trúc `atomic/` và `hunting-reports/` trong repo

```
atomic/                          # test plan — command chạy
├── T1059.001-powershell.md
├── T1547.001-run-key.md
├── T1053.005-scheduled-task.md
├── T1087.001-account-discovery.md
└── T1003.008-shadow-read.md

hunting-reports/                 # kết quả sau khi hunt
├── TEMPLATE.md                  # template
├── session-01-T1059.001.md      # 1 report / session
├── session-02-T1547.001.md
├── session-03-T1053.005.md
├── session-04-T1087.001.md
└── session-05-T1003.008.md
```

Test plan (atomic/) — **input**, làm sẵn trước.
Hunting report (hunting-reports/) — **output**, viết sau khi chạy + hunt.

## 4. Workflow 1 session

```
┌──────────────────────────────────────────────────────────────────┐
│  1. Đọc atomic/Txxxx.md — nắm chính xác command sẽ chạy          │
│  2. Ghi timestamp bắt đầu (UTC)                                   │
│  3. Chạy Invoke-AtomicTest Txxxx -TestNumbers <N>                 │
│  4. Ghi timestamp kết thúc                                        │
│  5. Chờ 30s cho pipeline: Sysmon → agent → Manager → Indexer     │
│  6. Query Wazuh Indexer / Dashboard theo hypothesis               │
│  7. Kiểm tra custom rule (100xxx) có fire không                  │
│  8. Reconstruct timeline từ raw Sysmon/audit event               │
│  9. Extract IOC → chạy enrich.py                                  │
│  10. Điền hunting-reports/session-NN-Txxxx.md                     │
│  11. Cleanup: Invoke-AtomicTest Txxxx -Cleanup                    │
│  12. Commit + push report vào repo                                │
└──────────────────────────────────────────────────────────────────┘
```

## 5. Template hunting report

Xem `hunting-reports/TEMPLATE.md`. Cấu trúc bắt buộc:

- **Metadata**: session#, ngày, technique, endpoint
- **Attack summary**: command đã chạy, timestamp start/end
- **Hypothesis**: analyst đặt gì trước khi query
- **Hunt query**: DSL / Dashboard filter
- **Findings**: bao nhiêu event, rule ID nào bắn, level, description
- **Timeline** (chronological): T0 → T+Ns event nào
- **IOC list**: hash/IP/domain extract được
- **Enrichment**: verdict VT/AbuseIPDB
- **MITRE mapping**: tactic + technique + sub
- **Detection assessment**: rule custom đủ chưa? gap? FP?
- **Remediation**: nếu là thật, cần làm gì
- **Screenshots**: từ Dashboard (optional)

## 6. Hunt queries mẫu

### DSL trên OpenSearch (dùng cho `curl` hoặc `enrich.py`)

```json
POST /wazuh-alerts-*/_search
{
  "size": 20,
  "query": {"bool": {"must": [
    {"match": {"agent.name": "win-ep-01"}},
    {"match": {"rule.id": "100101"}},
    {"range": {"@timestamp": {"gte": "now-30m"}}}
  ]}}
}
```

### Dashboard Discover — filter syntax (KQL)

```
agent.name : "win-ep-01" AND rule.id : "100101" AND @timestamp >= "now-30m"
```

Kết hợp query:
```
rule.mitre.id : "T1059.001" AND agent.name : "win-ep-01"
```

### Hunt để timeline reconstruction

Sau khi thấy 1 alert, chuyển sang xem **mọi event** từ agent quanh timestamp đó:

```
agent.name : "win-ep-01" AND @timestamp >= "2026-07-13T10:15:00Z" AND @timestamp <= "2026-07-13T10:16:00Z"
```

Xem process tree: `data.win.eventdata.parentImage`, `data.win.eventdata.image`.

## 7. Cleanup sau lab

Sau khi 5 session xong:

```powershell
# Trên Windows
Invoke-AtomicTest T1059.001 -Cleanup
Invoke-AtomicTest T1547.001 -Cleanup
Invoke-AtomicTest T1053.005 -Cleanup
Invoke-AtomicTest T1087.001 -Cleanup

# Remove Defender exclusion
Remove-MpPreference -ExclusionPath "C:\AtomicRedTeam\"

# (optional) uninstall ART
Remove-Item -Recurse -Force C:\AtomicRedTeam
```

```bash
# Trên Linux — ART Linux chạy tay nên không cần cleanup framework
# Chỉ cleanup file test tạo (VD /tmp/staging.tar.gz nếu test T1074)
```

## 8. Ghi log

Sau mỗi session, thêm entry vào `PROJECT_LOG.md`:

```
## 2026-XX-XX HH:MM | human | win-ep | phase6-session-01
- what: Invoke-AtomicTest T1059.001 -TestNumbers 1 (PowerShell -EncodedCommand)
- result: rule 100101 fired lvl12; timeline reconstructed; report ở hunting-reports/session-01-T1059.001.md
- next: session-02 T1547.001
```

## 9. Đánh giá cuối Phase 6

Sau 5 session, viết `hunting-reports/SUMMARY.md`:

- Tỷ lệ detect: X/5 technique bắt được bằng custom rule
- Rule cần tune (false positive nhiều): liệt kê
- Rule missing: technique nào không có rule detect
- MITRE coverage matrix: technique nào cover, technique nào chưa

Đây là **deliverable cuối** của dự án — showcase cho phỏng vấn.
