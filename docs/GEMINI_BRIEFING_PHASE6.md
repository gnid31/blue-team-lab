# Gemini Briefing — Phase 6 (Atomic Red Team on Windows)

> Đọc `docs/GEMINI_BRIEFING.md` trước để nắm bối cảnh dự án.

---

## Nhiệm vụ Phase 6

Chạy **4 atomic test** trên `win-ep-01` để sinh telemetry giả lập attack; Claude sẽ hunt trên Wazuh + viết hunting report.

Techniques cần chạy (theo thứ tự):

| Session | Technique | Test plan | Rule mong bắn |
|---|---|---|---|
| 1 | T1059.001 PowerShell EncodedCommand | `atomic/T1059.001-powershell.md` | 100101 |
| 2 | T1547.001 Registry Run Key | `atomic/T1547.001-run-key.md` | 100108 |
| 3 | T1053.005 Scheduled Task | `atomic/T1053.005-scheduled-task.md` | 100104 |
| 4 | T1087.001 Account Discovery | `atomic/T1087.001-account-discovery.md` | 100105 |

Session 5 (T1003.008 shadow read) chạy trên Linux, không thuộc Gemini scope.

---

## Bước 0 — Bootstrap 1 lần duy nhất

Nếu chưa cài **Invoke-AtomicRedTeam** trên win-ep-01:

**PowerShell as Administrator**:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
Add-MpPreference -ExclusionPath "C:\AtomicRedTeam\"
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force
Import-Module Invoke-AtomicRedTeam
Get-Command -Module Invoke-AtomicRedTeam | Select-Object -First 5
```

Verify:
```powershell
Invoke-AtomicTest T1059.001 -ShowDetails | Select-Object -First 20
# → in ra danh sách atomic test cho T1059.001
```

Append log:
```
## YYYY-MM-DD HH:MM | gemini | win-ep | phase6-setup
- what: installed Invoke-AtomicRedTeam framework + atomics repo
- result: ok — module loaded, T1059.001 -ShowDetails OK
- next: chờ Claude signal chạy session 1
```

Commit + push PROJECT_LOG.md.

---

## Bước 1 — Chạy 1 session (VD Session 1 T1059.001)

**Trước khi chạy**: paste đúng nội dung `atomic/T1059.001-powershell.md` (đọc trên repo). Ghi lại chính xác timestamp UTC bắt đầu:

```powershell
# Ghi timestamp
$start = [DateTime]::UtcNow
Write-Host "Start: $($start.ToString('o'))"

# Chạy test
Import-Module Invoke-AtomicRedTeam
Invoke-AtomicTest T1059.001 -TestNumbers 1

# Ghi timestamp kết thúc
$end = [DateTime]::UtcNow
Write-Host "End: $($end.ToString('o'))"
```

**Sau khi chạy**: chờ 30s cho pipeline agent → Manager → Indexer.

Sau đó cleanup:
```powershell
Invoke-AtomicTest T1059.001 -TestNumbers 1 -Cleanup
```

---

## Bước 2 — Log

Append entry vào `PROJECT_LOG.md`:
```
## YYYY-MM-DD HH:MM | gemini | win-ep | phase6-session-01
- what: Invoke-AtomicTest T1059.001 -TestNumbers 1 (PowerShell -EncodedCommand)
- start: 2026-07-13T10:15:23Z
- end:   2026-07-13T10:15:24Z
- result: test ran successfully, cleanup ok
- next: Claude hunt on Wazuh side + write session-01 report
```

Commit + push. **Đợi Claude phản hồi** trước khi chạy session tiếp theo.

---

## Bước 3 — Chạy session tiếp theo

Chỉ chạy khi Claude confirm session trước OK. Lặp lại bước 1-2 cho session 2, 3, 4.

---

## Quy tắc

1. **Không tự chạy nhiều session liên tiếp không đợi Claude** — Claude cần hunt + verify từng cái. Nếu chạy dồn, timeline lẫn khó reconstruct.
2. **Luôn ghi timestamp UTC** — không phải local time. Wazuh index dùng UTC.
3. **Không skip cleanup** — nếu Run key hoặc Scheduled task còn tồn tại, sẽ ảnh hưởng test sau + có thể trigger rule 100112 (LOLBIN service) nếu để lâu.
4. **Nếu test fail** (VD Defender block, ExecutionPolicy sai) — paste output cho user, đừng tự retry mù.
5. **Không cài extra tool** ngoài Invoke-AtomicRedTeam. Không tự thêm Sysmon rule, không disable Defender vĩnh viễn.

---

## Sau khi 4 session xong

```powershell
# Optional — remove Defender exclusion
Remove-MpPreference -ExclusionPath "C:\AtomicRedTeam\"

# Verify không còn task/regkey persistence
schtasks /query /fo LIST | Select-String "Atomic"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" | Select-String "Atomic"
# Cả 2 phải trả về rỗng
```

Ghi entry cuối cùng:
```
## YYYY-MM-DD HH:MM | gemini | win-ep | phase6-complete
- what: 4 session Windows đã chạy + cleanup + verify no leftover
- result: ok — chuyển control lại Claude để tổng hợp
- next: Phase 6 complete từ phía Windows
```
