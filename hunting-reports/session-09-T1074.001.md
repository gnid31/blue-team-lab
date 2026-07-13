# Incident Report — BTL-2026-009

*NIST SP 800-61r2 aligned. Session #9 — T1074.001 Local Data Staging.*
*⚠ **Detection coverage gap identified** — session này là case study cho sensor tuning necessity.*

## 1. Incident Identification

| Field | Value |
|---|---|
| **Report ID** | BTL-2026-009 |
| **Detection timestamp (UTC)** | N/A (rule 100109 và 100119 KHÔNG fire dù attack đã thực hiện) |
| **Analyst** | Claude |
| **Status** | **Investigation — Detection Gap Documented** |
| **Confidence** | **Low** (không có detection signal, xác định qua compensating controls) |

## 2. Categorization

| Field | Value |
|---|---|
| **Attack vector** | External (SSH) |
| **NIST category** | Malicious Code — pre-exfiltration |
| **MITRE tactic** | **Collection** (TA0009) |
| **MITRE technique** | **T1074.001 — Local Data Staging** |
| **Reference** | https://attack.mitre.org/techniques/T1074/001/ |

## 3. Prioritization

Không applicable — detection miss.

## 4. Detection & Analysis

### Attack thực hiện

**Windows** (via SSH labuser):
```powershell
Compress-Archive -Path C:\Windows\System32\drivers\etc\hosts -DestinationPath $env:TEMP\btlab_loot.zip -Force
```

**Linux** (via SSH gnid):
```bash
tar -czf /tmp/btlab_loot.tar.gz /etc/passwd
```

### Detection result — **MISS**

| Rule | Expected | Actual | Root cause |
|---|---|---|---|
| 100109 (Win, Sysmon EID 11 FileCreate) | Fire on `.zip` in Temp | **0 alerts** | SwiftOnSecurity Sysmon config filter mạnh — không log FileCreate cho `.zip` in Temp path |
| 100119 (Linux, auditd execve tar/zip/gzip) | Fire on tar → /tmp | **0 alerts** | Audit event có nhưng chưa reach indexer, hoặc rule regex miss |

### Root cause 1 — Sysmon config filter

SwiftOnSecurity config (community standard) mặc định log **CHỈ** các FileCreate patterns thuộc "suspicious extension" list. `.zip`, `.tar`, `.gz` **không có** trong danh sách default để giảm noise.

**Verify**: query all Sysmon EID 11 trong window → 7 events, tất cả là `__PSScriptPolicyTest_*` (PowerShell temporary policy check) — không có `btlab_loot.zip`.

**Fix**: extend Sysmon config để log FileCreate cho archive extensions:
```xml
<RuleGroup name="" groupRelation="or">
  <FileCreate onmatch="include">
    <Rule name="ArchiveInTemp" groupRelation="or">
      <TargetFilename condition="contains">\Temp\</TargetFilename>
      <TargetFilename condition="end with">.zip</TargetFilename>
      <TargetFilename condition="end with">.7z</TargetFilename>
      <TargetFilename condition="end with">.rar</TargetFilename>
    </Rule>
  </FileCreate>
</RuleGroup>
```

### Root cause 2 — Linux audit tar

`tar` khi chạy tạo hàng trăm audit events (mỗi file được archived = 1 open syscall). Wazuh agent message queue có thể **overflow** → drop events. Cần verify qua `/var/ossec/logs/ossec.log`.

**Alternative detection cho Linux**:
- File integrity monitoring (FIM) trên `/tmp/`, `/dev/shm/` với extension archive
- Rule dựa trên `data.audit.a2` (2nd argument của execve — path tar output)

## 5. Timeline

Attack thực hiện thành công, không detect. Attacker (giả định) có 1 window ~5s để exfiltrate archive trước khi cleanup.

## 6. Scope

- **Files created (Windows)**: `C:\Users\labuser\AppData\Local\Temp\btlab_loot.zip` — contains `hosts` file
- **Files created (Linux)**: `/tmp/btlab_loot.tar.gz` — contains `/etc/passwd`

## 7. Containment/Eradication

Không applicable trong session vì cleanup đã tự động thực hiện. **Nếu detection có**:
- Isolate host
- File deleted before exfil check (query outbound network trong 1 min sau file create)

## 8. Post-Incident — Lesson quan trọng

### Lessons learned

1. **Sensor tuning ≠ detection engineering**: rule Wazuh viết đúng, nhưng sensor (Sysmon config) không capture event → detection miss. Sensor + rule là **cặp**, không tách rời.

2. **SwiftOnSecurity Sysmon config quá aggressive filtering** cho lab thực dụng:
   - Ưu điểm: giảm noise 90%+ so với default
   - Nhược điểm: miss legitimate attacker patterns nếu extension không có trong include list
   - **Recommendation**: fork config và add archive extensions cho T1074 coverage

3. **Linux audit tar producing high volume**: cần tune Wazuh agent buffer hoặc dùng approach khác:
   - Option A: Wazuh FIM (`<syscheck>`) trên `/tmp/`, `/dev/shm/` với `check_all` — detect file created
   - Option B: eBPF-based sensor (Falco, Osquery) thay auditd cho technique này
   - Option C: Match file extension trong `data.audit.file.name` khi có `key=execve` — chưa test

4. **Detection gap phải được biết trước, không phải sau**: red team assessment quarterly bằng Atomic Red Team giúp phát hiện gap. Session này chính là simulation đó.

### Recommendations

- [ ] **Extend Sysmon config**: fork SwiftOnSecurity, add archive-in-Temp FileCreate rule
- [ ] **Enable Wazuh FIM** trên `/tmp/*.zip`, `/tmp/*.tar.gz`, `%TEMP%\*.zip`
- [ ] **Rule 100109 rework**: chain from Wazuh FIM rule instead of Sysmon EID 11
- [ ] **Test Linux audit buffer overflow**: `grep "message queue" /var/ossec/logs/ossec.log` — nếu overflow, tăng `<queue_size>`

## 9. Communications

Trong prod: gap này = detection engineer's TODO. Ưu tiên trong sprint tiếp theo.

## 10. References

- MITRE T1074.001: https://attack.mitre.org/techniques/T1074/001/
- SwiftOnSecurity Sysmon config: https://github.com/SwiftOnSecurity/sysmon-config
- Wazuh FIM docs: https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
- Rule: `wazuh-rules/local_rules.xml` — 100109, 100119
