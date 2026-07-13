# Phase 6 Summary — 10 MITRE Technique Hunting Sessions

Blue Team Lab — Trần Công Định — 2026-07-13

---

## Overview

9 hunting sessions covering **10 MITRE ATT&CK techniques** (session 07 combined T1021.002 + T1550.002). All reports NIST SP 800-61r2 aligned.

**Environment**:
- Wazuh Manager 4.9.2 (VPS 43.228.215.234) with 4480 built-in rules + 13 custom (100100-100120 range).
- Windows endpoint `win-ep-01` (Sysmon SwiftOnSecurity config + Wazuh agent).
- Linux endpoint `linux-ep-01` (auditd 26 rules + Wazuh agent).
- Automation: Claude executed via SSH from Kali — no manual relay needed after Session 01 setup.

---

## Coverage Matrix

| # | Session | Technique | Rule ID | Level | Result | TTD |
|---|---|---|---|---|---|---|
| 01 | T1059.001 | PowerShell (EncodedCommand, w hidden) | 100101 | 12 | ✅ 2 alerts | ~30s |
| 02 | T1547.001 | Registry Run Key | 100108 | 12 | ✅ 1 alert | ~1s |
| 03 | T1053.005 | Scheduled Task | 100104 | 10 | ✅ 1 alert | ~1s |
| 04 | T1087.001 | Account Discovery (Win + Linux) | 100105 + 100115 | 5 | ✅ 10 alerts (5 Win + 5 Linux) | ~0.2–1s |
| 05 | T1003.008 | /etc/shadow read | 100100 + 100120 | 12 → 14 | ✅ 1 alert (sau FP fix) | ~1s |
| 06 | T1543.003 | Windows Service Create | 100102 + 100112 | 10 → 14 | ✅ 2 alerts | ~1s |
| 07 | T1021.002 + T1550.002 | SMB Lateral + Pass-the-Hash | 100103 + 100106 | 14 | ✅ 1 alert | ~2s |
| 08 | T1562.001 | Disable Defender | 100107 | 14 | ✅ 3 alerts | ~1s |
| 09 | T1074.001 | Data Staging (Win + Linux) | 100109 + 100119 | 10 | ❌ **Miss — sensor gap** | N/A |

**Detection rate**: 9/10 techniques detected = **90%**.

---

## Key Findings

### 1. Rule Chain Pattern for Sysmon events

Standard `<if_sid>61603</if_sid>` (Sysmon EID 1 parent) rules **do NOT fire** reliably. Bug encountered on rules 100101, 100105, 100107, 100108, 100109.

**Fix** (documented in `docs/04-detection-rules.md §9 Appendix`):

| Data source | Recommended approach |
|---|---|
| Sysmon EID N | Chain from **specific built-in rule that already fires** (`<if_sid>92XXX</if_sid>`), OR `<if_group>sysmon_event_N</if_group>` with rich field constraints (originalFileName ưu tiên hơn image path) |
| Windows Security 4XXX | `<if_sid>60103</if_sid>` + `<field win.system.eventID>^4XXX$</field>` — hoạt động ngay lần đầu |
| Linux auditd | `<if_sid>80700</if_sid>` + field constraint (`audit.key`, `audit.exe`) — hoạt động ngay lần đầu |

### 2. Prerequisites often missed

- Windows Security **EID 4697** (service create): requires `auditpol /set /subcategory:"Security System Extension" /success:enable`
- Windows Security **EID 4698** (scheduled task): requires `auditpol /set /subcategory:"Other Object Access Events" /success:enable`
- Both audit subcategories default OFF trên Windows fresh install → sensor gap không được note trong doc mặc định.

### 3. False Positive Reality — T1003.008 case study

Session 05: rule 100100 (read `/etc/shadow`) initial version fired **8 alerts for 1 attack** — 87.5% FP.

Root cause: system components read shadow legitimately:
- `sshd` (auth flow, 3x)
- `systemd` (session init, 2x)
- `sudo` (password validation, 2x)
- `cat` (the actual attacker action, 1x)

**Fix**: negative field regex whitelisting system readers + sub-rule 100120 escalate attacker tools (cat, less, dd, xxd, ...) to level 14. Result: **100% precision** on retest.

Đây là **case study rule tuning** đầy đủ nhất trong Phase 6.

### 4. Detection Gap — T1074.001 Staging

Session 09: attack executed successfully (both Windows Compress-Archive + Linux tar), **no detection**. Root cause = **sensor tuning**, not rule logic:

- SwiftOnSecurity Sysmon config filters aggressively — `.zip` in Temp not in include list
- Linux auditd tar produces high event volume → potential Wazuh agent buffer overflow

**Lesson**: **Sensor + rule are coupled**. Custom rule không đủ nếu sensor không capture event. Cần fork Sysmon config hoặc dùng compensating control (Wazuh FIM).

### 5. Cross-Platform Detection Works

Session 04 chứng minh Windows + Linux rules cùng technique (T1087.001) fire đúng cùng lúc. Base cho MITRE ATT&CK coverage report per-OS.

---

## MITRE ATT&CK Coverage

**Tactic coverage** (from 10 techniques implemented):

| Tactic | Technique covered |
|---|---|
| **Initial Access** | (none — out of scope) |
| **Execution** | T1059.001, T1053.005 |
| **Persistence** | T1547.001, T1543.003, T1053.005 |
| **Privilege Escalation** | T1053.005 (multi-tactic) |
| **Defense Evasion** | T1562.001, T1543.003 (LOLBIN sub), T1550.002 |
| **Credential Access** | T1003.008 |
| **Discovery** | T1087.001 |
| **Lateral Movement** | T1021.002, T1550.002 |
| **Collection** | T1074.001 (miss) |
| **Command and Control** | (none) |
| **Exfiltration** | (none — chain sau collection) |

**Not covered** (limits của scope): TA0001 Initial Access, TA0011 C2, TA0010 Exfiltration.

---

## Detection Improvements Recommended

Based on the 9 hunt sessions, prioritized backlog:

### Priority 1 — Critical (implement trong sprint tiếp)

1. **Fork Sysmon config** để cover archive extensions in Temp (fix session 09 gap)
2. **Enable Wazuh FIM** trên `/tmp/*.zip`, `/tmp/*.tar.gz`, `%TEMP%\*.zip` (compensating control)
3. **Refine rule 100107** (T1562.001) — regex hiện match cả re-enable command. Tune để chỉ match disable action.
4. **Sub-rule 100108 extension** — chain thêm cho PowerShell/regedit (không chỉ reg.exe)

### Priority 2 — Important

5. Correlation rule: 5+ discovery commands / 5 min (session 04 recommendation)
6. Correlation rule: 5+ SMB logons same IP / 10 min (lateral movement chain)
7. Rule 4699 (service deleted within 60s of create) — attacker cleanup signal
8. Rule for EID 4104 (PowerShell ScriptBlock logging) — deeper visibility than EID 1 cmdline

### Priority 3 — Enhancement

9. Auto-enrichment writeback for ALL alert level ≥10 (currently manual `enrich.py --writeback`)
10. Custom OpenSearch dashboard visualizing MITRE technique coverage over time
11. Auto-generation of hunting report skeleton từ alert (template + auto-fill fields)

---

## Automation Achievements

- **SSH from Kali → Windows** via `labuser` + ed25519 key. Session 01 required manual Gemini bootstrap; Sessions 02-09 fully autonomous.
- **SSH tunnel** Kali:9200 → VPS Indexer — enrichment tool + hunt queries đều local.
- **enrich.py --writeback** flag: verdict persistent trong `enrichment-verdicts-YYYY.MM.DD` index → analyst xem Dashboard cùng chỗ với alert.

---

## Lessons Learned (Master List)

1. **"Chain from working built-in"** rule pattern giải quyết 90% Sysmon rule failure — thay vì viết rule từ scratch.
2. **Behavior detection > IOC detection** cho hầu hết TT&PP hiện đại. Session 01 confirmed: powershell.exe hash luôn "clean" trên VT.
3. **Sensor tuning là part of detection engineering** — không phải "config once and forget".
4. **False positive analysis với real data** hiệu quả hơn regex tinh chỉnh trước. Session 05 là ví dụ.
5. **Windows Security event chain đơn giản hơn Sysmon chain** rất nhiều — ưu tiên khi có thể chọn (VD dùng 4697 thay Sysmon EID 12 cho service create).
6. **Cross-platform detection cần cross-platform testing** — session 04 chạy Win + Linux đồng thời trong 3s.
7. **Correlation rules > threshold rules** cho low-level alert (level 5). Discovery + persistence + defense evasion combined = attack chain confirmed.

---

## Final Repo Structure (post-Phase 6)

```
blue-team-lab/
├── README.md                            # tổng quan
├── PROJECT_LOG.md                       # shared log Claude + Gemini + human
├── docs/
│   ├── 00-architecture.md
│   ├── 01-wazuh-server-setup.md         # Phase 1
│   ├── 02-linux-endpoint.md             # Phase 2
│   ├── 03-windows-endpoint.md           # Phase 3
│   ├── 04-detection-rules.md            # Phase 4 (779 dòng) + §9 rule debugging appendix
│   ├── 05-enrichment-tool.md            # Phase 5
│   ├── 05b-enrichment-writeback.md      # Phase 5b (Option A)
│   ├── 06-atomic-red-team.md            # Phase 6
│   ├── GEMINI_BRIEFING.md               # cross-agent
│   └── GEMINI_BRIEFING_PHASE6.md
├── wazuh-rules/
│   ├── local_rules.xml                  # 15 custom rules
│   └── RULES.md                         # catalog + FP profile per rule
├── auditd/
│   └── wazuh-audit.rules                # 27 audit rules
├── enrichment/                          # Python IOC enrichment CLI
│   ├── enrich.py
│   ├── providers.py, cache.py, ioc.py, wazuh_client.py
│   ├── README.md
│   └── requirements.txt
├── atomic/                              # 5 atomic test plans
│   ├── T1059.001-powershell.md
│   ├── T1547.001-run-key.md
│   ├── T1053.005-scheduled-task.md
│   ├── T1087.001-account-discovery.md
│   └── T1003.008-shadow-read.md
└── hunting-reports/                     # 9 sessions + summary
    ├── TEMPLATE.md                      # NIST 800-61r2 template
    ├── SUMMARY.md                       # this file
    ├── session-01-T1059.001.md
    ├── session-02-T1547.001.md
    ├── session-03-T1053.005.md
    ├── session-04-T1087.001.md
    ├── session-05-T1003.008.md
    ├── session-06-T1543.003.md
    ├── session-07-T1021.002-T1550.002.md
    ├── session-08-T1562.001.md
    └── session-09-T1074.001.md
```

---

## Deliverables per CV

CV commit: *"Ran threat hunting sessions using Atomic Red Team as a signal source, reconstructed each attack timeline end-to-end from raw telemetry, and produced a structured hunting report per session (hunting query, findings, IOC list, MITRE mapping, remediation)."*

✅ **Delivered**:
- **9 sessions covering 10 techniques** (T1003.008, T1021.002, T1053.005, T1059.001, T1074.001, T1087.001, T1543.003, T1547.001, T1550.002, T1562.001)
- **Every report follows NIST SP 800-61r2** — includes all 5 CV-required items (hunt query, findings, IOC list, MITRE mapping, remediation) + additional 5 industry-standard sections
- **Timeline reconstruction end-to-end** in section 5 of every report
- **Real signals from Atomic-inspired triggers** (not fabricated data)

Phase 6 = **DONE**.

---

## Contact & Continued Work

- GitHub: https://github.com/gnid31/blue-team-lab
- Project owner: nam@cycloneinstruments.ai (Trần Công Định)
- Continued work sau interview/deployment:
  - Fork Sysmon config
  - Wazuh 5.0 upgrade evaluation
  - MITRE ATT&CK Navigator export
  - Extend enrichment CLI: URL, email IOC
