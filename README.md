# Blue Team Threat Hunting Lab with Python IOC Enrichment

Home lab triển khai **Wazuh 4.9 HIDS** giám sát Windows + Linux endpoint, kèm **10 detection rules** mapped MITRE ATT&CK và **Python enrichment tool** tự động truy vấn VirusTotal / AbuseIPDB.

## Kiến trúc

```
                     ┌────────────────────────────┐
                     │   VPS (Ubuntu 22.04)       │
                     │   Wazuh Manager + Indexer  │
                     │   + Dashboard (AIO)        │
                     │   :1514 (agents)  :443 UI  │
                     └──────────────┬─────────────┘
                                    │  agent enrollment
              ┌─────────────────────┼─────────────────────┐
              │                     │                     │
    ┌─────────▼─────────┐ ┌─────────▼─────────┐ ┌─────────▼─────────┐
    │ Windows 10/11 VM  │ │ Ubuntu 22.04 VM   │ │  Kali host        │
    │ (VMware)          │ │ (VMware)          │ │  - Enrichment CLI │
    │ Sysmon + WazuhAgt │ │ auditd + WazuhAgt │ │  - Repo control   │
    └───────────────────┘ └───────────────────┘ └───────────────────┘
```

## Cấu trúc repo

| Thư mục            | Nội dung                                                       |
|--------------------|----------------------------------------------------------------|
| `docs/`            | Hướng dẫn từng phase (GUI + CLI)                               |
| `wazuh-rules/`     | 10 custom detection rules XML mapped MITRE ATT&CK              |
| `sysmon/`          | Sysmon config (SwiftOnSecurity fork, đã tune)                  |
| `auditd/`          | Linux auditd rule set                                          |
| `enrichment/`      | Python tool: đọc alert → truy vấn VT/AbuseIPDB → ghi verdict   |
| `hunting-reports/` | Báo cáo hunting per-session (Atomic Red Team)                  |
| `atomic/`          | Test plans / playbooks Atomic Red Team                         |
| `PROJECT_LOG.md`   | **Shared log** cho Claude (Kali) + Gemini Agent (Win/Linux VM) |

## Phase roadmap

1. **Phase 1** — Deploy Wazuh AIO trên VPS
2. **Phase 2** — Enroll Ubuntu endpoint + auditd
3. **Phase 3** — Enroll Windows endpoint + Sysmon
4. **Phase 4** — Author 10 detection rules (MITRE ATT&CK)
5. **Phase 5** — Python IOC enrichment tool (VirusTotal + AbuseIPDB)
6. **Phase 6** — Atomic Red Team hunting sessions + reports

Xem `PROJECT_LOG.md` để biết trạng thái hiện tại.
