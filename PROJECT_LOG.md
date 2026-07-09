# PROJECT_LOG

> **Mục đích**: shared context giữa Claude (chạy trên Kali host, control center) và Gemini Agent (chạy trên Windows/Linux VM endpoint). Mỗi khi có action đáng kể (deploy, thay đổi config, fix lỗi, hoàn thành phase), **ghi lại 1 entry** ở cuối file này.
>
> **Format entry**:
> ```
> ## YYYY-MM-DD HH:MM | <actor> | <host> | <phase>
> - what: <hành động cụ thể>
> - result: <ok / fail + chi tiết>
> - next: <bước kế tiếp>
> ```
>
> `<actor>` = `claude` | `gemini` | `human`
> `<host>` = `kali` | `vps` | `win-ep` | `linux-ep`

---

## Trạng thái hiện tại

| Phase | Mô tả                              | Trạng thái |
|-------|------------------------------------|------------|
| 1     | Wazuh AIO trên VPS                 | TODO       |
| 2     | Ubuntu endpoint + auditd           | TODO       |
| 3     | Windows endpoint + Sysmon          | TODO       |
| 4     | 10 detection rules MITRE ATT&CK    | TODO       |
| 5     | Python enrichment (VT + AbuseIPDB) | TODO       |
| 6     | Atomic Red Team hunting reports    | TODO       |

## Thông tin hạ tầng

- **VPS**: Ubuntu 22.04, ≥4GB RAM, 2 vCPU, 50GB — IP: `TODO`, SSH user: `TODO`
- **Windows endpoint**: VMware, Win 10/11 — hostname: `TODO`, IP LAN: `TODO`
- **Linux endpoint**: VMware, Ubuntu 22.04 — hostname: `TODO`, IP LAN: `TODO`
- **Kali host**: repo tại `/home/kali/blue-team-lab`

## Convention

- Docs trong `docs/` **luôn có cả GUI + CLI equivalent** cho mỗi bước.
- Secrets (API keys, agent enrollment key) **không commit**; dùng `.env` (đã có trong `.gitignore`).
- Rule ID cho Wazuh custom: dùng dải `100100-100199` để tránh xung đột.

---

## Log entries

## 2026-07-09 | claude | kali | scaffold
- what: init repo, tạo cấu trúc thư mục, README, PROJECT_LOG, .gitignore
- result: ok
- next: Phase 1 — deploy Wazuh AIO trên VPS (docs/01-wazuh-server-setup.md)
