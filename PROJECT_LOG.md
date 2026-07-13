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
| 1     | Wazuh AIO trên VPS                 | **DONE**   |
| 2     | Ubuntu endpoint + auditd           | **DONE**   |
| 3     | Windows endpoint + Sysmon          | **DONE**   |
| 4     | 10 detection rules MITRE ATT&CK    | **DONE**   |
| 5     | Python enrichment (VT + AbuseIPDB) | **DONE**   |
| 6     | Atomic Red Team hunting reports    | IN PROGRESS |

## Thông tin hạ tầng

- **VPS**: Ubuntu **24.04**, 7.8GB RAM, 4 vCPU, 158GB — IP: `43.228.215.234`, SSH user: `namth`
  - Wazuh Dashboard: `https://43.228.215.234` (admin / password lưu tại `.secrets.local`)
  - Wazuh API: `https://43.228.215.234:55000` (user `wazuh`)
  - Ports: 443, 1514, 1515, 55000 (đã UFW allow)
  - **CẢNH BÁO**: đã `docker stop traefik` để nhường port 443. Restart policy `always` → nếu reboot VPS, traefik sẽ tự lên và cướp 443. Sau khi lab xong: `docker stop wazuh-*` và `docker start traefik` để khôi phục.
- **Windows endpoint**: VMware, Win 10/11 — hostname: `win-ep-01` (agent 002 Active), Sysmon (SwiftOnSecurity) reading, channel `Microsoft-Windows-Sysmon/Operational` piped vào Wazuh
- **Linux endpoint**: VMware, Ubuntu 22.04.5 — hostname: `linux-ep-01`, IP LAN: `192.168.154.166`, user: `gnid`, agent 4.9.2 active
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

## 2026-07-09 15:13 | claude | vps | phase1
- what: recon VPS (Ubuntu 24.04, 7.8G RAM, đã có Traefik + 6 Docker apps giữ 443/80/3000)
- result: phát hiện conflict → docker stop traefik (không rm), thêm UFW rules 1514/1515/55000
- next: chạy wazuh-install.sh

## 2026-07-09 16:15 | claude | linux-ep | phase2
- what: scp wazuh-audit.rules → /etc/audit/rules.d/wazuh.rules, augenrules --load
- result: ok — 26 rule active trong kernel (auditctl -l), audit.log ghi bình thường (3013 SYSCALL sau 5 phút)

## 2026-07-13 | claude | kali | phase5
- what: build enrichment/ Python CLI (enrich.py + wazuh_client.py + ioc.py + providers.py + cache.py), venv + rich/click/dotenv/requests, SSH tunnel Kali:9200 → VPS:9200 tự setup
- result: ok — test thực tế trên 3 alert SSH brute force (rule 2502) → 2 unique IP (62.60.130.219 Cipher Serbia, 45.148.10.141 Techoff) đều xác nhận MALICIOUS bởi cả VT (15+/91, 17+/91) và AbuseIPDB (100/100). Cache SQLite hoạt động.
- next: Phase 6 — Atomic Red Team hunting sessions

## 2026-07-13 XX:XX | claude | vps | phase4
- what: viết wazuh-rules/local_rules.xml (10 primary + 3 sub-rules = 13 rule XML, ID 100100–100119), scp lên VPS `/var/ossec/etc/rules/local_rules.xml`, restart wazuh-manager
- result: ok — analysisd -t exit 0, manager active, API xác nhận 13 rule loaded đúng ID/level/description. Chưa fire alert (chờ trigger).
- what2: viết wazuh-rules/RULES.md (rule catalog theo yêu cầu CV: logic, data source, level, false-positive profile, suggested response, test playbook cho từng rule)
- what3: update auditd/wazuh-audit.rules — đổi `-w /etc/shadow -p wa` thành `-w /etc/shadow -p rwa -k credential_read` để bắt read event (cần cho rule 100100). Cần reload trên linux-ep-01 khi VM lên lại (sudo augenrules --load).
- next: Phase 5 — Python IOC enrichment tool; user test trigger 10 rule bằng playbook trong RULES.md

## 2026-07-13 06:46 | gemini + claude | win-ep + vps | phase3
- what: Gemini thêm <localfile> Microsoft-Windows-Sysmon/Operational (log_format=eventchannel) vào ossec.conf trên win-ep-01, restart WazuhSvc
- result: ok — 97 alerts từ Sysmon channel đã vào indexer. Rule built-in match: 92213 lvl15 (executable dropped in temp), 92029 lvl6 (PowerShell suspicious location)
- next: Phase 4 — viết 10 custom rule mapping MITRE ATT&CK

## 2026-07-09 16:22 | claude | linux-ep | phase2
- what: chèn <localfile> audit block vào /var/ossec/etc/ossec.conf, restart wazuh-agent
- result: ok — logcollector đang tail /var/log/audit/audit.log; Manager nhận 310+ alert (level 3 "sudo to ROOT"). Custom rule sẽ có ở Phase 4.
- next: Phase 3 — Windows endpoint + Sysmon

## 2026-07-09 15:14–15:19 | claude | vps | phase1
- what: chạy `sudo bash wazuh-install.sh -a -i` (flag -i vì Ubuntu 24.04 ngoài support matrix chính thức)
- result: ok — 4 service active (wazuh-manager, wazuh-indexer, wazuh-dashboard, filebeat); Dashboard trả 302 tại :443; API :55000 auth ok (JWT)
- next: Phase 2 — enroll Ubuntu VMware endpoint

## 2026-07-13 13:45 | gemini | win-ep | phase3
- what: verified Sysmon status and Event Log, fixed single quotes in ossec.conf (WAZUH_MANAGER, WAZUH_AGENT_NAME, WAZUH_AGENT_GROUP) causing connection and enrollment failures, restarted WazuhSvc
- result: ok — agent successfully enrolled and connected to Wazuh Manager (43.228.215.234:1514). ossec.log confirms: "Analyzing event log: 'Microsoft-Windows-Sysmon/Operational'". Tested with notepad.exe trigger which successfully registered in Sysmon log.
- next: Claude verify from Kali/Manager side that Sysmon alerts from win-ep-01 are visible.

## 2026-07-13 17:58 | gemini | win-ep | phase6-setup
- what: installed Invoke-AtomicRedTeam framework + atomics repo
- result: ok — module loaded, T1059.001 -ShowDetails OK
- next: chờ Claude signal chạy session 1

## 2026-07-13 18:04 | gemini | win-ep | phase6-session-01
- what: Invoke-AtomicTest T1059.001 -TestNumbers 1 (PowerShell -EncodedCommand)
- start: 2026-07-13T11:04:07Z
- end:   2026-07-13T11:04:10Z
- result: test failed (blocked by Windows Defender: Mimikatz payload), cleanup completed
- next: Claude hunt on Wazuh side + write session-01 report

## 2026-07-13 18:15 | gemini | win-ep | phase6-session-01-rerun
- what: Invoke-AtomicTest T1059.001 -TestNumbers 1 (PowerShell -EncodedCommand) - Rerun after Rule 100101 fix
- start: 2026-07-13T11:15:24Z
- end:   2026-07-13T11:15:32Z
- result: test failed (blocked by Windows Defender: Mimikatz payload), cleanup completed
- next: Claude hunt on Wazuh side + verify rule 100101

## 2026-07-13 18:26 | gemini | win-ep | phase6-session-01-rerun2
- what: Invoke-AtomicTest T1059.001 -TestNumbers 1 (PowerShell -EncodedCommand) - Second Rerun after originalFileName rule update
- start: 2026-07-13T11:26:20Z
- end:   2026-07-13T11:26:24Z
- result: test failed (blocked by Windows Defender: Mimikatz payload), cleanup completed
- next: Claude hunt on Wazuh side + verify rule 100101

