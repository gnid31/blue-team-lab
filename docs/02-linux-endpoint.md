# Phase 2 — Ubuntu endpoint + auditd (giải thích chi tiết)

> Doc này viết cho người **chưa từng chạm** Wazuh / auditd / SIEM. Đọc từ trên xuống, không skip.

---

## 0. Kiến thức nền

### 0.1. Wazuh là gì?

**Wazuh** là một nền tảng open-source kết hợp 3 vai trò:

| Vai trò | Ý nghĩa |
|---|---|
| **HIDS** (Host-based Intrusion Detection System) | Cài agent lên từng máy, quan sát log/file/process **trên chính máy đó** để phát hiện tấn công. |
| **SIEM** (Security Information & Event Management) | Gom log từ nhiều máy về 1 nơi, chuẩn hoá, index, alert, search. |
| **XDR** (Extended Detection & Response) | Có thể chạy **active response** (block IP, kill process) khi phát hiện đe doạ. |

Kiến trúc trong lab này:

```
┌─────────────────────────────────────────────────────────────┐
│  Wazuh Manager (VPS 43.228.215.234)                          │
│  ┌──────────────┐  ┌─────────────┐  ┌────────────────────┐ │
│  │ wazuh-manager│→ │ filebeat    │→ │ wazuh-indexer      │ │
│  │  (decode +   │  │ (ship JSON) │  │ (OpenSearch: lưu + │ │
│  │  rule match) │  └─────────────┘  │  index alert)      │ │
│  └──────▲───────┘                   └─────────▲──────────┘ │
│         │                                     │            │
│         │ port 1514/tcp                       │ 9200/tcp   │
│         │ (agent → manager)                   │            │
│         │                            ┌────────┴──────────┐ │
│         │                            │ wazuh-dashboard   │ │
│         │                            │ (UI Kibana-like)  │ │
│         │                            └───────────────────┘ │
└─────────┼──────────────────────────────────────────────────┘
          │
          │  event/log stream (encrypted)
          │
    ┌─────┴────────────────┐
    │ VM Ubuntu 22.04      │
    │  ┌────────────────┐  │
    │  │ wazuh-agent    │  │  ← process này đọc log các nơi trên máy
    │  └───▲────────────┘  │
    │      │ đọc file      │
    │      │               │
    │  ┌───┴────────────┐  │
    │  │ /var/log/audit │  │  ← auditd ghi vào đây
    │  │  /audit.log    │  │
    │  └───▲────────────┘  │
    │      │ auditd daemon ghi                                │
    │  ┌───┴────────────┐                                     │
    │  │ Linux kernel   │  ← kernel bắn event khi có syscall  │
    │  │ audit subsystem│    /file access match rule          │
    │  └────────────────┘                                     │
    └──────────────────────┘
```

### 0.2. Vì sao cần auditd?

Bản thân `wazuh-agent` **không quan sát trực tiếp syscall** hay file access. Nó chỉ **đọc file log**. Vậy dữ liệu về "process nào chạy lệnh gì, ai đọc `/etc/shadow`, ai ghi vào crontab" — **ai sinh ra**?

→ Đó là **auditd** (Linux Audit Daemon).

- Linux kernel có 1 subsystem tên **audit**, có thể lắng nghe syscall (`execve`, `connect`, `openat`, ...) và file access.
- Bạn đưa cho kernel 1 danh sách **rule** (chính là file `wazuh-audit.rules` mình vừa nạp).
- Mỗi khi có event khớp rule, kernel gửi event ra user-space qua netlink.
- `auditd` (daemon) nhận và ghi thành text vào **`/var/log/audit/audit.log`**.
- `wazuh-agent` đọc file log này, gửi lên Manager.
- Manager có **decoder audit** (built-in) parse text thành field JSON như `data.audit.key`, `data.audit.exe`, `data.audit.command`, ...
- Manager chạy **rule engine** — nếu match rule XML, sinh alert, ghi vào indexer.

**Không có auditd → không có visibility sâu về hệ thống Linux.**

### 0.3. MITRE ATT&CK

**MITRE ATT&CK** là framework mô tả kỹ thuật tấn công theo mã (T1003, T1059, ...). Ví dụ:

| Technique | Ý nghĩa | Ta bắt bằng cái gì? |
|---|---|---|
| **T1059** Command & Scripting Interpreter | Attacker chạy shell (`/bin/sh`, `bash`) | audit rule syscall `execve` |
| **T1548** Abuse Elevation Control Mechanism | Attacker leo quyền qua `sudo` | audit `-w /usr/bin/sudo -p x` |
| **T1136** Create Account | Tạo user mới | audit `-w /etc/passwd -p wa` |
| **T1543.002** Systemd Service | Persistence qua service | audit `-w /etc/systemd/system` |
| **T1053.003** Cron Job | Persistence qua cron | audit `-w /etc/crontab` |
| **T1547** Boot/Logon Autostart | Persistence qua SSH key | audit `-w /root/.ssh -p wa` |

File `auditd/wazuh-audit.rules` trong repo đã map sẵn 8 nhóm technique như trên. Phase 4 sẽ viết Wazuh rule XML để **sinh alert** cho từng technique — hiện tại auditd chỉ ghi log, chưa có alert cụ thể.

### 0.4. Các thuật ngữ Wazuh cần nhớ

| Thuật ngữ | Nghĩa |
|---|---|
| **Manager / Server** | Trung tâm — nhận log, chạy rule, sinh alert |
| **Agent** | Client cài trên endpoint — thu thập log |
| **Endpoint** | Máy đang được monitor (Ubuntu VM, Windows VM, ...) |
| **Enrollment** | Quá trình agent đăng ký với manager, nhận cert/key để truyền dữ liệu mã hoá |
| **Decoder** | Regex/script parse text log thành field JSON |
| **Rule** | XML định nghĩa điều kiện "khi thấy X → sinh alert level Y" |
| **Level** | 0–15, càng cao càng nghiêm trọng. ≥12 thường page oncall |
| **ossec.conf** | File config chính của agent, XML |
| **Indexer** | OpenSearch fork lưu alert để search |

---

## 1. Chuẩn bị VM Ubuntu (VMware)

### Yêu cầu VM

| Thông số | Giá trị đề xuất |
|---|---|
| OS | Ubuntu 22.04 LTS Server (nhẹ) hoặc Desktop |
| RAM | ≥ 2 GB |
| vCPU | 2 |
| Disk | 20 GB |
| Network | **NAT** (default VMware). Không cần bridged vì agent chủ động connect ra ngoài. |
| Hostname | `linux-ep-01` (đặt rõ ràng để tìm trên Dashboard) |

> **Vì sao NAT chứ không Host-only?** — Agent phải reach VPS `43.228.215.234` qua Internet. NAT dùng chung IP host, host có Internet → VM có Internet. Host-only thì VM chỉ nói chuyện với Kali, không ra ngoài.

### Đổi hostname

**GUI**: Settings → About → Device Name → `linux-ep-01` → reboot.

**CLI**:
```bash
sudo hostnamectl set-hostname linux-ep-01
# hostnamectl = tool systemd để set hostname vĩnh viễn (ghi /etc/hostname + /etc/machine-info)
```

Kiểm tra:
```bash
hostname
# → linux-ep-01
```

---

## 2. Cài Wazuh Agent

### 2.1. Ý nghĩa

Wazuh agent là 1 **service systemd** chạy 4 process nhỏ:

| Process | Vai trò |
|---|---|
| `wazuh-agentd` | Kết nối/duy trì phiên với Manager qua 1514/tcp (TLS) |
| `wazuh-logcollector` | Tail các file log (audit.log, syslog, apache, ...) |
| `wazuh-syscheckd` | File Integrity Monitoring (FIM) — hash file, phát hiện thay đổi |
| `wazuh-modulesd` | Chạy module phụ (SCA policy check, vulnerability scan, ...) |

Package `wazuh-agent` cài cả 4.

### 2.2. Lấy lệnh cài từ Dashboard (khuyến nghị)

**GUI (trên Kali)**:
1. Mở https://43.228.215.234 → login `admin`
2. Menu bên trái → **Wazuh** → **Agents**
3. Nút **Deploy new agent** (góc phải)
4. Chọn:
   - OS: **Linux → DEB amd64**
   - Server address: `43.228.215.234` (public IP VPS)
   - Assign agent name: `linux-ep-01`
   - Assign group: `default`
5. Copy toàn bộ command Dashboard sinh ra, paste vào VM.

> Vì sao dùng Dashboard? — Nó sinh sẵn 1 command đã điền đúng `WAZUH_MANAGER` + `WAZUH_AGENT_NAME`, không sai chính tả.

### 2.3. Cài bằng CLI (thủ công)

**Trong VM Ubuntu**:

```bash
# Bước 1: tải package .deb chính thức
wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.9.2-1_amd64.deb
```

Giải thích:
- `wget` = tải file HTTP
- URL này là repo apt chính thức của Wazuh. Phiên bản **4.9.2** phải khớp với Manager (Phase 1 cài 4.9.2). Không khớp phiên bản major có thể fail decode.

```bash
# Bước 2: cài package + set 2 biến môi trường để installer viết sẵn config
sudo WAZUH_MANAGER='43.228.215.234' WAZUH_AGENT_NAME='linux-ep-01' \
  dpkg -i ./wazuh-agent_4.9.2-1_amd64.deb
```

Giải thích:
- `sudo` — cần root vì cài vào `/var/ossec/`, ghi service systemd
- `WAZUH_MANAGER=...` — biến này được post-install script đọc, ghi thẳng vào `/var/ossec/etc/ossec.conf` phần `<server><address>...</address></server>`
- `WAZUH_AGENT_NAME=...` — tương tự, ghi vào file config để agent tự đăng ký với tên này
- `dpkg -i` — cài file .deb local (khác `apt install <name>` là cài từ repo)

```bash
# Bước 3: enable + start service
sudo systemctl daemon-reload         # reload unit file mới
sudo systemctl enable wazuh-agent    # tự start khi boot
sudo systemctl start wazuh-agent     # start ngay
sudo systemctl status wazuh-agent --no-pager | head -8
```

Kỳ vọng: `Active: active (running)`.

### 2.4. Verify agent đã connect Manager

**GUI (Dashboard trên Kali)**:
- Menu → **Agents** → thấy dòng `linux-ep-01` với chấm xanh **Active**.

**CLI (trên VPS)**:
```bash
sudo /var/ossec/bin/agent_control -l
# Output:
# ID: 001, Name: linux-ep-01, IP: any, Active
```

Giải thích: `agent_control` là tool trên Manager để list agent. Nếu status là `Never connected` → agent chưa reach được Manager (check firewall / IP sai).

---

## 3. Cài auditd + nạp rules

### 3.1. Cài auditd

**CLI (trong VM Ubuntu)**:
```bash
sudo apt install -y auditd audispd-plugins
```

Giải thích:
- `auditd` — daemon chính, đọc event từ kernel audit subsystem, ghi ra `/var/log/audit/audit.log`
- `audispd-plugins` — plugin dispatcher (chuyển audit event sang syslog, remote host, ...). Không dùng ngay nhưng nên cài kèm.
- `apt install -y` — `-y` = tự đồng ý prompt

```bash
sudo systemctl enable --now auditd
```

Giải thích:
- `enable --now` = combo: enable (tự start khi boot) + start ngay bây giờ.

### 3.2. Copy rule file từ repo (trên Kali) sang VM

**Trên Kali** (trong repo `/home/kali/blue-team-lab/`):
```bash
scp auditd/wazuh-audit.rules gnid@192.168.154.166:/tmp/
```

Giải thích từng phần:
- `scp` — **secure copy**, copy file qua SSH.
- `auditd/wazuh-audit.rules` — file source, đường dẫn tương đối trong repo.
- `gnid@192.168.154.166` — `<user>@<ip>` của VM. `gnid` là user Linux trong VM, `192.168.154.166` là IP VMware NAT gán cho VM.
- `:/tmp/` — đích trên VM. `/tmp` = thư mục tạm, world-writable → không cần sudo. Sẽ bị xoá khi reboot nhưng bước sau ta copy vào chỗ khác nên OK.

### 3.3. Đặt rule file vào thư mục auditd đọc

**CLI (trong VM)**:
```bash
sudo cp /tmp/wazuh-audit.rules /etc/audit/rules.d/wazuh.rules
```

Giải thích:
- `/etc/audit/rules.d/` — auditd đọc **tất cả** file `.rules` trong đây khi start, ghép lại thành 1 rule set. Cách này cho phép nhiều source (ta, distro, tool khác) cùng append rule mà không đè lên nhau.
- Đặt tên `wazuh.rules` cho dễ nhận ra là của lab này. Không đặt `audit.rules` vì auditd đã có file `audit.rules` mặc định (rỗng) trong thư mục đó — trùng tên sẽ đè.
- `sudo` — `/etc/audit/` chỉ root có quyền ghi.

### 3.4. Nạp rules vào kernel

**CLI (trong VM)**:
```bash
sudo augenrules --load
```

Giải thích:
- `augenrules` = "audit generate rules" — tool của gói auditd.
- Nó đọc **tất cả** `.rules` trong `/etc/audit/rules.d/`, sort theo tên, ghép thành file `/etc/audit/audit.rules` cuối cùng.
- Flag `--load` = sau khi ghép xong, **truyền rule vào kernel ngay** qua netlink (thay vì đợi reboot).
- Không có `--load` = chỉ ghép file, cần `systemctl restart auditd` để áp dụng.

> **Cảnh báo output "No rules"**: `augenrules --load` có thể in dòng `No rules` — đây là **status dump của kernel audit trước khi nạp rule mới**, không phải error. Confirm bằng `auditctl -l` ở bước sau.

### 3.5. Verify rules đã ở trong kernel

```bash
sudo auditctl -l | head -20
```

Giải thích:
- `auditctl -l` — list **rules đang active trong kernel** (không phải file). Đây là ground truth.
- `head -20` — chỉ xem 20 dòng đầu.

Kỳ vọng thấy 26 dòng, ví dụ:
```
-a always,exit -F arch=b64 -S execve -F key=execve
-w /usr/bin/sudo -p x -k priv_esc
-w /etc/passwd -p wa -k identity
...
```

Ý nghĩa cú pháp rule:
- `-a always,exit -F arch=b64 -S execve` — audit **mọi lần** syscall `execve` (chạy chương trình) trên kiến trúc 64-bit, tại thời điểm exit (kết thúc syscall).
- `-w /usr/bin/sudo -p x` — **watch** file `/usr/bin/sudo`, permission `x` = execute. Bất cứ ai chạy sudo đều bị ghi.
- `-p wa` = write + attribute change. `-p r` = read.
- `-k <key>` — tag đặt cho rule để dễ query bằng `ausearch -k <key>`.

---

## 4. Cấu hình Wazuh agent đọc `/var/log/audit/audit.log`

### 4.1. Ý nghĩa

Đến đây, auditd đã ghi vào `/var/log/audit/audit.log`, nhưng **Wazuh chưa biết đọc file đó** — cần khai báo trong `ossec.conf`.

### 4.2. Edit ossec.conf

File: `/var/ossec/etc/ossec.conf`

Thêm block sau **trước tag đóng `</ossec_config>`**:

```xml
<localfile>
  <log_format>audit</log_format>
  <location>/var/log/audit/audit.log</location>
</localfile>
```

Giải thích từng element:
- `<localfile>` — block khai báo 1 nguồn log local mà agent phải theo dõi.
- `<log_format>audit</log_format>` — **quan trọng**. Đây là "kiểu" của log; Wazuh có sẵn nhiều format: `syslog`, `audit`, `json`, `multi-line`, `eventchannel` (Windows), `command`, ... Format `audit` báo Manager dùng đúng decoder cho định dạng `type=SYSCALL msg=audit(...): ...`.
- `<location>` — path file cần tail. Wazuh sẽ theo dõi thay đổi (giống `tail -F`) — không đọc lại từ đầu mỗi lần restart.

### 4.3. Kiểm tra XML hợp lệ

```bash
sudo /var/ossec/bin/wazuh-agentd -t
# -t = test config, không start
# Nếu OK: không print gì hoặc "Configuration verified"
# Nếu sai XML: print lỗi + line number
```

### 4.4. Restart agent

```bash
sudo systemctl restart wazuh-agent
sudo systemctl is-active wazuh-agent   # → active
```

### 4.5. Verify agent đang tail đúng file

```bash
sudo tail -20 /var/ossec/logs/ossec.log | grep -i audit
```

Kỳ vọng thấy dòng:
```
wazuh-logcollector: INFO: (1950): Analyzing file: '/var/log/audit/audit.log'.
```

Nếu thấy → OK, agent đang tail file. Nếu không → check lại path + XML.

> **Có thể thấy WARNING**: `Target 'agent' message queue is full (1024). Log lines may be lost.` — đây là hiện tượng bình thường lần đầu, khi agent phải "catch up" nhiều nghìn dòng audit log cũ. Sau 30s sẽ ổn định.

---

## 5. Test end-to-end

### 5.1. Sinh event trên VM

```bash
# Trigger key=priv_esc + key=execve (từ /bin/sh)
sudo whoami
/bin/sh -c 'id'

# Trigger key=identity (đọc /etc/passwd không kích hoạt rule vì -p wa; cần ghi)
# Thay bằng chạy `sudo cat /etc/sudoers` để trigger sudoers_change đường watch execute sudo
sudo cat /etc/sudoers > /dev/null
```

### 5.2. Verify audit.log có event

```bash
sudo grep -E "key=(priv_esc|execve|sudoers_change)" /var/log/audit/audit.log | tail -5
```

Kỳ vọng: có ≥ 1 dòng cho mỗi key.

### 5.3. Verify alert đến Manager

**GUI (Dashboard trên Kali)**:
1. Vào `https://43.228.215.234` → login
2. Menu **Discover** (biểu tượng compass)
3. Chọn index pattern `wazuh-alerts-*`
4. Filter: `agent.name : "linux-ep-01"`
5. Time range: **Last 15 minutes**
6. Thấy list alert. Click 1 alert → expand → check `rule.description`, `full_log`, `data.audit.*`.

**CLI (trên VPS, dùng OpenSearch API)**:
```bash
curl -sk -u "admin:<DASHBOARD_PASS>" \
  -X POST "https://localhost:9200/wazuh-alerts-*/_search?pretty" \
  -H 'Content-Type: application/json' \
  -d '{
    "size": 5,
    "sort": [{"@timestamp": "desc"}],
    "query": { "match": { "agent.name": "linux-ep-01" } }
  }'
```

Giải thích:
- Wazuh indexer bản chất là OpenSearch (fork Elasticsearch). Truy vấn theo API OpenSearch DSL.
- Index pattern `wazuh-alerts-*` — mỗi ngày Wazuh tạo index mới `wazuh-alerts-4.x-YYYY.MM.DD`.
- `-u admin:...` — HTTP basic auth. Password cùng với password Dashboard.
- `-k` — bỏ qua verify cert (self-signed).

> **Chú ý ở Phase 2**: chưa có custom rule nên chỉ thấy alert built-in level 3 kiểu "Successful sudo to ROOT executed". **Phase 4** viết rule custom sẽ sinh alert riêng cho `key=priv_esc`, `key=execve`, ... với level cao hơn và mapping MITRE.

---

## 6. Troubleshooting

| Triệu chứng | Nguyên nhân | Fix |
|---|---|---|
| `systemctl status wazuh-agent` → **Never connected** | Firewall VPS chặn 1514, hoặc `WAZUH_MANAGER` sai IP | Test `nc -vz 43.228.215.234 1514` từ VM; check UFW trên VPS |
| Agent connected nhưng Dashboard không thấy alert | Đồng hồ VM lệch → timestamp tương lai/quá khứ | `sudo timedatectl set-ntp true` |
| `augenrules --load` báo `Error deleting rule` | auditd đang chạy immutable mode (`-e 2`) | Reboot VM để reset audit state |
| `auditctl -l` không thấy rule | File `.rules` sai cú pháp | Kiểm tra `journalctl -u auditd` |
| Discover trên Dashboard trống | Index pattern chưa tạo | Menu → Stack Management → Index Patterns → Create `wazuh-alerts-*` |
| Warning "message queue full" | Backfill lần đầu, chuyện bình thường | Đợi 60s |

---

## 7. Ghi log

Sau khi hoàn thành, append vào `PROJECT_LOG.md`:

```
## 2026-XX-XX HH:MM | human | linux-ep | phase2
- what: enrolled linux-ep-01 (agent 4.9.2), auditd 26 rules loaded, ossec.conf trỏ audit.log
- result: ok — alert level 3 "sudo to ROOT" hiện trên Dashboard
- next: Phase 3 — Windows endpoint
```

---

## Recap: pipeline dữ liệu hoàn chỉnh sau Phase 2

```
1. User chạy `sudo whoami`
   ↓
2. Kernel gọi syscall `execve` cho /usr/bin/whoami
   ↓
3. Kernel audit subsystem thấy `-w /usr/bin/sudo -p x` match  →  bắn event
   ↓
4. auditd nhận từ netlink, ghi text vào /var/log/audit/audit.log
   ↓
5. wazuh-agent (logcollector) đang tail file, đọc dòng mới
   ↓
6. Agent gửi qua TLS đến Manager :1514
   ↓
7. Manager (analysisd) decode text → JSON có field data.audit.key=priv_esc, data.audit.exe=/usr/bin/whoami
   ↓
8. Rule engine match → sinh alert
   ↓
9. filebeat ship JSON alert đến wazuh-indexer :9200
   ↓
10. Analyst mở Dashboard → thấy alert
```

Xong Phase 2, ta có 1 pipeline visibility hoàn chỉnh cho Linux endpoint. Phase 3 làm điều tương tự cho Windows (dùng Sysmon thay auditd).
