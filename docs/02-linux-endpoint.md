# Phase 2 — Ubuntu endpoint + auditd

**Mục tiêu**: cài Wazuh agent trên VM Ubuntu 22.04 (VMware) + auditd rules → telemetry vào Manager.

**Prereq**: Phase 1 done, Wazuh Manager đang chạy tại `43.228.215.234`.

---

## 1. Chuẩn bị VM Ubuntu (VMware)

- **OS**: Ubuntu 22.04 LTS Server hoặc Desktop
- **RAM**: ≥ 2GB, **CPU**: 2 vCPU, **Disk**: 20GB
- **Network**: NAT (default VMware) — cần ra Internet để tải Wazuh package + reach VPS
- **Hostname**: đặt rõ ràng, ví dụ `linux-ep-01`

### CLI (trong VM)
```bash
sudo hostnamectl set-hostname linux-ep-01
```

### GUI
Settings → About → Device Name → đổi thành `linux-ep-01` → reboot.

---

## 2. Cài Wazuh agent

Lấy command chuẩn từ Dashboard: **Wazuh menu → Agents → Deploy new agent**.
Nhập:
- OS: Linux → DEB amd64
- Server address: `43.228.215.234`
- Agent name: `linux-ep-01`
- Group: `default`

Dashboard sẽ generate command. Ví dụ:

### CLI (trong VM Ubuntu)
```bash
wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.9.2-1_amd64.deb
sudo WAZUH_MANAGER='43.228.215.234' WAZUH_AGENT_NAME='linux-ep-01' \
  dpkg -i ./wazuh-agent_4.9.2-1_amd64.deb

sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
sudo systemctl status wazuh-agent --no-pager | head -8
```

### GUI (không có cho việc install agent trên Linux; chỉ chạy CLI)

---

## 3. Verify agent đã connect

### GUI (trên Kali, mở Dashboard)
Wazuh menu → **Agents** → thấy `linux-ep-01` status **Active** (chấm xanh).

### CLI (trên VPS)
```bash
sudo /var/ossec/bin/agent_control -l | grep linux-ep-01
# Kỳ vọng: "ID: 001, Name: linux-ep-01, IP: ..., Active"
```

---

## 4. Cài + config auditd

### CLI (trong VM Ubuntu)
```bash
sudo apt install -y auditd audispd-plugins
sudo systemctl enable --now auditd
```

Copy audit rules từ repo:

```bash
# Trên Kali: scp từ repo qua VM
scp auditd/wazuh-audit.rules <vm-user>@<vm-ip>:/tmp/

# Trong VM
sudo cp /tmp/wazuh-audit.rules /etc/audit/rules.d/wazuh.rules
sudo augenrules --load
sudo auditctl -l | head -20
```

---

## 5. Cấu hình Wazuh agent đọc auditd

### CLI (trong VM Ubuntu)
Edit `/var/ossec/etc/ossec.conf`, thêm trong `<ossec_config>`:

```xml
<localfile>
  <log_format>audit</log_format>
  <location>/var/log/audit/audit.log</location>
</localfile>
```

Restart agent:
```bash
sudo systemctl restart wazuh-agent
```

---

## 6. Sinh test event

### CLI (trong VM)
```bash
# Triggering rule "T1059 – execve of /bin/sh"
/bin/sh -c 'id'

# Trigger sudo audit
sudo whoami
```

### Xác nhận trên Dashboard
Discover → index `wazuh-alerts-*` → filter `agent.name: linux-ep-01` → thấy event trong 30s.

---

## Ghi log

```
## 2026-XX-XX HH:MM | human | linux-ep | phase2
- what: enrolled linux-ep-01, auditd active, test event visible in Dashboard
- result: ok
- next: Phase 3 — Windows endpoint
```
