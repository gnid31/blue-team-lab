# Phase 1 — Deploy Wazuh 4.9 AIO trên VPS

**Mục tiêu**: cài Wazuh Manager + Indexer + Dashboard trên 1 VPS Ubuntu 22.04, mở port cho agent + admin UI.

**Prereq VPS**: Ubuntu 22.04 LTS, ≥ 4GB RAM, 2 vCPU, ≥ 50GB disk, root/sudo, internet ra ngoài.

---

## 1. Mở firewall (trước khi cài)

### CLI (VPS)
```bash
sudo ufw allow 22/tcp        # SSH
sudo ufw allow 443/tcp       # Wazuh Dashboard
sudo ufw allow 1514/tcp      # Agent connections
sudo ufw allow 1515/tcp      # Agent enrollment
sudo ufw allow 55000/tcp     # Wazuh API
sudo ufw --force enable
sudo ufw status numbered
```

### GUI (nhà cung cấp VPS — DigitalOcean / Vultr / AWS Security Group / …)
1. Vào Console → **Networking / Firewall** của VPS
2. Add inbound rules:
   - TCP 22 (SSH) — chỉ IP của bạn nếu có thể
   - TCP 443 — Dashboard
   - TCP 1514, 1515 — Agent (allow từ IP endpoint hoặc `0.0.0.0/0` nếu VM sau NAT)
   - TCP 55000 — API (nên giới hạn IP Kali của bạn)

> **Lý do**: Wazuh installer sẽ dựng self-signed cert cho 443 và 55000; nếu firewall chặn, dashboard sẽ không truy cập được từ Kali.

---

## 2. Update hệ thống

### CLI (VPS)
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl gnupg apt-transport-https lsb-release
timedatectl set-timezone Asia/Ho_Chi_Minh
```

---

## 3. Chạy Wazuh AIO installer

Wazuh khuyến nghị dùng `wazuh-install.sh` cho AIO. Script tự sinh cert, tạo password admin.

### CLI (VPS)
```bash
cd /root
curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.9/wazuh-certs-tool.sh

# All-in-one, ignore hardware check nếu VPS đúng >=4GB
sudo bash wazuh-install.sh -a
```

Đợi ~10–15 phút. Cuối output installer sẽ in:

```
INFO: --- Summary ---
INFO: You can access the web interface https://<VPS_IP>
    User: admin
    Password: <RANDOM_PASSWORD>
```

**Ghi ngay** password này vào password manager. Nếu miss, lấy lại:

```bash
sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
```

### GUI (không có — installer là CLI-only; sau khi xong mới có Dashboard)

---

## 4. Verify các service

### CLI (VPS)
```bash
sudo systemctl status wazuh-manager --no-pager | head -10
sudo systemctl status wazuh-indexer --no-pager | head -10
sudo systemctl status wazuh-dashboard --no-pager | head -10

# Test API
curl -k -u wazuh-wui:$(sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt | grep "'wazuh-wui'" -A1 | tail -1 | awk -F"'" '{print $2}') \
  https://localhost:55000/security/user/authenticate?raw=true
```

Kỳ vọng: 3 service `active (running)`, API trả về JWT token.

### GUI
- Mở trình duyệt trên Kali: `https://<VPS_IP>` → chấp nhận self-signed cert
- Login `admin` / `<RANDOM_PASSWORD>`
- Menu bên trái → **Wazuh** → **Agents** → hiện "0 agents"

---

## 5. Đổi password admin (khuyến nghị)

### CLI (VPS)
```bash
sudo /var/ossec/bin/wazuh-passwords-tool.sh -au admin -ap 'YourNewStrongPass!'
```

### GUI (Dashboard)
1. Góc trên phải → **avatar** → **Reset password**
2. Nhập password mới, ≥ 12 ký tự, có ký tự đặc biệt.

---

## 6. Ghi trạng thái vào PROJECT_LOG

Sau khi hoàn thành, ở **Kali** update `PROJECT_LOG.md`:

```
## 2026-07-XX HH:MM | human | vps | phase1
- what: cài Wazuh AIO 4.9 xong, 3 service running, Dashboard truy cập được
- result: ok
- next: Phase 2 — enroll Ubuntu endpoint
```

Và điền IP VPS + admin password (password **không commit**, chỉ note "đã lưu trong password manager").

---

## Troubleshooting nhanh

| Triệu chứng                              | Nguyên nhân thường gặp                     | Fix                                                         |
|------------------------------------------|--------------------------------------------|-------------------------------------------------------------|
| Installer báo "Not enough RAM"           | VPS < 3.5GB                                | Thêm swap `fallocate -l 4G /swapfile && ...`                |
| Dashboard 502 sau khi cài                | Indexer chưa lên kịp                       | `sudo systemctl restart wazuh-dashboard`, đợi 60s           |
| Không login được Dashboard               | Nhầm password admin vs kibanaserver        | Xem `wazuh-passwords.txt`                                   |
| Timeout 443 từ Kali                      | Firewall VPS hoặc security group chặn      | Kiểm tra ufw + firewall provider                            |

Khi có lỗi, paste output đầy đủ vào chat cho tôi — kèm command đã chạy.
