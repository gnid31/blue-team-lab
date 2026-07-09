# 00 — Architecture

## Topology

```
                     ┌────────────────────────────┐
                     │   VPS (Ubuntu 22.04)       │
                     │   Wazuh Manager + Indexer  │
                     │   + Dashboard (AIO)        │
                     │   :1514 (agents)  :443 UI  │
                     │   :55000 (API)             │
                     └──────────────┬─────────────┘
                                    │
              ┌─────────────────────┼─────────────────────┐
              │                     │                     │
    ┌─────────▼─────────┐ ┌─────────▼─────────┐ ┌─────────▼─────────┐
    │ Windows 10/11 VM  │ │ Ubuntu 22.04 VM   │ │  Kali host        │
    │ (VMware, NAT)     │ │ (VMware, NAT)     │ │  Repo control     │
    │ Sysmon + Agent    │ │ auditd + Agent    │ │  Enrichment CLI   │
    └───────────────────┘ └───────────────────┘ └───────────────────┘
```

## Data flow

1. Endpoint telemetry (Sysmon / auditd / OS logs) → Wazuh agent → **1514/tcp** → Wazuh Manager
2. Manager decodes → matches custom rule → writes to Indexer
3. Analyst xem alerts trên Dashboard (443/tcp)
4. Enrichment tool trên Kali đọc alerts (API 55000 hoặc export JSON) → VT/AbuseIPDB → verdict lưu lại

## Network

- Endpoint VM đặt ở **NAT** (VMware default) — cần internet để reach VPS + Wazuh repo.
- VPS mở inbound: `1514/tcp`, `1515/tcp` (enrollment), `55000/tcp`, `443/tcp` (giới hạn source IP nếu có thể).
- Kali reach VPS qua **API 55000** + **HTTPS 443**.

## Rule ID convention

- Wazuh built-in rules: 1–99999
- **Custom rules dùng dải `100100 – 100199`** (đủ cho 10 rule + spare)

## Secrets

- Không commit: agent enrollment key, VT/AbuseIPDB API key, Dashboard admin password.
- API keys lưu trong `enrichment/.env` (đã ignore).

## Versions pinned

| Component        | Version | Ghi chú                          |
|------------------|---------|----------------------------------|
| Wazuh            | 4.9.x   | AIO installer                    |
| Sysmon           | 15.x    | Với config SwiftOnSecurity fork  |
| Atomic Red Team  | latest  | Cài qua Invoke-AtomicRedTeam PS  |
| Python           | ≥3.10   | Enrichment tool                  |
