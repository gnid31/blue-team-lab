# IOC Enrichment CLI

Đọc alert từ **Wazuh Indexer**, extract IOC (hash / IP / domain), enrich qua **VirusTotal** + **AbuseIPDB**, in verdict lên console với color-coded label.

## Cài đặt

```bash
cd enrichment/
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

cp .env.example .env
# Edit .env, điền:
#   WAZUH_INDEXER_URL / USER / PASS (Dashboard admin cũng dùng được)
#   VT_API_KEY (từ virustotal.com/gui/my-apikey)
#   ABUSEIPDB_API_KEY (từ abuseipdb.com/account/api)
```

## Chạy trên Kali (Indexer nằm ở VPS)

Indexer chỉ listen `127.0.0.1:9200` trên VPS. Mở SSH tunnel trước:

```bash
ssh -N -L 9200:localhost:9200 namth@43.228.215.234 &
# `&` để chạy background. Kill khi xong: pkill -f "ssh.*9200"
```

Sau đó tool truy vấn `https://localhost:9200` → tunnel → VPS.

## Sử dụng

```bash
# Enrich alert level ≥7 trong 1h qua
.venv/bin/python enrich.py

# 20 alert của agent Windows trong 24h
.venv/bin/python enrich.py -a win-ep-01 -s now-24h -n 20

# Chỉ enrich rule cụ thể
.venv/bin/python enrich.py -r 100101

# Extract IOC (không call API, tiết kiệm quota)
.venv/bin/python enrich.py --dry-run

# Tất cả flag
.venv/bin/python enrich.py --help
```

## Flow

```
1. WazuhIndexer.search()  → OpenSearch DSL query wazuh-alerts-*
2. extract_iocs(alert)    → regex extract IPv4/domain/md5/sha1/sha256
                            + filter noise (RFC1918, .exe/.dll, MS/Google domains)
3. Cache.get()            → SQLite lookup (skip API nếu < TTL)
4. VirusTotal.lookup()    → v3 API, rate-limit 4 req/min free tier
5. AbuseIPDB.lookup()     → v2 API (chỉ IP)
6. render → rich table    → color-coded verdict, click link → VT/AbuseIPDB
```

## Ví dụ output

```
──── Blue Team Lab — IOC Enrichment  (min_level=7, since=now-24h, limit=3) ────
Fetched 3 alerts
Extracted 3 IOC instances (2 unique)

╭───────────────────────────────────────────────────────────────╮
│ 2026-07-13...  agent=vps  rule=2502 lvl=10  mitre=T1110       │
│ syslog: User missed the password more than one time           │
╰───────────────────────────────────────────────────────────────╯
  type   value           provider     verdict       score
  ip     62.60.130.219   virustotal   MALICIOUS     15/91
  ip     62.60.130.219   abuseipdb    MALICIOUS   100/100
  ...
Summary  malicious=4  suspicious=0  total_verdicts=4
```

## Cấu trúc code

| File | Vai trò |
|---|---|
| `enrich.py` | CLI (click) + orchestrator + rich rendering |
| `wazuh_client.py` | OpenSearch search wrapper |
| `ioc.py` | Regex + noise filter, trả về `list[Ioc]` |
| `providers.py` | `VirusTotal` + `AbuseIPDB` classes, chuẩn hoá thành `Verdict` |
| `cache.py` | SQLite cache TTL-based |

## Rate-limit & cost

| Provider | Free tier | Strategy trong tool |
|---|---|---|
| VirusTotal v3 | 4 req/min, 500 req/day | sleep 15.5s giữa call, cache 24h |
| AbuseIPDB v2 | 1000 req/day | Không sleep, cache 24h |

## Bảo mật

- `.env` chứa API key + Wazuh password → **đã gitignore** (`enrichment/.env`)
- Nếu leak key VT → chỉ đọc-only public data
- Nếu leak Wazuh admin password → attacker có toàn quyền Dashboard → **đổi password ngay**

## Writeback (Option A) — verdict persistent trong Indexer

Thêm flag `--writeback`:
```bash
.venv/bin/python enrich.py -r 2502 --writeback
```
Verdict được `PUT` vào index `enrichment-verdicts-YYYY.MM.DD` với schema chuẩn hoá. Analyst xem trên Dashboard qua index pattern `enrichment-verdicts-*` (tạo tự động lần đầu). Chi tiết: `docs/05b-enrichment-writeback.md`.

## Không làm được

- Ghi verdict **trực tiếp vào alert Wazuh gốc** (Wazuh 4.9 không có API endpoint sửa alert). Writeback tạo document riêng, join qua `alert_id`.
- Batch nhiều nghìn IOC — free tier VT sẽ hết trong ~2 giờ. Cần Premium API.
