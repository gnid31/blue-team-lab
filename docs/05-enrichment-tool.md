# Phase 5 — Python IOC Enrichment Tool (chi tiết)

> Doc cho người **chưa từng viết Python enrichment**. Đọc từ đầu, không skip.

---

## 0. Kiến thức nền

### 0.1. IOC là gì?

**IOC** = *Indicator of Compromise* — 1 giá trị (hash file, IP, domain, URL, registry key) có mối liên hệ đến 1 sự cố an ninh. Analyst dùng IOC để:

- Xác định `10.20.30.40` có phải C2 attacker → nếu có, block firewall
- Xác định file hash `a1b2c3...` có phải malware đã biết → nếu có, cách ly host
- Xác định `evil-domain.tld` có blacklist trên nhiều nguồn → block DNS

**Vấn đề**: alert Wazuh thô chỉ nói "process cmd.exe tạo file `evil.zip` trong Temp". Analyst phải:
1. Copy hash file → paste vào VirusTotal → chờ kết quả
2. Copy IP → paste vào AbuseIPDB → chờ
3. Ghi kết quả vào note
4. Lặp lại cho từng alert

→ **Tốn 5-10 phút/alert**. Với 50 alert/ngày = nửa ca làm việc chỉ để lookup TI. **Đây chính là repetitive task mà tool tự động hoá**.

### 0.2. Threat Intel provider

| Provider | Data | Free tier | Note |
|---|---|---|---|
| **VirusTotal** (v3) | File hash, IP, domain, URL — scan bởi 70+ engine AV | 4 req/min, 500 req/day | Hash lookup mạnh nhất |
| **AbuseIPDB** (v2) | Chỉ IP — confidence score 0-100 dựa report từ community | 1000 req/day | IP reputation chất lượng cao |
| Shodan | Port/banner IP | 100 req/mo (free) | Không dùng trong tool này |
| MISP | On-prem TI platform | Self-host | Enterprise, ngoài scope lab |

Tool này dùng **VT + AbuseIPDB** vì:
- Free tier đủ cho lab
- VT cover cả 3 loại IOC (hash + IP + domain)
- AbuseIPDB có score IP tin cậy, bổ sung VT

### 0.3. Wazuh Indexer

**Wazuh Indexer** = OpenSearch fork (bản chất là Elasticsearch), lưu alert dạng document JSON theo index pattern `wazuh-alerts-4.x-YYYY.MM.DD`. Query bằng **OpenSearch DSL** qua REST API port 9200.

Ví dụ query "alert level ≥ 7 trong 1h":
```json
POST /wazuh-alerts-*/_search
{
  "size": 20,
  "sort": [{"@timestamp": "desc"}],
  "query": {"bool": {"must": [
    {"range": {"rule.level": {"gte": 7}}},
    {"range": {"@timestamp": {"gte": "now-1h"}}}
  ]}}
}
```

**Cấu trúc 1 alert JSON** (rút gọn):
```json
{
  "_id": "abc123",
  "_source": {
    "@timestamp": "2026-07-13T09:48:50.451Z",
    "agent": {"name": "vps", "id": "000", "ip": "127.0.0.1"},
    "rule": {"id": "2502", "level": 10, "description": "User missed password",
             "mitre": {"id": ["T1110"]}},
    "data": {"srcip": "62.60.130.219", "srcuser": "root"},
    "full_log": "sshd[1234]: Failed password for root from 62.60.130.219 port 22"
  }
}
```

IOC nằm rải rác — `data.srcip`, `full_log`, `data.win.eventdata.hashes`, `data.audit.exe`, … Tool phải walk cả tree để extract.

### 0.4. Vì sao cần SSH tunnel?

Wazuh Indexer chỉ listen `127.0.0.1:9200` trên VPS (không expose public — đúng — vì có full alert data). Từ Kali reach thế nào?

**SSH port forwarding** — Kali mở port local 9200, mọi request tới đó tunnel qua SSH đến VPS:9200.

```
Kali:9200  ────SSH tunnel────►  VPS:9200 (Wazuh Indexer)
     ▲
     │ curl / Python request
     │
   Tool CLI
```

Lệnh mở tunnel:
```bash
ssh -N -L 9200:localhost:9200 namth@43.228.215.234
# -N: không mở shell, chỉ tunnel
# -L LOCAL:REMOTE_HOST:REMOTE_PORT
```

Chạy background: thêm `&` cuối lệnh, hoặc dùng `-f` cho ssh auto-fork.

Kill khi xong: `pkill -f "ssh.*9200"`.

---

## 1. Cài đặt

### 1.1. Chuẩn bị

- Python ≥ 3.10 (đã có sẵn Kali)
- API key VirusTotal (đăng ký free tại https://www.virustotal.com/gui/join-us)
- API key AbuseIPDB (đăng ký free tại https://www.abuseipdb.com/register)
- Password Wazuh Dashboard `admin` (đã có ở `.secrets.local`)

### 1.2. Cài dependencies

**CLI**:
```bash
cd /home/kali/blue-team-lab/enrichment
python3 -m venv .venv                       # tạo venv riêng cho tool
.venv/bin/pip install -r requirements.txt   # cài requests, dotenv, rich, click
```

Ý nghĩa các package:
- `requests` — HTTP client
- `python-dotenv` — load `.env` file thành env var
- `rich` — pretty console (color, table, panel)
- `click` — CLI framework (parse argument, --help auto-gen)

### 1.3. Cấu hình `.env`

```bash
cp .env.example .env
nano .env
```

Điền vào:
```
WAZUH_INDEXER_URL=https://localhost:9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASS=<Wazuh Dashboard admin password>
VT_API_KEY=<VirusTotal API key>
ABUSEIPDB_API_KEY=<AbuseIPDB API key>
```

**Không commit** `.env`. Đã có trong `.gitignore`.

---

## 2. Chạy end-to-end

### 2.1. Mở SSH tunnel (nếu chạy trên Kali)

```bash
ssh -N -L 9200:localhost:9200 namth@43.228.215.234 &
sleep 2
ss -tln | grep 9200    # verify port 9200 đang bind local
```

Nếu chạy tool **trên chính VPS**: bỏ qua bước tunnel.

### 2.2. Chạy dry-run (không call API)

```bash
.venv/bin/python enrich.py --dry-run --since now-24h --limit 5
```

Xem: tool có kéo được alert không, có extract đúng IOC không.

### 2.3. Chạy real enrichment

```bash
.venv/bin/python enrich.py --since now-24h --limit 5
```

Sẽ:
1. Fetch 5 alert level ≥7 mới nhất
2. Extract IOC unique
3. Với mỗi IOC → check cache. Miss → call VT (nếu hash/IP/domain) + AbuseIPDB (nếu IP)
4. Print bảng verdict với màu (red = malicious, yellow = suspicious, green = clean)
5. Summary tổng

Ước lượng thời gian: **~16s / IOC** vì VT free tier rate-limit 4/min.

### 2.4. Filter cụ thể

```bash
# Chỉ alert từ Windows endpoint
.venv/bin/python enrich.py -a win-ep-01

# Chỉ rule 100101 (PowerShell suspicious)
.venv/bin/python enrich.py -r 100101

# Alert 15 phút gần đây, min level 10
.venv/bin/python enrich.py -l 10 -s now-15m

# Alert SSH brute force 24h
.venv/bin/python enrich.py -r 2502 -s now-24h
```

---

## 3. Kiến trúc code

### 3.1. Sơ đồ

```
                    ┌──────────────────┐
                    │  enrich.py (CLI) │  ← click parse args, orchestrator
                    └────────┬─────────┘
                             │
       ┌─────────────────────┼─────────────────────┐
       │                     │                     │
┌──────▼──────┐    ┌─────────▼─────────┐   ┌───────▼────────┐
│ wazuh_      │    │ ioc.py            │   │ providers.py   │
│ client.py   │    │ regex + noise     │   │ VirusTotal +   │
│ OpenSearch  │    │ filter →          │   │ AbuseIPDB      │
│ query       │    │ list[Ioc]         │   │ → Verdict      │
└─────────────┘    └───────────────────┘   └────────────────┘
                             │                     │
                             │             ┌───────▼────────┐
                             │             │ cache.py       │
                             │             │ SQLite TTL     │
                             │             └────────────────┘
                             │                     │
                    ┌────────▼─────────────────────▼────────┐
                    │ rich Console: Panel + Table + link    │
                    └───────────────────────────────────────┘
```

### 3.2. `ioc.py` — regex extract

Walk cả tree JSON alert, ở mỗi string chạy regex:
- IPv4: `\b(?:...){3}(?:...)\b` — 4 octet
- SHA256: `\b[a-f0-9]{64}\b` — 64 hex chars
- SHA1: `\b[a-f0-9]{40}\b`
- MD5: `\b[a-f0-9]{32}\b`
- Domain: FQDN pattern

Sau đó filter noise:
- IP RFC1918 (10.0/8, 172.16/12, 192.168/16), loopback 127.0.0.0/8 → bỏ
- Domain Microsoft/Google/Ubuntu → bỏ
- Extension `.exe` `.dll` `.sys` — coi là filename, không phải domain

### 3.3. `providers.py` — Verdict normalisation

Mỗi provider trả về format khác nhau:
- VT: `stats.malicious`, `stats.suspicious`, `harmless`, `undetected`
- AbuseIPDB: `abuseConfidenceScore` (0-100)

Class `Verdict` chuẩn hoá:
```python
@dataclass
class Verdict:
    provider: str
    value: str
    malicious: int    # count / score
    total: int        # max
    verdict_label: str  # "clean" | "suspicious" | "malicious" | "unknown"
    link: str
    raw: dict
```

Label rule:
- VT: ratio malicious/total ≥ 15% → malicious; ≥ 5% hoặc ≥ 1 engine → suspicious
- AbuseIPDB: score ≥ 75 → malicious; ≥ 25 → suspicious; > 0 → suspicious

### 3.4. `cache.py` — SQLite TTL

Schema đơn:
```sql
CREATE TABLE enrichment (
    ioc_key    TEXT PRIMARY KEY,   -- "virustotal:sha256:abc..."
    provider   TEXT NOT NULL,
    verdict    TEXT NOT NULL,      -- JSON blob
    fetched_at INTEGER NOT NULL
);
```

Get: nếu tồn tại + `now - fetched_at < ttl` → dùng cache; else miss.

Lợi ích: query lại cùng IOC không tốn quota. Với VT free (4 req/min), cache là **thiết yếu** — không có cache thì 100 alert × 3 IOC = 300 IOC × 15s = **75 phút mỗi run**.

### 3.5. `wazuh_client.py` — 30 dòng

Wrapper `requests.Session()` với basic auth + verify=False (self-signed cert). Search chỉ đủ builder cho `bool.must` filter theo level/agent/rule/timerange.

### 3.6. `enrich.py` — orchestrator

- click parse `--min-level -l`, `--agent -a`, `--rule-id -r`, `--since -s`, `--limit -n`, `--dry-run`
- Load `.env` bằng `dotenv`
- Loop: fetch → extract → enrich (with cache) → render
- Rich `console.status()` cho spinner khi enrich

---

## 4. Cách extend

### 4.1. Thêm provider mới (ví dụ Shodan)

Trong `providers.py` add class:
```python
class Shodan:
    BASE = "https://api.shodan.io"
    def __init__(self, api_key): ...
    def lookup(self, ioc_type, value) -> Verdict:
        if ioc_type != "ip": return Verdict(...)  # skip
        r = requests.get(f"{self.BASE}/shodan/host/{value}",
                         params={"key": self.api_key})
        ...
```

Trong `enrich.py`, thêm vào `_enrich_ioc()`:
```python
if ioc.type == "ip":
    v = shodan.lookup(ioc.type, ioc.value)
    verdicts.append(v)
```

### 4.2. Export ra JSONL

Thêm flag `--output enriched.jsonl` vào click, mở file mode `a`, sau mỗi alert:
```python
out.write(json.dumps({
    "alert_id": ea.alert_id, "iocs": [asdict(i) for i in ea.iocs],
    "verdicts": [asdict(v) for lst in enriched.values() for v in lst],
}) + "\n")
```

### 4.3. Chạy liên tục (daemon mode)

Bọc trong loop 5 phút:
```python
while True:
    hits = idx.search(since="now-5m", ...)
    process(hits)
    time.sleep(300)
```

Hoặc dùng systemd timer thay vì loop.

---

## 5. Bảo mật & operational

### 5.1. Secrets

- `.env` — file duy nhất chứa key. Không commit (đã gitignore).
- Nếu chạy trên VPS, khuyến nghị move `.env` ra `/etc/wazuh-enrichment/env` với `chmod 600`, đọc bằng `dotenv_path=...`.
- Rotate key VT/AbuseIPDB mỗi 6 tháng, hoặc ngay khi nghi leak.

### 5.2. Rate-limit & retry

- VT: tool sleep 15.5s giữa call. Nếu API trả 429 → sleep 30s extra (đã handle).
- AbuseIPDB: 1000/day. Tool không tự đếm — theo dõi qua dashboard AbuseIPDB.
- Nếu chạy trên nhiều máy cùng key → tổng quota chia đôi. Không nên.

### 5.3. False positive

- IP có VT report cũ (2-3 năm) có thể đã được reclaim bởi provider hợp pháp. Đọc kỹ `last_analysis_date`.
- Hash file legitimate có thể match "1/91 malicious" do 1 engine false positive. Threshold 15% giúp giảm.

### 5.4. Không làm được

- **Không thay Wazuh custom rule** — tool chỉ enrich, không tự block/isolate. Chain đầy đủ: Wazuh alert → enrichment verdict → analyst quyết định response.
- **Không hỗ trợ URL / email IOC** — chỉ hash/IP/domain. Extend dễ.
- **Không parse alert từ WEC** hay các nguồn không phải Wazuh Indexer.

---

## 6. Recap workflow

```
1. SSH tunnel Kali:9200 → VPS:9200
2. python enrich.py [flags]
3. Tool query Wazuh Indexer
4. Extract IOC unique (dedupe)
5. Với mỗi IOC:
   ├─ Cache hit? → dùng
   └─ Miss → VT + AbuseIPDB → cache
6. Render bảng verdict color-coded
7. Analyst đọc → decide response (block IP, kill process, isolate host)
```

Kết thúc Phase 5, dự án đã đủ giá trị CV:
- ✅ HIDS + Sysmon/auditd telemetry
- ✅ 10 custom rule MITRE
- ✅ **Python enrichment tự động hoá lookup** ← tự động hoá analyst workload

Phase 6 (Atomic Red Team hunting) sẽ demo end-to-end: attack → alert → enrich → report.
