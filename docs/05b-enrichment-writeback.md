# Phase 5b — Enrichment writeback vào Wazuh Indexer

> Extension của Phase 5. Cho phép verdict VT/AbuseIPDB **persistent** trong Indexer → analyst xem trên Dashboard cạnh alert gốc.

---

## 0. Tại sao?

Phase 5 base chỉ in verdict lên console → khi tắt terminal là mất. Analyst khác mở Dashboard vẫn thấy alert "raw" không có TI context.

Option A: ghi verdict vào **1 index OpenSearch riêng** (`enrichment-verdicts-*`), Dashboard tạo index pattern → search song song với `wazuh-alerts-*`. Verdict trở thành **first-class document** trong SIEM.

## 1. Kiến trúc bổ sung

```
                                       ┌──────────────────────┐
                                       │  Wazuh Indexer       │
                                       │                      │
enrich.py --writeback  ──HTTPS PUT──►  │  wazuh-alerts-*      │
                       (nếu --wb)      │  enrichment-verdicts-*  ◄── mới
                                       └──────────▲───────────┘
                                                  │
                                                  │ Dashboard "Discover" hoặc
                                                  │ custom visualization
                                                  ▼
                                              analyst
```

Mỗi verdict → 1 document JSON riêng, không sửa alert gốc (an toàn, không side effect).

## 2. Sử dụng

Thêm `--writeback` (hoặc `--wb`) vào lệnh cũ:

```bash
.venv/bin/python enrich.py -r 2502 -s now-24h -n 5 --writeback
```

Tool sẽ:
1. Fetch + enrich như bình thường
2. Sau khi render console, tự động `PUT _index_template/enrichment-verdicts-template` (idempotent — không lỗi nếu template đã tồn tại)
3. Với mỗi verdict → `POST /enrichment-verdicts-YYYY.MM.DD/_doc {...}` (index mỗi ngày 1 file)
4. In `Writeback: indexed N verdicts …`

## 3. Cấu trúc document `enrichment-verdicts`

```json
{
  "@timestamp": "2026-07-13T10:43:53Z",
  "alert_id": "rnwPW58BURcMXD9z97Ff",
  "alert_timestamp": "2026-07-13T10:39:57.519Z",
  "agent_name": "vps",
  "rule_id": "2502",
  "rule_level": 10,
  "rule_description": "syslog: User missed the password more than one time",
  "mitre": ["T1110"],
  "ioc_type": "ip",
  "ioc_value": "45.148.10.151",
  "ioc_source_field": "data.srcip",
  "provider": "virustotal",
  "verdict_label": "malicious",
  "malicious": 17,
  "total": 91,
  "score": "17/91",
  "link": "https://www.virustotal.com/gui/ip-address/45.148.10.151"
}
```

Ý nghĩa field:
- `alert_id` — join key sang `wazuh-alerts-*` document (khớp `_id` alert Wazuh)
- `ioc_source_field` — nơi extract IOC trong alert gốc (VD `data.srcip`, `data.win.eventdata.commandLine`)
- `verdict_label` — enum `clean | suspicious | malicious | unknown` — dùng để filter/color map
- `link` — clickable link tới trang provider

## 4. Tạo index pattern trong Dashboard (GUI + CLI)

### GUI (khuyến nghị lần đầu)

1. Login `https://43.228.215.234` (admin)
2. Menu (icon 3 gạch) → **Dashboard management** → **Index patterns**
3. Nút **Create index pattern**
4. Ô "Index pattern name": gõ `enrichment-verdicts-*` → button "Next step"
5. "Time field": chọn `@timestamp` → **Create index pattern**
6. Xong. Dashboard giờ recognise index này.

### CLI (cho ai muốn scriptable)

```bash
# Tạo saved-object index pattern qua Dashboard API
curl -sk -u "admin:$WAZUH_DASHBOARD_PASS" \
  -H "osd-xsrf: true" -H "Content-Type: application/json" \
  -X POST "https://43.228.215.234/api/saved_objects/index-pattern/enrichment-verdicts" \
  -d '{"attributes":{"title":"enrichment-verdicts-*","timeFieldName":"@timestamp"}}'
```

## 5. Xem verdict trên Dashboard

### 5.1. Discover

1. Menu → **Discover**
2. Chọn index pattern `enrichment-verdicts-*` (dropdown góc trên trái)
3. Set time range → **Last 24 hours**
4. Thấy list verdict. Click 1 document → expand.
5. Add column: `ioc_value`, `provider`, `verdict_label`, `score`, `rule_id`

### 5.2. Filter nhanh

Trong ô search Discover:
```
verdict_label : "malicious" AND provider : "virustotal"
```
```
ioc_type : "ip" AND agent_name : "vps"
```

### 5.3. Correlation với alert gốc

Query 1 alert Wazuh cụ thể + verdict tương ứng bằng cách join qua `alert_id`:

```bash
# Xem alert
GET /wazuh-alerts-*/_doc/rnwPW58BURcMXD9z97Ff

# Xem verdict cho alert đó
GET /enrichment-verdicts-*/_search
{"query": {"match": {"alert_id": "rnwPW58BURcMXD9z97Ff"}}}
```

## 6. Visualization (tuỳ chọn)

Dashboard → **Visualize** → tạo:

- **Data table**: top 10 IOC malicious (aggregation `Terms` trên `ioc_value`, filter `verdict_label:malicious`)
- **Pie chart**: verdict distribution (`Terms` trên `verdict_label`)
- **Line chart**: verdict count theo thời gian (`Date histogram` trên `@timestamp`)
- **Metric**: tổng verdict malicious 24h (`Filter` `verdict_label:malicious`, `Count`)

Save → thêm vào **Dashboard** riêng "IOC Enrichment Overview".

## 7. Retention

Index `enrichment-verdicts-YYYY.MM.DD` được tạo mỗi ngày. Sau vài tháng sẽ ăn disk.

Cleanup thủ công:
```bash
# Xoá index cũ hơn 30 ngày
DATE=$(date -d '30 days ago' +%Y.%m.%d)
curl -sk -u "admin:$PASS" -X DELETE "https://localhost:9200/enrichment-verdicts-$DATE"
```

Hoặc cấu hình **ISM policy** (Index State Management) trong OpenSearch:
```json
POST _plugins/_ism/policies/enrichment-cleanup
{
  "policy": {
    "default_state": "hot",
    "states": [{
      "name": "hot",
      "transitions": [{"state_name": "delete", "conditions": {"min_index_age": "30d"}}]
    },{
      "name": "delete",
      "actions": [{"delete": {}}]
    }]
  }
}
```

## 8. Bảo mật

- Verdict document chứa `link` → khi analyst click sẽ mở VT/AbuseIPDB, không có credential nào lộ.
- User Dashboard read-only vẫn xem được nếu grant `enrichment-verdicts-*` vào role — cấu hình trong `Security → Roles`.
- **Không log API key** trong document (đã cẩn thận, chỉ ghi verdict + link công khai).

## 9. Rollback

Nếu muốn tắt writeback: bỏ flag `--writeback` khi chạy. Data đã ghi vẫn còn — xoá thủ công bằng:
```bash
curl -sk -u "admin:$PASS" -X DELETE "https://localhost:9200/enrichment-verdicts-*"
curl -sk -u "admin:$PASS" -X DELETE "https://localhost:9200/_index_template/enrichment-verdicts-template"
```

## 10. Ghi log

```
## 2026-XX-XX HH:MM | human | kali | phase5b
- what: enable writeback (--writeback flag), tạo index pattern `enrichment-verdicts-*` trong Dashboard
- result: ok — N verdict indexed, Discover query malicious=X
- next: (Phase 6 hoặc analyst dùng flow này daily)
```
