# Phase 7 — Custom Dashboard (Wazuh Dashboard GUI)

> Hướng dẫn build custom dashboard cho dự án blue-team-lab. **Ưu tiên GUI**; CLI ở section 5 để tham khảo.

---

## 0. Kiến thức nền

### 0.1. Wazuh Dashboard là gì?

**Wazuh Dashboard** = fork của **OpenSearch Dashboards** (bản thân là fork của **Kibana**). Đã cài sẵn ở Phase 1. Truy cập: `https://43.228.215.234` (login `admin`).

3 tab quan trọng cho phase này (icon 3 gạch → menu):

| Menu path | Mục đích |
|---|---|
| **Dashboard management → Index patterns** | Định nghĩa "chỗ để đọc data" — pattern như `wazuh-alerts-*` |
| **Visualize** | Vẽ 1 chart/table từ index pattern |
| **Dashboard** | Gom nhiều visualization vào 1 trang |

### 0.2. Data ta có

| Index pattern | Nguồn | Field chính |
|---|---|---|
| `wazuh-alerts-*` | Wazuh Manager alerts (auto-created) | `agent.name`, `rule.id`, `rule.level`, `rule.mitre.id`, `data.win.eventdata.*`, `data.audit.*` |
| `enrichment-verdicts-*` | Custom (Phase 5b) | `ioc_value`, `provider`, `verdict_label`, `score`, `alert_id` |

Verify 2 index pattern có sẵn: Menu → Dashboard management → Index patterns → phải thấy cả 2 dòng. Nếu thiếu `enrichment-verdicts` xem `docs/05b-enrichment-writeback.md` §4.

### 0.3. Mục tiêu

Build **6 visualization** + **1 dashboard tổng hợp** phản ánh mọi giá trị Phase 1-6:

| # | Visualization | Type | Data source | Kể chuyện gì |
|---|---|---|---|---|
| 1 | MITRE Technique Coverage | Data Table | wazuh-alerts | 10 technique nào ta phát hiện, count mỗi cái |
| 2 | Custom Rule Fires (100100-100120) | Vertical bar | wazuh-alerts | Rule nào bắn nhiều, rule nào chưa bao giờ bắn |
| 3 | Enrichment Verdict Distribution | Donut/Pie | enrichment-verdicts | Ratio malicious / suspicious / clean |
| 4 | Top IOCs Enriched | Data Table | enrichment-verdicts | IOC nào nhiều alert nhất |
| 5 | Alerts by Agent (Timeline) | Line | wazuh-alerts | Trend theo thời gian, split by agent |
| 6 | Alerts by Rule Level | Vertical bar | wazuh-alerts | Distribution severity |

---

## 1. Build từng Visualization (GUI)

### 1.1. Visualization 1 — MITRE Technique Coverage

**Mục tiêu**: bảng liệt kê technique MITRE nào detect được, kèm alert count.

**GUI steps**:

1. Menu → **Visualize** → **Create visualization** (góc phải)
2. Chọn type: **Data table**
3. Chọn index pattern: **`wazuh-alerts-*`**
4. Ở panel bên phải:
   - **Metrics** → **Count** (mặc định giữ nguyên)
   - Click **Add** → **Buckets** → **Split rows**
     - Aggregation: **Terms**
     - Field: **`rule.mitre.id`**
     - Order by: **metric: Count**
     - Order: **Descending**
     - Size: **20**
     - Custom label: **MITRE Technique**
5. Click nút **▶ Update** (góc dưới)
6. Kết quả: bảng 2 cột (Technique | Count) — ví dụ:
   ```
   T1547.001    1
   T1053.005    1
   T1059.001    2
   T1550.002    1
   ...
   ```
7. Menu → **Save** → Title: **`BTL - MITRE Technique Coverage`** → Save

### 1.2. Visualization 2 — Custom Rule Fires

**Mục tiêu**: bar chart chỉ 10 custom rule.

**GUI steps**:

1. **Visualize** → Create → **Vertical Bar**
2. Index pattern: **`wazuh-alerts-*`**
3. **Metrics** → **Y-axis** → Count
4. **Buckets** → **X-axis**:
   - Aggregation: **Terms**
   - Field: **`rule.id`**
   - Size: **15**
   - Custom label: **Custom Rule ID**
5. Add filter ngay dưới thanh search (góc trên) — **Add filter**:
   - Field: `rule.id`
   - Operator: **is one of**
   - Values (paste từng cái, tab để tách): `100100, 100101, 100102, 100104, 100105, 100106, 100107, 100108, 100109, 100112, 100115, 100119, 100120`
   - Save filter
6. Update. Kết quả: cột đứng, mỗi cột 1 rule ID.
7. Save: title **`BTL - Custom Rule Fires (100100-100120)`**

> **Ghi chú**: rule ID 100103 (T1021.002) không fire riêng vì bị dedup bởi 100106 (level 14) — normal behavior, xem session 07 report.

### 1.3. Visualization 3 — Enrichment Verdict Distribution

**Mục tiêu**: pie/donut chart tỷ lệ verdict.

**GUI steps**:

1. **Visualize** → Create → **Pie**
2. Index pattern: **`enrichment-verdicts-*`** ← khác với ở trên!
3. **Metrics** → **Slice size** → Count
4. **Buckets** → **Split slices**:
   - Aggregation: **Terms**
   - Field: **`verdict_label`**
   - Size: **5**
   - Custom label: **Verdict**
5. Options tab (bên phải trên) → **Donut**: toggle ON (để có lỗ giữa cho đẹp)
6. Update. Kết quả: 4 màu ứng với `malicious / suspicious / clean / unknown`.
7. Save: **`BTL - Enrichment Verdict Distribution`**

### 1.4. Visualization 4 — Top IOCs Enriched

**Mục tiêu**: bảng top IOC bị flag nhiều nhất.

**GUI steps**:

1. **Visualize** → Create → **Data table**
2. Index pattern: **`enrichment-verdicts-*`**
3. **Metrics** → Count
4. **Buckets** → **Split rows** (thêm **3 buckets liên tiếp**):
   - Bucket 1: Terms — Field `ioc_value` — Size 15 — Custom label **IOC Value**
   - Bucket 2 (click Add → Sub-buckets? Actually just Add Split rows): Terms — Field `provider` — Size 3 — Custom label **Provider**
   - Bucket 3: Terms — Field `verdict_label` — Size 4 — Custom label **Verdict**
5. Update. Kết quả: bảng 4 cột (IOC, Provider, Verdict, Count).
6. Save: **`BTL - Top IOCs Enriched`**

### 1.5. Visualization 5 — Alerts by Agent (Timeline)

**Mục tiêu**: line chart theo thời gian, mỗi agent 1 line.

**GUI steps**:

1. **Visualize** → Create → **Line**
2. Index pattern: **`wazuh-alerts-*`**
3. **Metrics** → **Y-axis** → Count
4. **Buckets** → **X-axis**:
   - Aggregation: **Date Histogram**
   - Field: **@timestamp**
   - Minimum interval: **Auto**
5. **Add sub-buckets** → **Split series**:
   - Sub aggregation: **Terms**
   - Field: **`agent.name`**
   - Size: **5**
   - Custom label: **Agent**
6. Time picker (góc phải trên): **Last 24 hours**
7. Update. Kết quả: đường timeline, mỗi màu 1 agent (vps, win-ep-01, linux-ep-01).
8. Save: **`BTL - Alerts by Agent (Timeline)`**

### 1.6. Visualization 6 — Alerts by Rule Level

**Mục tiêu**: bar histogram severity distribution.

**GUI steps**:

1. **Visualize** → Create → **Vertical Bar**
2. Index pattern: **`wazuh-alerts-*`**
3. **Metrics** → **Y-axis** → Count
4. **Buckets** → **X-axis**:
   - Aggregation: **Terms**
   - Field: **`rule.level`**
   - Order by: **Alphabetical** (để 0→15 theo thứ tự level)
   - Order: **Ascending**
   - Size: **16**
   - Custom label: **Rule Level**
5. Update. Kết quả: bar theo level 3, 5, 7, 8, 10, 12, 14, 15.
6. Save: **`BTL - Alerts by Rule Level`**

---

## 2. Assemble Dashboard (GUI)

Đến đây có 6 saved visualization. Gom vào 1 dashboard:

1. Menu → **Dashboard** → **Create dashboard**
2. Click **Add** (góc trên, cạnh Save)
3. Panel bên phải hiện danh sách visualization đã save → check 6 cái **BTL - ***
4. Đóng panel Add — 6 visualization đã append vào dashboard
5. **Kéo thả để sắp xếp** theo layout đề xuất:

   ```
   ┌─────────────────────────┬─────────────────────────┐
   │ MITRE Technique Coverage│ Custom Rule Fires       │
   │ (top-left, 50% width)   │ (top-right, 50% width)  │
   ├─────────────────────────┼─────────────────────────┤
   │ Verdict Distribution    │ Top IOCs Enriched       │
   │ (33% width)             │ (67% width, wider)      │
   ├─────────────────────────┴─────────────────────────┤
   │ Alerts by Agent Timeline (full width, thấp)       │
   ├─────────────────────────┬─────────────────────────┤
   │ Alerts by Rule Level    │ (empty — có thể add Markdown text) │
   └─────────────────────────┴─────────────────────────┘
   ```

6. **Time picker**: set **Last 24 hours** (hoặc **Last 7 days** nếu muốn xem trend rộng)
7. **Refresh**: 30 seconds (nếu muốn auto refresh)
8. Click **Save** (góc trên phải):
   - Title: **`Blue Team Lab — SOC Overview`**
   - Description: `Custom dashboard: MITRE coverage, custom rule fires, enrichment verdicts, IOC ranking, agent timeline, rule level distribution.`
   - **Store time with dashboard**: ✅ (giữ time picker Last 24h)
   - Save

Xong. Dashboard giờ có URL cố định: menu → Dashboard → **Blue Team Lab — SOC Overview**.

---

## 3. Add Markdown widget (optional — sáng tạo thêm)

Thêm text block giới thiệu dashboard:

1. Trong dashboard đang edit → **Add** → tab **Markdown**
2. Nội dung:
   ```markdown
   # Blue Team Lab — SOC Overview
   
   **Project**: Wazuh 4.9 HIDS + 10 MITRE ATT&CK detection rules + Python IOC enrichment
   
   **Data sources**:
   - `wazuh-alerts-*` — Sysmon + auditd + Windows Security
   - `enrichment-verdicts-*` — VirusTotal + AbuseIPDB verdict
   
   **Custom rules**: 100100 – 100120 (T1003.008, T1021.002, T1053.005, T1059.001, T1074.001, T1087.001, T1543.003, T1547.001, T1550.002, T1562.001)
   
   **Docs**: [github.com/gnid31/blue-team-lab](https://github.com/gnid31/blue-team-lab)
   ```
3. Save panel. Kéo vào góc trên đầu dashboard.

---

## 4. Export dashboard (backup + share)

Sau khi build xong, export sang file `.ndjson` để commit vào repo:

**GUI**:

1. Menu → **Stack Management** (hoặc "Dashboard management") → **Saved objects**
2. Click **Export** (góc phải)
3. Check các item:
   - Index patterns: `wazuh-alerts-*`, `enrichment-verdicts-*`
   - Visualizations: 6 cái **BTL - ***
   - Dashboards: **Blue Team Lab — SOC Overview**
4. Bật toggle **Include related objects** (để tự động include references)
5. Click **Export** → download file `export.ndjson`
6. Rename → `dashboard/blue-team-lab.ndjson`
7. Copy vào repo:
   ```bash
   scp namth@43.228.215.234:~/export.ndjson dashboard/blue-team-lab.ndjson
   git add dashboard/blue-team-lab.ndjson
   git commit -m "dashboard: export saved objects (6 viz + 1 dashboard)"
   ```

---

## 5. CLI equivalent (reference)

Nếu muốn scripted rebuild sau này, gọi Saved Objects API trên port 443:

```bash
# Import từ ndjson (upload)
curl -sk -u "admin:$PASS" -H "osd-xsrf: true" \
  -F "file=@dashboard/blue-team-lab.ndjson" \
  "https://43.228.215.234/api/saved_objects/_import?overwrite=true"

# Export bulk
curl -sk -u "admin:$PASS" -H "osd-xsrf: true" -H "Content-Type: application/json" \
  -X POST "https://43.228.215.234/api/saved_objects/_export" \
  -d '{"type":["visualization","dashboard","index-pattern"],"includeReferencesDeep":true}' \
  > dashboard/blue-team-lab.ndjson

# Delete 1 object (nếu cần rebuild)
curl -sk -u "admin:$PASS" -H "osd-xsrf: true" \
  -X DELETE "https://43.228.215.234/api/saved_objects/visualization/btl-viz-mitre"
```

Docs API: https://opensearch.org/docs/latest/dashboards/management/saved-objects/

---

## 6. Screenshot cho CV / README

Sau khi dashboard hoạt động, **screenshot** để nhúng vào CV / GitHub README:

**GUI**:

1. Time picker → **Last 24 hours** (để có data đầy đủ)
2. Chrome/Firefox → **F11** full-screen
3. **Print Screen** hoặc `Shift+PrintScreen` chọn window
4. Save vào `dashboard/screenshots/overview.png`

**Recommend** capture các state:
- `overview.png` — full dashboard 24h view
- `mitre-close.png` — zoom MITRE table
- `verdict-pie.png` — verdict distribution với legend
- `timeline.png` — agent timeline

Reference trong README:
```markdown
## Dashboard preview

![SOC Overview](dashboard/screenshots/overview.png)
```

---

## 7. Troubleshooting

| Triệu chứng | Nguyên nhân | Fix |
|---|---|---|
| Visualization "No results found" | Time picker sai — data ở ngoài range | Đổi Last 24h / Last 7 days |
| MITRE technique bucket rỗng | `rule.mitre.id` chưa được index như keyword | Refresh index pattern (Index patterns → wazuh-alerts → refresh field list) |
| Pie chart 100% "unknown" | Data cache cũ — chưa có enrichment mới | Chạy lại `python enrich.py --writeback` |
| Filter `is one of` không apply | Wazuh Dashboard field type strict — thử `is` cho từng ID | Dùng KQL query trực tiếp: `rule.id : (100100 or 100101 or ...)` |
| Dashboard load chậm | Time range quá rộng | Set Last 24h hoặc Last 7 days, tránh Last year |

---

## 8. Ghi log

Sau khi hoàn thành:

```
## 2026-XX-XX HH:MM | human | kali+dashboard | phase7
- what: build 6 BTL visualization + 1 dashboard "Blue Team Lab — SOC Overview" trong Wazuh Dashboard
- result: ok — dashboard live tại /app/dashboards#/view/blue-team-lab-overview; exported .ndjson vào repo
- next: screenshot cho CV
```

---

## 9. Đề xuất extension sau

Nếu muốn cải tiến dashboard:

1. **Alerts vs Enrichment join** — dùng OpenSearch join query (script hoặc Vega custom viz) để hiển thị **alert kèm verdict** trong 1 row
2. **MITRE ATT&CK Navigator export** — dùng viz 1 làm data source, generate JSON theo format ATT&CK Navigator layer → import vào navigator.mitre.org
3. **Auto-alert email** — cấu hình Wazuh Dashboard Alerting plugin để email khi rule level ≥ 14 fire
4. **Vega custom visualization** — cho phép chart phức tạp hơn (Sankey flow của attack chain, force-directed IOC graph)

Xem docs OpenSearch Dashboards: https://opensearch.org/docs/latest/dashboards/
