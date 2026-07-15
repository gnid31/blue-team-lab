# Phase 7 — Custom Dashboards (Wazuh Dashboard GUI)

> **3 dashboard persona-based**. Ưu tiên GUI; CLI section 8.
>
> **Verified on**: Wazuh 4.9.2 + OpenSearch Dashboards **2.13.0** (query `/api/status` để xác nhận version của bạn).

---

## Filter & Query — cách dùng đúng trong OpenSearch Dashboards 2.13

Section này gộp thành **1 chỗ** để tránh lặp trong từng viz. Đọc kỹ trước khi build.

### F.1. Query language

**DQL (Dashboards Query Language)** — mặc định. Không phải KQL (Kibana). Cú pháp gần giống nhưng có khác biệt.

Toggle DQL / Lucene: ở **query bar** (thanh search bar trên đầu Discover / Visualize / Dashboard) có button nhỏ **"DQL"** — click để chuyển sang Lucene nếu cần.

### F.2. DQL syntax cần nhớ

```
field : value                    # single value match
field : "value with space"       # quote nếu có space
field : (v1 or v2 or v3)         # multiple values (case-insensitive keyword or/and/not)
field : *                        # exists (non-null)
NOT field : value                # negation
field1 : v1 and field2 : v2      # combine AND
field.subfield : value           # dotted path OK
field : 100*                     # wildcard (chỉ với keyword field, không phải text field)
field > 100                      # range (chỉ với numeric field)
field >= "2026-07-13"            # date range
```

### F.3. Field type quan trọng cần biết

| Field | Type | DQL query mẫu |
|---|---|---|
| `rule.id` | **keyword (string)** | `rule.id : "100100"` hoặc `rule.id : 100100` (không quote OK), wildcard `rule.id : 1001*` |
| `rule.level` | **long (integer)** | `rule.level >= 12` |
| `agent.name` | keyword | `agent.name : "win-ep-01"` |
| `rule.mitre.id` | keyword | `rule.mitre.id : "T1059.001"` |
| `@timestamp` | date | `@timestamp >= "now-24h"` |
| `data.win.eventdata.commandLine` | text (searchable) | `data.win.eventdata.commandLine : *EncodedCommand*` |
| `data.audit.exe` | keyword | `data.audit.exe : "/usr/bin/cat"` |

Verify field type: **Dashboard management → Index patterns → chọn pattern → tab Fields** → cột "Type".

### F.4. 2 cách filter data — chọn cái nào?

**Cách 1: DQL trong Query Bar (recommended cho phức tạp / nhiều value)**

Query bar = thanh dài trên đầu, có placeholder "DQL". Gõ trực tiếp:

```
rule.id : (100100 or 100101 or 100102 or 100104 or 100105 or 100106 or 100107 or 100108 or 100109 or 100112 or 100115 or 100119 or 100120)
```

Enter → filter apply ngay. Query lưu vào URL, có thể share.

**Ưu**: gọn, share được, dễ edit.
**Nhược**: cần biết cú pháp DQL.

**Cách 2: "Add filter" button (GUI, recommended cho single condition)**

Click **`+ Add filter`** (nút cạnh query bar, có icon dấu cộng) → mở modal:

```
┌─── Edit filter ─────────────────────────────┐
│ Field:      [ rule.id            ▼ ]         │
│ Operator:   [ is one of          ▼ ]         │
│ Values:     [ 100100 ⓧ ] [100101 ⓧ] [+ ...] │
│             (gõ value, Enter để add chip)   │
│                                              │
│ □ Custom label (optional):                   │
│   [ Custom rules 100XXX               ]      │
│                                              │
│ [ Edit query DSL ▼ ]  [ Cancel ] [ Save ]   │
└──────────────────────────────────────────────┘
```

Operator options trong OSD 2.13:

- `is`
- `is not`
- **`is one of`** ← dùng cho multi-value discrete
- `is not one of`
- `exists` (field non-null)
- `does not exist`
- `is between` (range)
- `is not between`

Với **13 rule ID** → dùng "is one of" phải gõ 13 lần Enter → tedious. Nên dùng Cách 1 (DQL query bar).

**Ưu Cách 2**: không cần biết cú pháp, có validation.
**Nhược**: chậm với nhiều value, khó edit sau khi save.

### F.5. Cách shortcut cho custom rules 100100-100120

Vì `rule.id` là keyword, có 3 cách filter tất cả custom rules:

| Cách | DQL query | Bắt được | Ghi chú |
|---|---|---|---|
| **Wildcard đơn** | `rule.id : 1001*` | Tất cả `1001xx` (100100-100199) | **Ngắn gọn nhất**, khớp scope custom range đúng |
| Explicit OR | `rule.id : (100100 or 100101 or ...)` | Chỉ ID liệt kê | An toàn nhất khi range không liên tục |
| Filter modal "is one of" | (Add filter → is one of → gõ từng ID) | Chỉ ID nhập | Dùng khi ít value và cần GUI |

**Khuyến nghị cho dự án này**: dùng `rule.id : 1001*` — vì convention của repo là 100100-100199 → wildcard match đúng scope.

### F.6. Filter vs "Buckets → Split" trong Visualize builder

Đừng nhầm 2 chỗ khác nhau:

- **Top query bar / Add filter**: filter DATA đưa vào visualization (mọi document phải match).
- **Buckets → Split rows / Split series / X-axis**: chia data thành nhóm để aggregate (Terms, Date Histogram, Range, ...).

VD: muốn "bar chart của 13 custom rule".
- Cách đúng: filter `rule.id : 1001*` ở query bar + bucket Terms field `rule.id` size 15
- Cách sai: bỏ filter, chỉ dùng bucket Terms — sẽ show top 15 rule bất kỳ (mostly built-in noise)

### F.7. Global (dashboard-wide) vs Panel-level filter

- Filter đặt trên **Dashboard** → apply cho **mọi panel** trong dashboard đó.
- Filter đặt trên **Visualize** (edit 1 viz) → chỉ áp cho viz đó, được **lưu vào saved object của viz**.

Nếu build 3 dashboards trong section 2-4 dưới, filter "custom rule range" nên đặt ở **panel level (Visualize)** vì mỗi dashboard cần scope khác nhau.

---

## 0. Kiến thức nền + design principles

### 0.1. Wazuh Dashboard = OpenSearch Dashboards fork

Đã cài Phase 1 tại `https://43.228.215.234`. 3 menu quan trọng:

| Menu | Mục đích |
|---|---|
| **Dashboard management → Index patterns** | Định nghĩa nguồn data (`wazuh-alerts-*`, `enrichment-verdicts-*`) |
| **Visualize** | Vẽ 1 chart |
| **Dashboard** | Gom nhiều chart |

### 0.2. Nguyên tắc thiết kế dashboard

Trước khi build, nắm 7 nguyên tắc — quyết định 1 dashboard tốt hay tệ.

**1. Audience-first** — không có "1 dashboard cho tất cả". Persona quyết định:

| Persona | Cần gì | Time-context |
|---|---|---|
| L1 SOC Analyst | Alert queue + triage | Real-time (last 15 min) |
| Threat Hunter / Detection Engineer | Rule performance + hunt data | Historical (24h - 7d) |
| SOC Manager | KPIs, coverage, SLA | Weekly/monthly |
| CISO / Exec | Risk posture, top threat | Monthly |

**Dự án này** = threat hunter + detection engineer + demo cho recruiter → **KHÔNG** phải L1 real-time alert queue.

**2. 5-second rule** — user nhìn 5s phải hiểu ngay tình hình + action gì cần làm.

**3. Actionable > descriptive** — mỗi viz trả lời "vì cái này tôi làm gì?":
- ❌ "Alert count by level" — biết để làm gì?
- ✅ "5 critical unacknowledged >15 min" — call to action

**4. Information hierarchy (F-pattern)** — top-left = quan trọng nhất; right & bottom = detail.

**5. Data-ink ratio (Tufte)** — maximize data pixels, minimize chartjunk. Không 3D, không background gradient.

**6. Baseline / threshold** — trending up có tốt/xấu? Cần reference line hoặc SLA target, không show con số trần.

**7. Time-boxed context** — mỗi dashboard 1 time frame rõ ràng, không lộn xộn.

### 0.3. Standards / frameworks tham chiếu

Không có ISO/NIST standard riêng cho SOC dashboard, nhưng các reference:

| Framework | Lĩnh vực | Dùng gì cho dự án này |
|---|---|---|
| **Stephen Few** — "Information Dashboard Design" | Sách kinh điển | 13 lỗi thường gặp; layout principles |
| **Edward Tufte** — "Visual Display of Quantitative Info" | Sách kinh điển | Data-ink ratio, sparkline |
| **Google SRE — 4 Golden Signals** | Ops monitoring | Rate/Errors/Duration/Saturation áp cho SOC = Alerts/hour / FP rate / MTTD / Analyst workload |
| **SOC-CMM** (Rob van Os) | SOC maturity model | Domain metrics list dashboard-able |
| **MITRE ATT&CK Navigator** | Detection coverage | Heatmap technique coverage |
| **NIST CSF Detect function** | Framework governance | Category DE.CM (Continuous Monitoring) metrics |

---

## 1. 3 Dashboard tách biệt theo persona

### 1.1. Overview

| Dashboard | Persona | Time frame | Audience question trả lời |
|---|---|---|---|
| **A. Detection Engineering** | Detection engineer / threat hunter | Last 7 days | "Rule của tôi có hoạt động không? Đang miss technique nào?" |
| **B. Hunt Support** | Threat hunter khi trong session | Last 24 hours | "Attack đang xảy ra? IOC nào cần block? Correlation gì có sẵn?" |
| **C. Lab Health / Executive** | Recruiter, interviewer, CISO | Last 7 days | "Dự án này produce gì? Coverage rộng không? Nghiêm túc không?" |

### 1.2. Data source & metrics

| Metric | Source | Dùng ở dashboard |
|---|---|---|
| `rule.mitre.id` | wazuh-alerts-* | A, C |
| `rule.id` (custom range 100100-100120) | wazuh-alerts-* | A |
| `rule.level` | wazuh-alerts-* | A, C |
| `agent.name` | wazuh-alerts-* | B, C |
| `data.win.eventdata.*` / `data.audit.*` | wazuh-alerts-* | B (drill-down) |
| `verdict_label`, `ioc_value`, `provider` | enrichment-verdicts-* | B, C |
| `@timestamp` | both | A, B, C |

---

## 2. Dashboard A — Detection Engineering

**Persona**: người viết rule, muốn biết rule có hoạt động và có gap gì.

**Layout**:
```
┌──────────────────────────────┬──────────────────────────────┐
│ A1. Custom Rule Performance  │ A2. MITRE ATT&CK Coverage    │
│ (data table)                 │ (heatmap or matrix table)    │
├──────────────────────────────┴──────────────────────────────┤
│ A3. Custom Rule Fires Timeline (multi-line 100100-100120)   │
├──────────────────────────────┬──────────────────────────────┤
│ A4. Coverage Gap             │ A5. Rule Level Distribution  │
│ (table: built-in fires but   │ (bar histogram)              │
│  no custom rule for same TT) │                              │
└──────────────────────────────┴──────────────────────────────┘
```

### A1 — Custom Rule Performance (table)

**Question**: rule nào fire, rule nào chưa bao giờ, last fire khi nào?

**GUI**:

1. Visualize → Create → **Data table**
2. Index pattern: `wazuh-alerts-*`
3. Time picker: **Last 7 days**
4. Buckets → **Split rows**:
   - Terms — field `rule.id` — size 20 — Custom label "Rule ID"
5. Add sub-metric (top-right corner "+" trong metric panel):
   - **Max** → field `@timestamp` → Custom label "Last fire"
6. Filter custom rule range — trong **query bar** trên đầu, gõ:
   ```
   rule.id : 1001*
   ```
   Enter. (Xem section F.5 để hiểu tại sao wildcard tốt hơn "is one of".)
7. Save: **`BTL-A1 Custom Rule Performance`**

### A2 — MITRE ATT&CK Coverage (heatmap)

**Question**: technique nào cover, count bao nhiêu?

**GUI**:

1. Visualize → Create → **Heat map** (nếu không có, dùng Data table)
2. Index pattern: `wazuh-alerts-*`
3. Metrics → Value: Count
4. Buckets → **Y-axis**: Terms — field `rule.mitre.tactic` — size 12
5. Buckets → **X-axis**: Terms — field `rule.mitre.id` — size 30
6. Save: **`BTL-A2 MITRE ATT&CK Coverage`**

> **Trick nâng cao**: dùng Vega custom visualization để render đúng theo layout ATT&CK Navigator. Docs: https://opensearch.org/docs/latest/dashboards/visualize/vega/

### A3 — Custom Rule Fires Timeline (multi-line)

**Question**: rule nào có FP trend spike?

**GUI**:

1. Visualize → **Line**
2. Index pattern: `wazuh-alerts-*`
3. Filter query bar: `rule.id : 1001*` (giống A1)
4. X-axis: Date Histogram — `@timestamp` — Auto
5. Split series: Terms — `rule.id` — size 15
6. Save: **`BTL-A3 Custom Rule Fires Timeline`**

### A4 — Coverage Gap (table)

**Question**: technique nào có alert built-in Wazuh mà **không có** rule custom mapping?

**GUI**:

1. Visualize → **Data table**
2. Index pattern: `wazuh-alerts-*`
3. Filter query bar: `NOT rule.id : 1001*` — loại trừ custom rule (chỉ giữ built-in)
4. Buckets → Split rows: Terms — `rule.mitre.id` — size 30
5. Sort desc by Count
6. Save: **`BTL-A4 Coverage Gap (Built-in vs Custom)`**

> **Note**: `rule.id < 100000` KHÔNG work vì `rule.id` là **keyword** (không phải numeric). Phải dùng `NOT rule.id : 1001*` hoặc "is not one of" filter modal.

**Cách dùng**: so sánh với A2 — technique nào có trong A4 mà không có trong A2 = gap → cần viết rule custom mới.

### A5 — Rule Level Distribution (bar)

**Question**: tỷ lệ level severity của rule custom (kiểm tra không "level inflation")?

**GUI**:

1. Visualize → **Vertical Bar**
2. Index pattern: `wazuh-alerts-*`
3. Filter query bar: `rule.id : 1001*` (chỉ custom rule)
4. X-axis: Terms — `rule.level` — order asc — size 16 — Custom label "Level"
5. Save: **`BTL-A5 Rule Level Distribution`**

### Assemble Dashboard A

1. Dashboard → Create → Add → chọn 5 viz **BTL-A***
2. Layout theo sơ đồ ở trên (kéo thả)
3. Time picker: **Last 7 days**
4. Save: **`Blue Team Lab — A. Detection Engineering`**

---

## 3. Dashboard B — Hunt Support

**Persona**: threat hunter trong session, cần visibility real-time.

**Layout**:
```
┌──────────────────────────────┬──────────────────────────────┐
│ B1. Enrichment Verdict       │ B2. Top Malicious IOCs       │
│ (donut, 24h)                 │ (data table with VT link)    │
├──────────────────────────────┴──────────────────────────────┤
│ B3. Alerts by Agent Timeline (multi-line, 24h)              │
├──────────────────────────────┬──────────────────────────────┤
│ B4. Top Users / Process      │ B5. Cross-agent Correlation  │
│ (data table)                 │ (technique + multi-agent)    │
└──────────────────────────────┴──────────────────────────────┘
```

### B1 — Enrichment Verdict (donut)

**Question**: trong 24h enrichment vừa chạy, có bao nhiêu malicious?

**GUI**:

1. Visualize → **Pie**
2. Index pattern: **`enrichment-verdicts-*`**
3. Slice size: Count
4. Split slices: Terms — `verdict_label` — size 4
5. Options → **Donut: ON**
6. Time picker: Last 24h
7. Save: **`BTL-B1 Enrichment Verdict`**

### B2 — Top Malicious IOCs (table)

**Question**: IOC nào cần block/investigate ngay?

**GUI**:

1. Visualize → **Data table**
2. Index pattern: `enrichment-verdicts-*`
3. Filter query bar: `verdict_label : "malicious"`
4. Split rows:
   - Bucket 1: Terms — `ioc_value` — size 20
   - Bucket 2: Terms — `provider` — size 3
   - Bucket 3: Terms — `link` — size 1 (để hiển thị link)
5. Save: **`BTL-B2 Top Malicious IOCs`**

**Trick clickable link**: OpenSearch Dashboards **field format** — Index patterns → enrichment-verdicts → field `link` → set format = **Url** → template `{{value}}`. Sau đó bảng sẽ render link click được.

### B3 — Alerts by Agent Timeline (line)

**Question**: agent nào bùng phát alert?

**GUI**:

1. Visualize → **Line**
2. Index pattern: `wazuh-alerts-*`
3. Filter query bar: `rule.level >= 7` (chỉ alert đáng chú ý — `rule.level` là numeric nên `>=` work)
4. X-axis: Date Histogram — `@timestamp` — 30 min
5. Split series: Terms — `agent.name` — size 5
6. Time picker: Last 24h
7. Save: **`BTL-B3 Alerts by Agent`**

### B4 — Top Users / Processes (table)

**Question**: user/process nào có nhiều alert nhất → suspicious behavior candidate?

**GUI**:

1. Visualize → **Data table**
2. Index pattern: `wazuh-alerts-*`
3. Split rows:
   - Bucket 1: Terms — `data.win.eventdata.user` — size 10
   - Bucket 2: Terms — `data.win.eventdata.image` — size 3
4. Sort desc Count
5. Save: **`BTL-B4 Top Users & Processes`**

### B5 — Cross-agent Correlation

**Question**: cùng technique fire trên nhiều agent = attack chain?

**GUI**:

1. Visualize → **Data table**
2. Index pattern: `wazuh-alerts-*`
3. Filter query bar: `rule.level >= 7`
4. Metric → **Add** → **Unique Count** → field `agent.name` → Custom label "Unique agents"
5. Buckets → Split rows: Terms — `rule.mitre.id` — size 20 — Order by "Unique agents" metric desc
6. Sort → technique có unique agents ≥ 2 = correlation signal
7. Save: **`BTL-B5 Cross-agent Correlation`**

### Assemble Dashboard B

1. Dashboard → Create → Add → 5 viz **BTL-B***
2. Time picker: **Last 24 hours**
3. Auto-refresh: **30 seconds** (real-time feel)
4. Save: **`Blue Team Lab — B. Hunt Support`**

---

## 4. Dashboard C — Lab Health / Executive

**Persona**: recruiter, interviewer, CISO. Cần "5-second story".

**Layout**:
```
┌─────┬─────┬─────┬─────┐  ← 4 big number panels (top row)
│ 4K  │ 10  │  3  │ 87% │
│Alert│Tech │Agent│Cover│
└─────┴─────┴─────┴─────┘
┌──────────────────────────────────────────────────────────────┐
│ C5. MITRE ATT&CK Coverage Heatmap (full width)              │
├──────────────────────────────┬───────────────────────────────┤
│ C6. Timeline last 7d         │ C7. Verdict Distribution      │
│ (line)                       │ (donut)                       │
└──────────────────────────────┴───────────────────────────────┘
```

### C1-C4 — Big Number Panels

**Question**: 5s snapshot.

**GUI cho C1 (Total alerts)**:

1. Visualize → **Metric**
2. Index pattern: `wazuh-alerts-*`
3. Metric: Count
4. Options → **Show title**: OFF (chỉ số)
5. Font size: 60 (lớn)
6. Time picker: Last 7 days
7. Save: **`BTL-C1 Total Alerts`**

**C2 — Unique techniques**:
1. Metric type → **Unique Count** (cardinality)
2. Field: `rule.mitre.id`
3. Save: **`BTL-C2 Techniques Detected`**

**C3 — Unique agents monitored**:
1. Metric type → **Unique Count**
2. Field: `agent.name`
3. Save: **`BTL-C3 Agents Monitored`**

**C4 — Enrichment coverage %**:
- Complex — cần **Percentile aggregation** hoặc dùng TSVB (Time Series Visual Builder)
- Simplified: chỉ show enrichment total count (từ enrichment-verdicts-*)
- Save: **`BTL-C4 Enrichment Verdicts Written`**

### C5 — MITRE ATT&CK Coverage Heatmap

Reuse **BTL-A2** hoặc build lại với Vega custom cho layout ATT&CK Navigator-style.

### C6 — Alerts Timeline 7d

Reuse **BTL-A3** hoặc simplified single-line (total count không split).

### C7 — Verdict Distribution 7d

Same as **BTL-B1** nhưng time frame Last 7 days.

### Assemble Dashboard C

1. Dashboard → Create → Add
2. Layout: 4 big numbers row top, MITRE heatmap giữa, 2 chart bottom
3. **Markdown widget** cho intro:
   ```markdown
   # Blue Team Lab — Threat Detection Overview
   
   Wazuh 4.9 HIDS + 15 custom rules mapped MITRE ATT&CK + Python IOC enrichment (VirusTotal + AbuseIPDB)
   
   Repo: [github.com/gnid31/blue-team-lab](https://github.com/gnid31/blue-team-lab)
   ```
4. Time picker: **Last 7 days**
5. Save: **`Blue Team Lab — C. Overview (Executive)`**

---

## 5. Navigation between dashboards

Wazuh Dashboard cho phép link giữa dashboards qua **Markdown** widget hoặc **Dashboard-only mode**:

Trong Dashboard C, thêm markdown block:
```markdown
🔍 **Drill down**:
- [Detection Engineering →](#/dashboards/view/blue-team-lab-a)
- [Hunt Support →](#/dashboards/view/blue-team-lab-b)
```

(URL slug tuỳ theo bạn đặt khi save)

---

## 6. Export cả 3 dashboards (backup)

**GUI**:

1. Menu → **Stack Management** → **Saved objects**
2. Search bar: gõ `BTL-` — filter toàn bộ visualization + dashboard của lab
3. Check all → **Export** (góc phải)
4. Bật toggle **Include related objects**
5. Download `export.ndjson`
6. Rename → `dashboard/blue-team-lab-all.ndjson`
7. Commit:
   ```bash
   scp namth@43.228.215.234:~/export.ndjson dashboard/blue-team-lab-all.ndjson
   git add dashboard/blue-team-lab-all.ndjson
   git commit -m "dashboard: export 3 persona dashboards (Detection Engineering + Hunt Support + Executive)"
   ```

---

## 7. Screenshot cho CV / README

Với 3 dashboards, screenshot theo priority:

1. **Dashboard C** (Executive) — screenshot chính cho **README hero image** — trực quan nhất
2. **Dashboard A** — screenshot cho phần "Detection Engineering" của CV
3. **Dashboard B** — chỉ screenshot khi có session hunting đang chạy (data phong phú)

Save:
```
dashboard/screenshots/
├── C-executive-overview.png    ← hero image
├── A-detection-engineering.png
└── B-hunt-support.png
```

README embed:
```markdown
## Dashboard preview

![Executive Overview](dashboard/screenshots/C-executive-overview.png)
```

---

## 8. CLI equivalent (reference)

```bash
# Import từ ndjson
curl -sk -u "admin:$PASS" -H "osd-xsrf: true" \
  -F "file=@dashboard/blue-team-lab-all.ndjson" \
  "https://43.228.215.234/api/saved_objects/_import?overwrite=true"

# Export toàn bộ visualization + dashboard
curl -sk -u "admin:$PASS" -H "osd-xsrf: true" -H "Content-Type: application/json" \
  -X POST "https://43.228.215.234/api/saved_objects/_export" \
  -d '{"type":["visualization","dashboard","index-pattern"],"includeReferencesDeep":true}' \
  > dashboard/blue-team-lab-all.ndjson

# Delete 1 dashboard để rebuild sạch
curl -sk -u "admin:$PASS" -H "osd-xsrf: true" \
  -X DELETE "https://43.228.215.234/api/saved_objects/dashboard/blue-team-lab-a"
```

API docs: https://opensearch.org/docs/latest/dashboards/management/saved-objects/

---

## 9. Troubleshooting

| Triệu chứng | Nguyên nhân | Fix |
|---|---|---|
| Viz "No results found" | Time range sai | Đổi Last 24h / 7d |
| `rule.mitre.id` bucket empty | Field chưa index như keyword | Menu → Index patterns → wazuh-alerts → Refresh field list |
| Heatmap không load | Data quá spare (ít technique) | Cần thêm data — chạy thêm session hunt |
| "Include related objects" export ra file rỗng | Không có object nào được select | Search "BTL-" trước, check all |
| Field format URL không render link | Cần bật trong index pattern setting | Index patterns → enrichment-verdicts → field `link` → Edit → Format: Url |

---

## 10. Ghi log

```
## 2026-XX-XX HH:MM | human | kali+dashboard | phase7
- what: build 3 dashboards (A Detection Engineering, B Hunt Support, C Executive Overview) với ~13 visualization tổng
- result: ok — 3 dashboards live, exported .ndjson, screenshots vào dashboard/screenshots/
- next: embed screenshot vào README, PR review
```

---

## 11. Đề xuất extension

Sau khi 3 dashboards work:

1. **MITRE ATT&CK Navigator export** — build 1 script Python đọc `wazuh-alerts-*` → output JSON theo format navigator.mitre.org
2. **Vega custom viz** — thay heatmap default bằng custom D3-based cho A2/C5 (ATT&CK Navigator layout đúng chuẩn)
3. **Alerting plugin** — cấu hình gửi email khi rule level ≥ 14 fire (OpenSearch Alerting)
4. **Dashboard drill-down** — click vào 1 rule.id trong table → mở Discover với filter apply sẵn
5. **Anomaly Detection plugin** — OpenSearch có sẵn ML plugin, có thể set anomaly detector trên alert count timeline
