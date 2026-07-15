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

## 1. Dashboards for SOC1 + DFIR + (optional) Executive

### 1.1. Persona reality check

Trước khi build, phân biệt **SOC L1** và **DFIR** — hai vai trò rất khác nhau:

| Vai trò | Vòng đời | Tần suất | Câu hỏi chính | Time frame |
|---|---|---|---|---|
| **SOC L1 Analyst** | Detect → Triage → Escalate/Close | 24/7 shift, xử lý mọi alert đến | "Alert nào tôi cần xử lý *ngay*?" | Real-time / Last 15m–4h |
| **DFIR Analyst** | Investigate confirmed incident (post-triage escalation) | Ad-hoc, deep-dive khi có incident | "Chuyện gì đã xảy ra trên host X? Chain of events là gì?" | Incident window (last 24h–7d, focused) |

**SOC1** = surface. **DFIR** = deep. Không dùng chung 1 dashboard.

### 1.2. Framework support cho 2 persona

- **SOC1**: 4 metric của **Google SRE Golden Signals** map sang SOC — **Rate** (alerts/hour), **Errors** (FP rate), **Duration** (MTTA/MTTR), **Saturation** (analyst workload). Cũng bám **SANS SOC Triage** — Detect → Analyze → Contain.
- **DFIR**: bám **NIST SP 800-86** (Guide to Integrating Forensic Techniques into Incident Response) — 4 phase Collection → Examination → Analysis → Reporting. Dashboard hỗ trợ Examination + Analysis.

### 1.3. Ba dashboards

| Dashboard | Persona | Time | Auto-refresh | Câu hỏi trả lời |
|---|---|---|---|---|
| **SOC1 — Real-time Triage** | L1 Analyst | Last 4 hours | 30 giây | "Alert nào critical? Agent nào đang silent? Rule nào đang noise?" |
| **DFIR — Investigation Workbench** | DFIR Analyst | Incident window (variable) | Manual | "Trên host X, user Y, khoảng thời gian Z — chain of events là gì?" |
| **Executive Overview** *(optional)* | CV showcase / CISO snapshot | Last 7 days | 5 phút | "Dự án cover gì? Bao nhiêu detection? Big picture" |

### 1.4. Data sources dùng chung

| Source | Field key | Dashboard nào dùng |
|---|---|---|
| `wazuh-alerts-*` | `@timestamp`, `rule.id/level/description/mitre.id`, `agent.name`, `data.win.system.eventID`, `data.win.eventdata.*`, `data.audit.*` | Cả 3 |
| `enrichment-verdicts-*` | `ioc_value`, `verdict_label`, `provider`, `score`, `link`, `alert_id` | DFIR (IOC pivot), Executive (chart) |

---

## 2. Dashboard SOC1 — Real-time Triage

**Persona**: L1 analyst đang online shift, xử lý alert stream.

**Nguyên tắc thiết kế**:
- **Alert queue chiếm trung tâm** — analyst nhìn 90% thời gian ở đây
- **KPI row trên top** — 4 số lớn để scan 5 giây
- **Auto-refresh 30s** — real-time feel
- **Time frame Last 4 hours** default — đủ context cho shift

**Layout**:
```
┌───────┬───────┬───────┬───────┐
│ Total │Critic │Distinct│Rule.id│  ← 4 KPI panels (Metric type)
│ alerts│ unack │ agents │ noisy │     (last 15 min unless noted)
└───────┴───────┴───────┴───────┘
┌────────────────────────────────────────────────────────────┐
│ SOC1-Q Alert Queue                                        │
│   time | agent | rule.id | level | mitre | description   │  ← main workspace
│   (sorted: level desc, then @timestamp desc, 50 rows)     │     data table
└────────────────────────────────────────────────────────────┘
┌──────────────────────────┬─────────────────────────────────┐
│ SOC1-R Rule fires (4h)   │ SOC1-A Agent last-seen          │
│   bar per rule.id        │   table: agent | last event ago │
│   (spot noisy rules)     │   (silent agent = suspicious)   │
└──────────────────────────┴─────────────────────────────────┘
```

### SOC1-K1 — Total alerts (last 15 min)

**Question**: "Đang có nhiều alert bất thường không?"

**GUI**:

1. **Visualize** → Create → **Metric**
2. Index pattern: `wazuh-alerts-*`
3. Metric aggregation: **Count**
4. Query bar: (empty — tất cả alerts)
5. Time picker: **Last 15 minutes**
6. Options → Font size: **60** (lớn, dễ scan)
7. Save: **`BTL-SOC1-K1 Alerts 15m`**

### SOC1-K2 — Critical unacknowledged (level ≥ 12, last 15 min)

**Question**: "Có alert critical nào tôi chưa xử lý?"

> **Ghi chú**: Wazuh 4.9 native **không có** field "acknowledged" — đây là gap so với thương mại SIEM (Splunk, Sentinel). Trong lab, "unack" = alert vừa mới đến (last 15 min). Trong production cần OpenSearch Alerting plugin hoặc SOAR tích hợp để track state.

**GUI**:

1. Visualize → Metric
2. Index pattern: `wazuh-alerts-*`
3. Query bar: `rule.level >= 12`
4. Time picker: **Last 15 minutes**
5. Options → Font size 60, color **red** (Options → Metric → Color ranges: ≥1 = danger)
6. Save: **`BTL-SOC1-K2 Critical Unack 15m`**

### SOC1-K3 — Distinct agents active (last 15 min)

**Question**: "Bao nhiêu endpoint đang sinh telemetry?"

**GUI**:

1. Visualize → Metric
2. Index pattern: `wazuh-alerts-*`
3. Metric aggregation: **Unique Count** (Cardinality) — field `agent.name`
4. Time picker: Last 15 min
5. Custom label: "Agents active"
6. Save: **`BTL-SOC1-K3 Agents Active`**

### SOC1-K4 — Rule ID noisiest last 4h

**Question**: "Rule nào đang spam để tune?"

**GUI**:

1. Visualize → Metric
2. Index pattern: `wazuh-alerts-*`
3. Metric aggregation: **Top Hit** — field `rule.id`, size 1, order by Count desc
4. Time picker: Last 4 hours
5. Custom label: "Noisiest rule (4h)"
6. Save: **`BTL-SOC1-K4 Noisy Rule`**

### SOC1-Q — Alert Queue (data table, workspace)

**Question**: Analyst spend 90% thời gian ở đây — cần xử lý cái nào tiếp?

**GUI**:

1. Visualize → **Data table**
2. Index pattern: `wazuh-alerts-*`
3. Query bar: `rule.level >= 7` (skip low-level noise)
4. Time picker: **Last 4 hours**
5. Metrics: **Count** (giữ default; sẽ hide sau)
6. Buckets → **Split rows** (nhiều bucket theo thứ tự để hiển thị các cột):
   - Bucket 1: **Terms** — field `@timestamp` — size 50 — Order **Descending** (mới nhất trên đầu). *Note: dùng Terms trên timestamp là hack để show từng row; alternative là dùng Saved Search embed — xem note phía dưới.*
   - Bucket 2: Terms — `agent.name` — size 1
   - Bucket 3: Terms — `rule.id` — size 1
   - Bucket 4: Terms — `rule.level` — size 1 — Order desc theo level
   - Bucket 5: Terms — `rule.mitre.id` — size 1
   - Bucket 6: Terms — `rule.description` — size 1
7. Options tab → **Show partial rows: ON**
8. Save: **`BTL-SOC1-Q Alert Queue`**

**Alternative tốt hơn — Saved Search + Discover embed** (recommend):

1. Menu → **Discover**
2. Index pattern: `wazuh-alerts-*`
3. Query: `rule.level >= 7`
4. Time picker: Last 4 hours
5. Columns to display (bấm + cạnh field trong sidebar): `agent.name`, `rule.id`, `rule.level`, `rule.mitre.id`, `rule.description`
6. Sort: `rule.level` desc, `@timestamp` desc
7. **Save** search → title **`BTL-SOC1-Q Alert Queue (saved search)`**
8. Sau đó add saved search vào dashboard qua Add → **Saved Search** tab

Saved Search dùng cho SOC1 tốt hơn Data table vì:
- Hiển thị raw event row (như Splunk timeline)
- Click 1 row → expand → xem full JSON
- Sort tự động
- Không phải hack bucket "Terms trên timestamp"

### SOC1-R — Rule fires timeline (last 4h)

**Question**: "Có rule nào bùng phát bất thường?"

**GUI**:

1. Visualize → **Vertical Bar**
2. Index pattern: `wazuh-alerts-*`
3. Time picker: Last 4 hours
4. X-axis: **Date Histogram** — `@timestamp` — interval **10 min**
5. Split series: Terms — `rule.id` — size 10 — Order Count desc
6. Query bar: `rule.level >= 5`
7. Options → **Legend position: right**
8. Save: **`BTL-SOC1-R Rule Fires 4h`**

### SOC1-A — Agent Last-Seen (silent detector)

**Question**: "Endpoint nào không sinh telemetry gần đây → có thể bị compromise/tamper agent?"

**GUI**:

1. Visualize → **Data table**
2. Index pattern: `wazuh-alerts-*`
3. Time picker: **Last 24 hours** (cần range rộng hơn để so sánh)
4. Metrics:
   - Delete default Count
   - Add **Max** — field `@timestamp` — Custom label "Last event"
   - Add **Count** — Custom label "Alerts (24h)"
5. Buckets → Split rows: Terms — `agent.name` — size 20 — Order by Max @timestamp asc (agent cũ nhất lên trên = silent nhất)
6. Save: **`BTL-SOC1-A Agent Last-Seen`**

Cách dùng: agent nào có "Last event" > 1h ago = suspicious, cần check `systemctl status wazuh-agent` trên VM đó.

### Assemble Dashboard SOC1

1. Menu → **Dashboard** → Create
2. Add:
   - 4 metric: **BTL-SOC1-K1..K4** (row trên, mỗi cái rộng 12/48 grid = 25%)
   - Saved search **BTL-SOC1-Q** (row 2, full width, height 20/48)
   - **BTL-SOC1-R** (row 3, rộng 24/48)
   - **BTL-SOC1-A** (row 3, rộng 24/48)
3. Time picker: **Last 4 hours**
4. **Auto-refresh: 30 seconds** (click nút refresh nhỏ trên đầu → set)
5. Save with time: **`Blue Team Lab — SOC1 Real-time Triage`**

---

## 3. Dashboard DFIR — Investigation Workbench

**Persona**: DFIR analyst đang deep-dive trên confirmed incident.

**Nguyên tắc thiết kế**:
- **Filter đóng vai trò trung tâm** — user set agent/user/timerange, mọi panel react
- **Panel drill-down** — chuyên biệt cho từng loại telemetry (process, network, file, registry)
- **Không auto-refresh** — freeze snapshot của incident window
- **Time picker rộng** — set thủ công cho incident (VD 2 giờ quanh alert timestamp)

**Layout**:
```
┌───────────────────────────────────────────────────────────┐
│ DFIR-F Filter widget (Markdown hướng dẫn dùng filter bar) │  ← control zone
├───────────────────────────────────────────────────────────┤
│ DFIR-T Event Timeline (saved search, sorted by @timestamp)│  ← main investigation
│   time | eventID | image | commandLine | user | rule.id  │     workspace
└───────────────────────────────────────────────────────────┘
┌───────────────┬───────────────┬───────────────────────────┐
│ DFIR-P Process│ DFIR-N Network│ DFIR-F File/Registry      │
│   Tree        │   Flow        │   Activity                │
│ (EID 1 table) │ (EID 3 table) │ (EID 11+13 table)         │
└───────────────┴───────────────┴───────────────────────────┘
┌───────────────────────────┬───────────────────────────────┐
│ DFIR-U User Activity      │ DFIR-I IOC Enrichment Pivot   │
│ (grouped by user)         │ (from enrichment-verdicts-*)  │
└───────────────────────────┴───────────────────────────────┘
```

### DFIR-F — Filter Control (Markdown widget)

**Question**: Hướng dẫn analyst dùng filter bar.

**GUI**:

1. Dashboard → Edit → Add → **Markdown** panel
2. Content:
   ````markdown
   ## DFIR Investigation Filters
   
   **Bắt đầu**: đặt trong query bar 1 hoặc kết hợp các filter dưới đây, rồi set time picker theo incident window:
   
   - **Focus 1 host**: `agent.name : "win-ep-01"`
   - **Focus 1 user**: `data.win.eventdata.user : "*labuser*"` (Windows) hoặc `data.audit.auid : "1000"` (Linux)
   - **Focus 1 technique**: `rule.mitre.id : "T1059.001"`
   - **Focus 1 hash**: `data.win.eventdata.hashes : *B4E7BC24*`
   - **Focus 1 IP**: `data.win.eventdata.destinationIp : "192.168.154.166"`
   - **Focus 1 file path**: `data.win.eventdata.targetFilename : *"\\Temp\\"*`
   
   **Kết hợp** với `AND`:
   ```
   agent.name : "win-ep-01" AND data.win.eventdata.user : *labuser* AND @timestamp >= "2026-07-13T12:00:00Z"
   ```
   
   Sau khi set filter → mọi panel dưới đây tự cập nhật.
   ````
3. Save panel (icon disk trong Markdown editor)

### DFIR-T — Event Timeline (saved search)

**Question**: Chuỗi sự kiện theo thời gian trong incident window.

**GUI**:

1. Menu → **Discover**
2. Index pattern: `wazuh-alerts-*`
3. Columns (bấm + cạnh field): `@timestamp`, `agent.name`, `data.win.system.eventID`, `rule.id`, `data.win.eventdata.image`, `data.win.eventdata.commandLine`, `data.win.eventdata.user`
4. Sort: `@timestamp` **ascending** (chronological cho reconstruction)
5. Query: (empty — filter apply từ dashboard-level)
6. Save search: **`BTL-DFIR-T Event Timeline`**
7. Trong dashboard, Add → Saved Search tab → chọn saved search này

### DFIR-P — Process Tree (Sysmon EID 1)

**Question**: Parent-child process — attacker's shell → child spawn?

**GUI**:

1. Visualize → **Data table**
2. Index pattern: `wazuh-alerts-*`
3. Query bar: `data.win.system.eventID : "1"`
4. Time picker: (rely on dashboard-level)
5. Buckets → Split rows:
   - Bucket 1: Terms — `data.win.eventdata.parentImage` — size 10 — Custom label "Parent"
   - Bucket 2: Terms — `data.win.eventdata.image` — size 10 — Custom label "Child"
   - Bucket 3: Terms — `data.win.eventdata.user` — size 3 — Custom label "User"
6. Save: **`BTL-DFIR-P Process Tree`**

Cách dùng: xem row nào có `parentImage: sshd-session.exe` + `image: powershell.exe` = attacker shell.

### DFIR-N — Network Connections (Sysmon EID 3)

**Question**: Ai kết nối tới đâu, lateral movement?

**GUI**:

1. Visualize → Data table
2. Index pattern: `wazuh-alerts-*`
3. Query bar: `data.win.system.eventID : "3"`
4. Split rows:
   - Bucket 1: Terms — `data.win.eventdata.image` — size 10 — "Process"
   - Bucket 2: Terms — `data.win.eventdata.destinationIp` — size 20 — "Destination IP"
   - Bucket 3: Terms — `data.win.eventdata.destinationPort` — size 10 — "Port"
5. Save: **`BTL-DFIR-N Network Connections`**

> **Prereq**: Sysmon SwiftOnSecurity default filter EID 3 khá aggressive — nếu bảng rỗng, cần tune Sysmon config include EID 3 rộng hơn.

### DFIR-FR — File + Registry Activity

**Question**: Attacker drop file gì? Ghi registry key gì?

**GUI**:

1. Visualize → Data table
2. Index pattern: `wazuh-alerts-*`
3. Query bar: `data.win.system.eventID : ("11" or "13")` (EID 11 FileCreate + EID 13 RegistryEvent)
4. Split rows:
   - Bucket 1: Terms — `data.win.system.eventID` — size 2 — "EID"
   - Bucket 2: Terms — `data.win.eventdata.targetFilename` — size 15 — "File" (empty cho EID 13)
   - Bucket 3: Terms — `data.win.eventdata.targetObject` — size 15 — "Registry" (empty cho EID 11)
   - Bucket 4: Terms — `data.win.eventdata.image` — size 5 — "By process"
5. Save: **`BTL-DFIR-FR File+Registry`**

### DFIR-U — User Activity (grouped)

**Question**: 1 user cụ thể đã làm gì trên các host?

**GUI**:

1. Visualize → Data table
2. Index pattern: `wazuh-alerts-*`
3. Split rows:
   - Bucket 1: Terms — `data.win.eventdata.user` — size 10 — "User"
   - Bucket 2: Terms — `agent.name` — size 5 — "Host"
   - Bucket 3: Terms — `rule.mitre.id` — size 10 — "MITRE"
4. Save: **`BTL-DFIR-U User Activity`**

Filter dashboard-level: `data.win.eventdata.user : *labuser*` → chỉ hiện labuser action.

### DFIR-I — IOC Enrichment Pivot

**Question**: Bắt đầu từ 1 IOC → tất cả verdict + alert liên quan?

**GUI**:

1. Visualize → Data table
2. Index pattern: **`enrichment-verdicts-*`**
3. Query bar (dashboard-level filter sẽ append): (empty)
4. Split rows:
   - Bucket 1: Terms — `ioc_value` — size 15 — "IOC"
   - Bucket 2: Terms — `provider` — size 3 — "Provider"
   - Bucket 3: Terms — `verdict_label` — size 4 — "Verdict"
   - Bucket 4: Terms — `alert_id` — size 3 — "Alert ID"
5. Save: **`BTL-DFIR-I IOC Pivot`**

Cách dùng: nếu analyst có sẵn IOC hash/IP, filter `ioc_value : "62.60.130.219"` → thấy verdict + alert_id → jump sang DFIR-T timeline với `_id: <alert_id>`.

### Assemble Dashboard DFIR

1. Dashboard → Create → Add:
   - **BTL-DFIR-F** (Markdown, row top, full width)
   - **BTL-DFIR-T** (Saved Search, row 2, full width, height lớn)
   - **BTL-DFIR-P** (row 3, 16/48 grid)
   - **BTL-DFIR-N** (row 3, 16/48 grid)
   - **BTL-DFIR-FR** (row 3, 16/48 grid)
   - **BTL-DFIR-U** (row 4, 24/48 grid)
   - **BTL-DFIR-I** (row 4, 24/48 grid)
2. Time picker: **manual** (analyst set theo incident window; default Last 24 hours)
3. Auto-refresh: **OFF** (freeze snapshot)
4. Save: **`Blue Team Lab — DFIR Investigation Workbench`**

---

## 4. Dashboard Executive Overview (optional — CV showcase)

**Persona**: recruiter, CISO snapshot. Không phải operational persona nhưng có giá trị để nhúng vào CV/README.

**Layout & GUI**: giữ như bản A→C trước đây — xem section 4 cũ trong `git log` để reference nếu cần build. Tóm tắt panels:

- **EXEC-K1..K4**: 4 big number (Total alerts 7d, Unique techniques, Agents monitored, Verdicts written)
- **EXEC-M**: MITRE ATT&CK Coverage heatmap
- **EXEC-T**: Timeline last 7d
- **EXEC-V**: Enrichment Verdict donut

Save: **`Blue Team Lab — Executive Overview`**.

---


## 5. Navigation between dashboards

Wazuh Dashboard cho phép link giữa dashboards qua **Markdown** widget hoặc **Dashboard-only mode**:

Trong Executive dashboard, thêm markdown block link sang operational dashboards:
```markdown
🔍 **Drill down**:
- [🚨 SOC L1 Triage →](#/dashboards/view/blue-team-lab-soc1)
- [🔬 DFIR Investigation →](#/dashboards/view/blue-team-lab-dfir)
```

Trong SOC1 dashboard, có thể thêm markdown link sang DFIR cho analyst dễ escalate:
```markdown
Cần deep-dive 1 alert? → [🔬 DFIR Workbench](#/dashboards/view/blue-team-lab-dfir)
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
   git commit -m "dashboard: export SOC1 + DFIR + Executive dashboards (persona-based)"
   ```

---

## 7. Screenshot cho CV / README

Priority screenshot:

1. **Executive Overview** — screenshot chính cho **README hero image** — trực quan nhất cho recruiter
2. **SOC1 Real-time Triage** — screenshot khi có alert stream (chạy session hunt trước để có data phong phú)
3. **DFIR Workbench** — screenshot với 1 incident window đã filter (VD session 01 T1059.001 time range)

Save:
```
dashboard/screenshots/
├── executive-overview.png       ← hero image cho README
├── soc1-triage.png              ← operational dashboard L1
└── dfir-workbench.png           ← investigation dashboard
```

README embed:
```markdown
## Dashboard preview

![SOC Overview](dashboard/screenshots/executive-overview.png)

**Operational dashboards**: [SOC1 Triage](dashboard/screenshots/soc1-triage.png) · [DFIR Workbench](dashboard/screenshots/dfir-workbench.png)
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
  -X DELETE "https://43.228.215.234/api/saved_objects/dashboard/blue-team-lab-soc1"
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
