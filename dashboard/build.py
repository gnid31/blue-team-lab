#!/usr/bin/env python3
"""Build 3 dashboards + 18 saved objects trong Wazuh Dashboard qua Saved Objects API.

Dashboards:
  - SOC L1 Alert Triage Console
  - DFIR Incident Investigation Workbench
  - Threat Detection Program Overview (Executive)

Chạy 1 lần: python3 dashboard/build.py
Sau đó mở https://43.228.215.234 → Dashboards → chọn tên.
"""
from __future__ import annotations
import json
import sys
import urllib3
from pathlib import Path

import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

URL = "https://43.228.215.234"
AUTH = ("admin", "T6bvRoNWwO9nvRMqBnAoBCs*S2m2mon+")
H = {"osd-xsrf": "true", "Content-Type": "application/json"}

IDX_ALERTS = "wazuh-alerts-*"
IDX_VERDICTS = "enrichment-verdicts"


def api(method: str, path: str, body: dict | None = None):
    r = requests.request(method, f"{URL}{path}", auth=AUTH, headers=H, verify=False,
                         data=json.dumps(body) if body else None, timeout=30)
    if r.status_code >= 400:
        print(f"  ✗ {method} {path} → {r.status_code}: {r.text[:250]}")
        return None
    return r.json() if r.text else {}


def save_viz(so_id: str, title: str, vis_state: dict, idx_pattern: str,
             query: str = "", filters: list | None = None):
    """Save 1 visualization saved object."""
    vs = dict(vis_state, title=title)
    ss = {
        "index": idx_pattern,
        "query": {"language": "kuery", "query": query},
        "filter": filters or [],
    }
    body = {"attributes": {
        "title": title,
        "visState": json.dumps(vs),
        "uiStateJSON": "{}",
        "description": "",
        "version": 1,
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(ss)},
    }}
    r = api("POST", f"/api/saved_objects/visualization/{so_id}?overwrite=true", body)
    print(f"  {'✓' if r else '✗'} viz {so_id:35} — {title}")


def save_search(so_id: str, title: str, idx_pattern: str, columns: list[str],
                query: str = "", sort: list | None = None):
    """Save 1 saved search."""
    ss = {
        "index": idx_pattern,
        "query": {"language": "kuery", "query": query},
        "filter": [],
        "highlightAll": True,
        "version": True,
    }
    body = {"attributes": {
        "title": title,
        "description": "",
        "hits": 0,
        "columns": columns,
        "sort": sort or [["@timestamp", "desc"]],
        "version": 1,
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(ss)},
    }}
    r = api("POST", f"/api/saved_objects/search/{so_id}?overwrite=true", body)
    print(f"  {'✓' if r else '✗'} search {so_id:32} — {title}")


def save_dashboard(so_id: str, title: str, panel_refs: list[tuple[str, str, dict]],
                   time_from: str = "now-24h", time_to: str = "now",
                   refresh_pause: bool = True, refresh_value: int = 0,
                   markdown_panels: list[tuple[str, dict]] | None = None):
    """
    panel_refs: list of (type, so_id, gridData). type = 'visualization' or 'search'.
    markdown_panels: list of (markdown_content, gridData).
    """
    panels = []
    references = []
    i = 0
    for typ, sid, grid in panel_refs:
        pi = f"panel_{i}"
        panels.append({
            "version": "2.13.0",
            "gridData": {**grid, "i": pi},
            "panelIndex": pi,
            "embeddableConfig": {},
            "panelRefName": f"panel_{i}",
        })
        references.append({"name": f"panel_{i}", "type": typ, "id": sid})
        i += 1
    for md_content, grid in (markdown_panels or []):
        pi = f"panel_{i}"
        panels.append({
            "version": "2.13.0",
            "type": "visualization",
            "gridData": {**grid, "i": pi},
            "panelIndex": pi,
            "embeddableConfig": {
                "savedVis": {
                    "title": "",
                    "description": "",
                    "type": "markdown",
                    "params": {"fontSize": 12, "openLinksInNewTab": True, "markdown": md_content},
                    "uiState": {},
                    "data": {"aggs": [], "searchSource": {"query": {"language": "kuery", "query": ""},
                                                           "filter": []}},
                }
            },
        })
        i += 1

    body = {
        "attributes": {
            "title": title,
            "hits": 0,
            "description": f"Auto-generated Blue Team Lab dashboard — {title}",
            "panelsJSON": json.dumps(panels),
            "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
            "version": 1,
            "timeRestore": True,
            "timeTo": time_to,
            "timeFrom": time_from,
            "refreshInterval": {"pause": refresh_pause, "value": refresh_value},
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({
                "query": {"language": "kuery", "query": ""}, "filter": []})},
        },
        "references": references,
    }
    r = api("POST", f"/api/saved_objects/dashboard/{so_id}?overwrite=true", body)
    print(f"  {'✓' if r else '✗'} DASHBOARD {so_id:25} — {title}")


# ---------- Visualization spec builders ----------

def m_count(label: str, agg_type: str = "count", field: str | None = None,
            color: str | None = None):
    """Metric viz spec."""
    metric_agg = {"id": "1", "enabled": True, "type": agg_type, "schema": "metric",
                  "params": {}}
    if field:
        metric_agg["params"] = {"field": field}
    if label:
        metric_agg["params"]["customLabel"] = label
    metric_params = {"metric": {"percentageMode": False, "useRanges": False,
                                "colorSchema": "Green to Red", "metricColorMode": "None",
                                "colorsRange": [{"from": 0, "to": 10000}],
                                "labels": {"show": True}, "invertColors": False,
                                "style": {"bgFill": "#000", "bgColor": False,
                                          "labelColor": False, "subText": "",
                                          "fontSize": 60}}}
    if color:
        metric_params["metric"]["metricColorMode"] = "Labels"
        metric_params["metric"]["colorSchema"] = color
    return {"type": "metric", "params": metric_params, "aggs": [metric_agg]}


def m_table(rows: list[dict], perPage: int = 20):
    """Data table viz spec. rows = list of terms bucket specs."""
    aggs = [{"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}}]
    for i, r in enumerate(rows, 2):
        aggs.append({"id": str(i), "enabled": True, "type": r.get("type", "terms"),
                     "schema": "bucket", "params": r["params"]})
    return {"type": "table", "params": {"perPage": perPage, "showPartialRows": True,
                                         "showMetricsAtAllLevels": True,
                                         "showTotal": False, "totalFunc": "sum",
                                         "sort": {"columnIndex": None, "direction": None}},
            "aggs": aggs}


def m_bar(x_field: str, split_field: str | None = None, size: int = 15,
          is_date_hist: bool = False, interval: str = "auto"):
    aggs = [{"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}}]
    if is_date_hist:
        aggs.append({"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
                     "params": {"field": x_field, "useNormalizedEsInterval": True,
                                "interval": interval, "drop_partials": False,
                                "min_doc_count": 1, "extended_bounds": {}}})
    else:
        aggs.append({"id": "2", "enabled": True, "type": "terms", "schema": "segment",
                     "params": {"field": x_field, "size": size, "order": "desc",
                                "orderBy": "1", "otherBucket": False}})
    if split_field:
        aggs.append({"id": "3", "enabled": True, "type": "terms", "schema": "group",
                     "params": {"field": split_field, "size": 10, "order": "desc",
                                "orderBy": "1", "otherBucket": False}})
    return {"type": "histogram",
            "params": {"grid": {"categoryLines": False},
                       "categoryAxes": [{"id": "CategoryAxis-1", "type": "category",
                                         "position": "bottom", "show": True,
                                         "labels": {"show": True, "rotate": 0}}],
                       "valueAxes": [{"id": "ValueAxis-1", "position": "left", "show": True,
                                      "type": "value"}],
                       "seriesParams": [{"show": True, "type": "histogram",
                                         "mode": "stacked",
                                         "data": {"label": "Count", "id": "1"},
                                         "valueAxis": "ValueAxis-1"}],
                       "addTooltip": True, "addLegend": True, "legendPosition": "right"},
            "aggs": aggs}


def m_line(x_field: str, split_field: str | None = None, interval: str = "auto"):
    aggs = [{"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
             "params": {"field": x_field, "useNormalizedEsInterval": True,
                        "interval": interval, "drop_partials": False,
                        "min_doc_count": 1, "extended_bounds": {}}}]
    if split_field:
        aggs.append({"id": "3", "enabled": True, "type": "terms", "schema": "group",
                     "params": {"field": split_field, "size": 5, "order": "desc",
                                "orderBy": "1"}})
    return {"type": "line",
            "params": {"grid": {"categoryLines": False},
                       "categoryAxes": [{"id": "CategoryAxis-1", "type": "category",
                                         "position": "bottom", "show": True}],
                       "valueAxes": [{"id": "ValueAxis-1", "position": "left", "show": True,
                                      "type": "value"}],
                       "seriesParams": [{"show": True, "type": "line", "mode": "normal",
                                         "data": {"label": "Count", "id": "1"},
                                         "valueAxis": "ValueAxis-1",
                                         "drawLinesBetweenPoints": True,
                                         "showCircles": True}],
                       "addTooltip": True, "addLegend": True, "legendPosition": "right"},
            "aggs": aggs}


def m_pie(field: str, size: int = 5, is_donut: bool = True):
    return {"type": "pie",
            "params": {"type": "pie", "addTooltip": True, "addLegend": True,
                       "legendPosition": "right", "isDonut": is_donut,
                       "labels": {"show": True, "values": True, "last_level": True}},
            "aggs": [{"id": "1", "enabled": True, "type": "count", "schema": "metric",
                      "params": {}},
                     {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
                      "params": {"field": field, "size": size, "order": "desc",
                                 "orderBy": "1", "otherBucket": False}}]}


# ============================================================
# BUILD
# ============================================================
def build_soc():
    print("\n=== SOC L1 Alert Triage Console ===")
    save_viz("soc-alert-volume-15m", "SOC - Alert Volume (Last 15 min)",
             m_count("Alerts"), IDX_ALERTS)
    save_viz("soc-critical-unack-15m", "SOC - Critical Alerts Unacknowledged (Last 15 min)",
             m_count("Critical"), IDX_ALERTS, query="rule.level >= 12")
    save_viz("soc-active-endpoints", "SOC - Active Endpoints",
             m_count("Endpoints", "cardinality", "agent.name"), IDX_ALERTS)
    save_viz("soc-top-firing-rule", "SOC - Top Firing Rule (Last 4h)",
             {"type": "metric",
              "params": {"metric": {"labels": {"show": True},
                                     "style": {"fontSize": 30}}},
              "aggs": [{"id": "1", "enabled": True, "type": "top_hits", "schema": "metric",
                        "params": {"field": "rule.description", "size": 1, "sortField": "@timestamp",
                                   "sortOrder": "desc", "aggregate": "concat",
                                   "customLabel": "Latest high-severity rule"}}]},
             IDX_ALERTS, query="rule.level >= 10")

    save_search("soc-triage-queue", "SOC - Triage Queue (High-Severity Alerts)",
                IDX_ALERTS,
                columns=["agent.name", "rule.id", "rule.level", "rule.mitre.id",
                         "rule.description"],
                query="rule.level >= 7",
                sort=[["rule.level", "desc"], ["@timestamp", "desc"]])

    save_viz("soc-rule-activity-4h", "SOC - Rule Activity Trend (Last 4h)",
             m_bar("@timestamp", split_field="rule.id", is_date_hist=True, interval="10m"),
             IDX_ALERTS, query="rule.level >= 5")

    save_viz("soc-endpoint-heartbeat", "SOC - Endpoint Heartbeat Status",
             {"type": "table",
              "params": {"perPage": 20, "showPartialRows": True,
                          "showMetricsAtAllLevels": True, "showTotal": False,
                          "totalFunc": "sum"},
              "aggs": [{"id": "1", "enabled": True, "type": "max", "schema": "metric",
                        "params": {"field": "@timestamp", "customLabel": "Last event"}},
                       {"id": "2", "enabled": True, "type": "count", "schema": "metric",
                        "params": {"customLabel": "Events (24h)"}},
                       {"id": "3", "enabled": True, "type": "terms", "schema": "bucket",
                        "params": {"field": "agent.name", "size": 20, "order": "asc",
                                   "orderBy": "1", "customLabel": "Endpoint"}}]},
             IDX_ALERTS)


def build_dfir():
    print("\n=== DFIR Incident Investigation Workbench ===")

    save_search("dfir-event-timeline", "DFIR - Incident Event Timeline",
                IDX_ALERTS,
                columns=["agent.name", "data.win.system.eventID", "rule.id",
                         "data.win.eventdata.image", "data.win.eventdata.commandLine",
                         "data.win.eventdata.user", "data.audit.exe"],
                query="",
                sort=[["@timestamp", "asc"]])

    save_viz("dfir-process-lineage",
             "DFIR - Process Execution Lineage (Sysmon EID 1)",
             m_table([
                 {"params": {"field": "data.win.eventdata.parentImage", "size": 10,
                             "order": "desc", "orderBy": "1", "customLabel": "Parent"}},
                 {"params": {"field": "data.win.eventdata.image", "size": 10,
                             "order": "desc", "orderBy": "1", "customLabel": "Child"}},
                 {"params": {"field": "data.win.eventdata.user", "size": 3,
                             "order": "desc", "orderBy": "1", "customLabel": "User"}},
             ]),
             IDX_ALERTS, query='data.win.system.eventID:"1"')

    save_viz("dfir-network-connections",
             "DFIR - Network Connections (Sysmon EID 3)",
             m_table([
                 {"params": {"field": "data.win.eventdata.image", "size": 10,
                             "order": "desc", "orderBy": "1", "customLabel": "Process"}},
                 {"params": {"field": "data.win.eventdata.destinationIp", "size": 20,
                             "order": "desc", "orderBy": "1", "customLabel": "Dest IP"}},
                 {"params": {"field": "data.win.eventdata.destinationPort", "size": 10,
                             "order": "desc", "orderBy": "1", "customLabel": "Port"}},
             ]),
             IDX_ALERTS, query='data.win.system.eventID:"3"')

    save_viz("dfir-file-registry-mods",
             "DFIR - File & Registry Modifications (Sysmon EID 11/13)",
             m_table([
                 {"params": {"field": "data.win.system.eventID", "size": 2,
                             "order": "desc", "orderBy": "1", "customLabel": "EID"}},
                 {"params": {"field": "data.win.eventdata.targetFilename", "size": 10,
                             "order": "desc", "orderBy": "1", "customLabel": "File"}},
                 {"params": {"field": "data.win.eventdata.targetObject", "size": 10,
                             "order": "desc", "orderBy": "1", "customLabel": "Registry"}},
                 {"params": {"field": "data.win.eventdata.image", "size": 5,
                             "order": "desc", "orderBy": "1", "customLabel": "Process"}},
             ]),
             IDX_ALERTS, query='data.win.system.eventID:("11" or "13")')

    save_viz("dfir-user-activity",
             "DFIR - User Activity Across Endpoints",
             m_table([
                 {"params": {"field": "data.win.eventdata.user", "size": 10,
                             "order": "desc", "orderBy": "1", "customLabel": "User"}},
                 {"params": {"field": "agent.name", "size": 5,
                             "order": "desc", "orderBy": "1", "customLabel": "Host"}},
                 {"params": {"field": "rule.mitre.id", "size": 10,
                             "order": "desc", "orderBy": "1", "customLabel": "MITRE"}},
             ]),
             IDX_ALERTS)

    save_viz("dfir-ioc-crossref",
             "DFIR - IOC Threat Intel Cross-Reference",
             m_table([
                 {"params": {"field": "ioc_value", "size": 15,
                             "order": "desc", "orderBy": "1", "customLabel": "IOC"}},
                 {"params": {"field": "provider", "size": 3,
                             "order": "desc", "orderBy": "1", "customLabel": "Provider"}},
                 {"params": {"field": "verdict_label", "size": 4,
                             "order": "desc", "orderBy": "1", "customLabel": "Verdict"}},
                 {"params": {"field": "alert_id", "size": 3,
                             "order": "desc", "orderBy": "1", "customLabel": "Alert ID"}},
             ]),
             IDX_VERDICTS)


def build_exec():
    print("\n=== Threat Detection Program Overview (Executive) ===")
    save_viz("exec-total-alerts-7d", "Exec - Total Alerts (Last 7 days)",
             m_count("Alerts (7d)"), IDX_ALERTS)
    save_viz("exec-mitre-techniques", "Exec - Unique MITRE Techniques Detected",
             m_count("Techniques", "cardinality", "rule.mitre.id"), IDX_ALERTS)
    save_viz("exec-endpoints-monitored", "Exec - Endpoints Monitored",
             m_count("Endpoints", "cardinality", "agent.name"), IDX_ALERTS)
    save_viz("exec-verdicts-written", "Exec - Threat Intel Verdicts Written",
             m_count("Verdicts"), IDX_VERDICTS)

    save_viz("exec-mitre-heatmap", "Exec - MITRE ATT&CK Coverage Heatmap",
             {"type": "heatmap",
              "params": {"addLegend": True, "addTooltip": True, "colorSchema": "Blues",
                         "enableHover": True, "legendPosition": "right",
                         "times": [], "type": "heatmap",
                         "valueAxes": [{"id": "ValueAxis-1", "labels": {"color": "black",
                                        "rotate": 0, "show": False}, "scale": {"type": "linear"},
                                        "show": False, "type": "value"}]},
              "aggs": [{"id": "1", "enabled": True, "type": "count", "schema": "metric",
                        "params": {}},
                       {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
                        "params": {"field": "rule.mitre.id", "size": 30, "order": "desc",
                                   "orderBy": "1", "customLabel": "Technique"}},
                       {"id": "3", "enabled": True, "type": "terms", "schema": "group",
                        "params": {"field": "agent.name", "size": 5, "order": "desc",
                                   "orderBy": "1", "customLabel": "Endpoint"}}]},
             IDX_ALERTS)

    save_viz("exec-alert-trend-7d", "Exec - Alert Volume Trend (Last 7 days)",
             m_line("@timestamp", interval="6h"), IDX_ALERTS,
             query="rule.level >= 5")

    save_viz("exec-verdict-distribution", "Exec - Threat Intel Verdict Distribution",
             m_pie("verdict_label", size=5, is_donut=True), IDX_VERDICTS)


def build_dashboards():
    print("\n=== DASHBOARDS ===")

    # ---- SOC L1 ----
    soc_md = """## SOC L1 Alert Triage Console

**Persona**: L1 analyst online shift. Auto-refresh 30s. Time frame Last 4 hours.

**Workflow**: 4 KPI trên → nếu Critical > 0 → scroll xuống Triage Queue → chọn alert level cao nhất → escalate.

Cần deep-dive 1 alert? → [DFIR Workbench](#/dashboards/view/btl-dfir)
"""
    save_dashboard("btl-soc-l1", "Blue Team Lab - SOC L1 Alert Triage Console",
                   panel_refs=[
                       ("visualization", "soc-alert-volume-15m",
                        {"x": 0, "y": 0, "w": 12, "h": 8}),
                       ("visualization", "soc-critical-unack-15m",
                        {"x": 12, "y": 0, "w": 12, "h": 8}),
                       ("visualization", "soc-active-endpoints",
                        {"x": 24, "y": 0, "w": 12, "h": 8}),
                       ("visualization", "soc-top-firing-rule",
                        {"x": 36, "y": 0, "w": 12, "h": 8}),
                       ("search", "soc-triage-queue",
                        {"x": 0, "y": 8, "w": 48, "h": 20}),
                       ("visualization", "soc-rule-activity-4h",
                        {"x": 0, "y": 28, "w": 24, "h": 12}),
                       ("visualization", "soc-endpoint-heartbeat",
                        {"x": 24, "y": 28, "w": 24, "h": 12}),
                   ],
                   markdown_panels=[(soc_md, {"x": 0, "y": 40, "w": 48, "h": 6})],
                   time_from="now-4h", time_to="now",
                   refresh_pause=False, refresh_value=30000)

    # ---- DFIR ----
    dfir_md = """## DFIR Investigation Scope Filters

**Persona**: DFIR analyst. Manual time picker theo incident window. No auto-refresh (freeze snapshot).

**Filter shortcuts** (paste vào query bar trên):
- Host: `agent.name : "win-ep-01"`
- User: `data.win.eventdata.user : *labuser*` (Win) hoặc `data.audit.auid : "1000"` (Linux)
- Technique: `rule.mitre.id : "T1059.001"`
- Hash: `data.win.eventdata.hashes : *B4E7BC24*`
- IP: `data.win.eventdata.destinationIp : "192.168.154.166"`
- Path: `data.win.eventdata.targetFilename : *"\\\\Temp\\\\"*`

Combine với `and`: `agent.name : "win-ep-01" and data.win.eventdata.user : *labuser*`
"""
    save_dashboard("btl-dfir", "Blue Team Lab - DFIR Incident Investigation Workbench",
                   panel_refs=[
                       ("search", "dfir-event-timeline",
                        {"x": 0, "y": 6, "w": 48, "h": 20}),
                       ("visualization", "dfir-process-lineage",
                        {"x": 0, "y": 26, "w": 16, "h": 14}),
                       ("visualization", "dfir-network-connections",
                        {"x": 16, "y": 26, "w": 16, "h": 14}),
                       ("visualization", "dfir-file-registry-mods",
                        {"x": 32, "y": 26, "w": 16, "h": 14}),
                       ("visualization", "dfir-user-activity",
                        {"x": 0, "y": 40, "w": 24, "h": 14}),
                       ("visualization", "dfir-ioc-crossref",
                        {"x": 24, "y": 40, "w": 24, "h": 14}),
                   ],
                   markdown_panels=[(dfir_md, {"x": 0, "y": 0, "w": 48, "h": 6})],
                   time_from="now-24h", time_to="now",
                   refresh_pause=True, refresh_value=0)

    # ---- Executive ----
    exec_md = """# Blue Team Lab — Threat Detection Program

**Wazuh 4.9 HIDS** + **15 custom rules** mapped MITRE ATT&CK + **Python IOC enrichment** (VirusTotal + AbuseIPDB)

📖 [Repo](https://github.com/gnid31/blue-team-lab) · [Hunting reports](https://github.com/gnid31/blue-team-lab/tree/main/hunting-reports)

Operational drill-down: [SOC L1 Triage](#/dashboards/view/btl-soc-l1) · [DFIR Workbench](#/dashboards/view/btl-dfir)
"""
    save_dashboard("btl-executive", "Blue Team Lab - Threat Detection Program Overview",
                   panel_refs=[
                       ("visualization", "exec-total-alerts-7d",
                        {"x": 0, "y": 6, "w": 12, "h": 8}),
                       ("visualization", "exec-mitre-techniques",
                        {"x": 12, "y": 6, "w": 12, "h": 8}),
                       ("visualization", "exec-endpoints-monitored",
                        {"x": 24, "y": 6, "w": 12, "h": 8}),
                       ("visualization", "exec-verdicts-written",
                        {"x": 36, "y": 6, "w": 12, "h": 8}),
                       ("visualization", "exec-mitre-heatmap",
                        {"x": 0, "y": 14, "w": 48, "h": 14}),
                       ("visualization", "exec-alert-trend-7d",
                        {"x": 0, "y": 28, "w": 32, "h": 12}),
                       ("visualization", "exec-verdict-distribution",
                        {"x": 32, "y": 28, "w": 16, "h": 12}),
                   ],
                   markdown_panels=[(exec_md, {"x": 0, "y": 0, "w": 48, "h": 6})],
                   time_from="now-7d", time_to="now",
                   refresh_pause=True, refresh_value=0)


def export_all(out_path: Path):
    """Export all saved objects to ndjson."""
    print(f"\n=== EXPORT to {out_path} ===")
    body = {"objects": [
        {"type": "index-pattern", "id": "wazuh-alerts-*"},
        {"type": "index-pattern", "id": "enrichment-verdicts"},
        {"type": "dashboard", "id": "btl-soc-l1"},
        {"type": "dashboard", "id": "btl-dfir"},
        {"type": "dashboard", "id": "btl-executive"},
    ], "includeReferencesDeep": True}
    r = requests.post(f"{URL}/api/saved_objects/_export", auth=AUTH, headers=H,
                      verify=False, data=json.dumps(body), timeout=60)
    if r.status_code >= 400:
        print(f"  ✗ export failed: {r.status_code}: {r.text[:200]}")
        return
    out_path.write_text(r.text)
    print(f"  ✓ {out_path} ({out_path.stat().st_size} bytes)")


def main():
    build_soc()
    build_dfir()
    build_exec()
    build_dashboards()
    export_all(Path(__file__).parent / "blue-team-lab-all.ndjson")
    print("\n✅ DONE. Mở https://43.228.215.234 → Dashboards")
    print("   • Blue Team Lab - SOC L1 Alert Triage Console")
    print("   • Blue Team Lab - DFIR Incident Investigation Workbench")
    print("   • Blue Team Lab - Threat Detection Program Overview")


if __name__ == "__main__":
    main()
