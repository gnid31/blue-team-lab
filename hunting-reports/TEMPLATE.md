# Hunting Report — Session NN

## Metadata

| Field | Value |
|---|---|
| Session # | NN |
| Date (UTC) | YYYY-MM-DD |
| Analyst | (tên) |
| Technique | **Txxxx.xxx — <tên>** |
| Tactic | (Execution / Persistence / Discovery / …) |
| Endpoint | win-ep-01 / linux-ep-01 |
| Custom rule | 100xxx |
| Data source | Sysmon EID N / auditd key=Y / Windows Security 4XXX |

---

## 1. Attack summary

Command đã chạy (mô phỏng attacker):

```powershell
# hoặc bash — copy chính xác từ atomic/Txxxx.md
```

| Thời điểm | Sự kiện |
|---|---|
| YYYY-MM-DD HH:MM:SS UTC | Start test |
| YYYY-MM-DD HH:MM:SS UTC | Command completed |
| YYYY-MM-DD HH:MM:SS UTC | Cleanup |

---

## 2. Hypothesis

> Nếu attacker chạy Txxxx trên endpoint, ta kỳ vọng thấy:
> - [ ] Sysmon EID N với image=... commandLine chứa ...
> - [ ] Custom rule 100xxx bắn alert level Y
> - [ ] MITRE tag Txxxx trong alert
> - [ ] IOC extract: (hash / IP / domain)

---

## 3. Hunt queries

### DSL query (OpenSearch)
```json
POST /wazuh-alerts-*/_search
{
  "query": { … }
}
```

### Dashboard filter (KQL)
```
agent.name : "…" AND rule.id : "…" AND @timestamp >= "…"
```

---

## 4. Findings

| Metric | Value |
|---|---|
| Alert count | N |
| Custom rule fired | 100xxx (Y/N) |
| Built-in rule matched | 61xxx / 92xxx / … |
| Highest level | X |
| MITRE tag confirmed | Txxxx |

Raw alert JSON (rút gọn):
```json
{
  "@timestamp": "…",
  "rule": {"id": "…", "level": …, "description": "…"},
  "data": { … }
}
```

---

## 5. Timeline reconstruction

Chronological từ raw event (Sysmon/auditd), không phải chỉ alert:

| T+  | Event | Source | Chi tiết |
|-----|-------|--------|----------|
| T+0s | Process create | Sysmon EID 1 | parentImage=`cmd.exe`, image=`powershell.exe`, cmdline=… |
| T+1s | Network connect | Sysmon EID 3 | destination=… |
| T+2s | File create | Sysmon EID 11 | file=… |
| T+3s | Registry set | Sysmon EID 13 | key=…, value=… |

Query để lấy timeline:
```
agent.name : "win-ep-01" AND @timestamp >= "T0" AND @timestamp <= "T0+60s"
```

---

## 6. IOC list

| Type | Value | Source field | Notes |
|---|---|---|---|
| SHA256 | … | `data.win.eventdata.hashes` | binary attacker dropped |
| IP | … | `data.win.eventdata.destinationIp` | C2 nghi ngờ |
| Domain | … | `data.win.eventdata.queryName` | DNS query |
| File | … | `data.win.eventdata.targetFilename` | staging location |

---

## 7. Enrichment

Chạy tool: `python enrich.py -r 100xxx --writeback`

| IOC | Provider | Verdict | Score | Link |
|---|---|---|---|---|
| … | VirusTotal | malicious | 15/91 | https://… |
| … | AbuseIPDB | malicious | 100/100 | https://… |

---

## 8. MITRE mapping

| Field | Value |
|---|---|
| Tactic | Execution |
| Technique | T1059 Command & Scripting Interpreter |
| Sub-technique | T1059.001 PowerShell |
| Reference | https://attack.mitre.org/techniques/T1059/001/ |

Kill chain step (nếu có sub-events): reconstruction xem section 5.

---

## 9. Detection assessment

- **Rule custom 100xxx**:
  - Fired: (Y/N)
  - Đúng level? (Y/N — nếu quá thấp/cao đề xuất chỉnh)
  - False positive tiềm năng: …
- **Gap detection**: technique có sub-command nào không match rule không? (VD `-EncodedCommand` viết hoa vs thường)
- **Suggested rule tuning**: … (VD thêm regex, thêm parent context)

---

## 10. Remediation (nếu là thật)

1. **Contain**: isolate host qua Wazuh active-response `firewall-drop`
2. **Eradicate**: kill process, xoá autorun key, gỡ scheduled task
3. **Recover**: rebuild host nếu compromise sâu, reset credential user
4. **Lessons learned**: cập nhật rule 100xxx nếu detection có gap

---

## 11. Screenshots (optional)

- Dashboard alert view
- Discover timeline
- Enrichment console output

---

## 12. References

- Atomic test source: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/Txxxx/Txxxx.md
- MITRE ATT&CK: https://attack.mitre.org/techniques/Txxxx/
- Wazuh docs: https://documentation.wazuh.com/
