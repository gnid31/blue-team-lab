# Incident / Hunting Report — [ID]

> Format: aligned to **NIST SP 800-61 Rev. 2** (Computer Security Incident Handling Guide) with hunting-oriented adaptations.
>
> Field name → NIST section reference.

## NIST SP 800-61r2 section mapping

Cross-reference giữa section trong report này và section chính thức của NIST SP 800-61r2:

| Report section | NIST §ref | NIST section title |
|---|---|---|
| 1. Incident Identification | §3.2.5 | Incident Documentation |
| 2. Incident Categorization | §3.2.1 | Attack Vectors |
| 3. Incident Prioritization | §3.2.6 | Incident Prioritization |
| 4. Detection & Analysis | §3.2 | Detection and Analysis (parent) |
| 5. Chronology / Timeline | §3.2.5 | Incident Documentation |
| 6. Scope | §3.2.4 | Incident Analysis |
| 7. Containment, Eradication, Recovery | §3.3 | Containment, Eradication, and Recovery |
| 8. Post-Incident Activity | §3.4 | Post-Incident Activity |
| 9. Communications Log | §3.2.7 | Incident Notification |

Source: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf

---

## 1. Incident Identification (NIST §3.2.5)

| Field | Value |
|---|---|
| **Report ID** | BTL-YYYY-NNN (Blue Team Lab, year, sequence) |
| **Detection timestamp (UTC)** | YYYY-MM-DDTHH:MM:SSZ |
| **Report timestamp (UTC)** | YYYY-MM-DDTHH:MM:SSZ |
| **Analyst / Handler** | (name / role) |
| **Status** | New \| In Progress \| Contained \| Eradicated \| Recovered \| **Closed** |
| **Confidence** | Low \| Medium \| High (analyst confidence trong finding) |

---

## 2. Incident Categorization (NIST §3.2.1)

| Field | Value |
|---|---|
| **Attack vector** | External \| Internal \| Web \| Email \| Removable Media \| Impersonation \| Improper Usage \| Loss/Theft \| Other |
| **Threat actor** | External \| Insider \| Simulated (Red Team / Atomic) \| Unknown |
| **NIST incident category** | DoS \| Malicious Code \| Unauthorized Access \| Improper Usage \| Reconnaissance \| Investigation |
| **MITRE ATT&CK Tactic** | (VD: Execution, Persistence) |
| **MITRE ATT&CK Technique** | Txxxx.xxx |
| **MITRE reference** | https://attack.mitre.org/techniques/Txxxx/ |

---

## 3. Incident Prioritization (NIST §3.2.6)

NIST-standard impact matrix:

| Dimension | Value | Justification |
|---|---|---|
| **Functional Impact** | None \| Low \| Medium \| High | (mức ảnh hưởng đến operation) |
| **Information Impact** | None \| Privacy Breach \| Proprietary Breach \| Integrity Loss | (data leak / tamper?) |
| **Recoverability** | Regular \| Supplemented \| Extended \| Not Recoverable | (nỗ lực phục hồi) |
| **Overall Priority** | **Low \| Medium \| High \| Critical** | (composite từ 3 dimension trên) |

Matrix mapping (theo NIST 800-61r2 Table 3-3):

```
                    │ Functional Impact
                    │ None    Low    Medium    High
────────────────────┼─────────────────────────────────
Info: None          │ Low    Low    Medium    High
Info: Privacy       │ Low    Med    Medium    High
Info: Proprietary   │ Med    Med    High      Critical
Info: Integrity     │ Med    High   High      Critical
```

---

## 4. Detection & Analysis (NIST §3.2)

### 4.1. Detection method

- Automated (rule ID `Nxxxxx` matched) \| Manual hunt \| TI feed \| User report
- **Sensor / Data source**: (Sysmon EID N, auditd key=X, Windows Security 4XXX, ...)

### 4.2. Hypothesis (nếu proactive hunt)

> Nếu <condition>, ta kỳ vọng thấy <observable> trong <log source>.

### 4.3. Hunt queries

**OpenSearch DSL**:
```json
POST /wazuh-alerts-*/_search
{ ... }
```

**Dashboard KQL**:
```
rule.id : "..." AND @timestamp >= "..."
```

### 4.4. Findings

| Metric | Value |
|---|---|
| Alert count | N |
| Custom rule fired | Nxxxxx (Y/N) |
| Highest severity level | N |
| MITRE tag confirmed | Txxxx.xxx |
| False positives concurrent | N |

**Sample event JSON** (rút gọn):
```json
{ "rule": { "id": "...", "level": ..., "mitre": {...} },
  "data": { ... } }
```

---

## 5. Chronology / Timeline (NIST §3.2.5)

Chronological reconstruction từ raw log:

| Timestamp (UTC) | Actor | Action | Source | Notes |
|---|---|---|---|---|
| T0 | attacker | ssh login | 4624 | user=labuser |
| T0+2s | attacker | powershell.exe -EncodedCommand ... | Sysmon EID 1 | rule 100101 fires |
| T0+3s | ... | ... | ... | ... |

---

## 6. Scope (NIST §3.2.4)

### 6.1. Affected systems

| Hostname | IP | OS | Role | Impact |
|---|---|---|---|---|
| win-ep-01 | 192.168.154.164 | Windows 10 | Endpoint | (compromised / attempted / N/A) |

### 6.2. Affected users / accounts

| Account | Role | Notes |
|---|---|---|
| labuser | Local Administrator | (test account, isolated) |

### 6.3. Affected data

- **PII exposed**: (Yes/No — chi tiết)
- **Confidential business data**: (Yes/No)
- **Credentials / secrets**: (Yes/No)

### 6.4. Indicators of Compromise (IOCs)

| Type | Value | Source field | Notes |
|---|---|---|---|
| SHA256 | ... | data.win.eventdata.hashes | binary |
| IP | ... | data.win.eventdata.destinationIp | C2 nghi ngờ |
| Domain | ... | ... | ... |

### 6.5. TI Enrichment (VT / AbuseIPDB)

| IOC | Provider | Verdict | Score | Analysis date |
|---|---|---|---|---|
| ... | VirusTotal | malicious | 15/91 | ... |
| ... | AbuseIPDB | malicious | 100/100 | ... |

**Enrichment tool run**: `python enrich.py -r <rule_id> --writeback`
**Verdict indexed**: `enrichment-verdicts-YYYY.MM.DD`

---

## 7. Containment, Eradication, Recovery (NIST §3.3)

### 7.1. Containment strategy

- **Short-term**: (isolate host, block IP, kill process)
- **Long-term**: (patch, rotate credential, disable account)
- **Evidence preservation**: (memory dump, disk image, log snapshot)

### 7.2. Eradication actions

- [ ] Kill malicious process (PID X)
- [ ] Remove persistence artifact (Registry key, service, scheduled task)
- [ ] Revoke compromised credential
- [ ] Quarantine dropped file

### 7.3. Recovery actions

- [ ] Restore from clean backup (nếu compromise sâu)
- [ ] Rebuild host (nếu rootkit / kernel-level compromise)
- [ ] Reset password + rotate keys
- [ ] Re-enable services

### 7.4. Verification

- Alert level tương tự không tái xuất hiện trong X giờ sau
- Endpoint hoạt động bình thường
- Không thấy IOC trong log tail 24h

---

## 8. Post-Incident Activity (NIST §3.4)

### 8.1. Lessons learned

- Rule detection có gap không? (VD: technique variant không match regex)
- Time-to-detect (TTD): T_detect - T_attack
- Time-to-respond (TTR): T_contain - T_detect

### 8.2. Detection improvements

- [ ] Rule tuning: (VD: thêm regex pattern, giảm level FP)
- [ ] Sensor tuning: (VD: bật thêm Sysmon config)
- [ ] Correlation rule: (multi-event pattern)

### 8.3. Prevention measures

- [ ] Application whitelist
- [ ] Group Policy tighten (VD: PowerShell Constrained Language)
- [ ] Network segmentation
- [ ] Analyst training

---

## 9. Communications Log (NIST §3.2.7)

| Timestamp | To/From | Channel | Content summary |
|---|---|---|---|
| T+0m | SOC → Manager | Slack | Alert notification |
| T+10m | SOC → Business | Email | Impact assessment |
| T+30m | SOC → CIO | Phone | Escalation (nếu Critical) |

---

## 10. References & Attachments

- Atomic test source: https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/Txxxx/
- MITRE ATT&CK Txxxx: https://attack.mitre.org/techniques/Txxxx/
- Wazuh rule: [`wazuh-rules/local_rules.xml`](../wazuh-rules/local_rules.xml)
- Rule FP profile: [`wazuh-rules/RULES.md`](../wazuh-rules/RULES.md#rule-100xxx)
- NIST SP 800-61r2: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf
- Enrichment verdict index: `enrichment-verdicts-YYYY.MM.DD`
- Screenshots: `hunting-reports/screenshots/session-NN/` (optional)
