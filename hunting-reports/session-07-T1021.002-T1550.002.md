# Incident Report — BTL-2026-007

*NIST SP 800-61r2 aligned. Combined session #7 covering T1021.002 (SMB Lateral) + T1550.002 (Pass-the-Hash).*

## 1. Incident Identification

| Field | Value |
|---|---|
| **Report ID** | BTL-2026-007 |
| **Detection timestamp (UTC)** | 2026-07-13T14:55:14Z |
| **Analyst** | Claude |
| **Status** | **Closed** |
| **Confidence** | **High** — NTLM heuristic matched, RFC1918 source |

## 2. Categorization

| Field | Value |
|---|---|
| **Attack vector** | Lateral (Linux → Windows via SMB) |
| **NIST category** | Unauthorized Access — lateral movement |
| **MITRE tactic** | **Lateral Movement** (TA0008) + **Defense Evasion** (TA0005) |
| **MITRE technique** | **T1021.002 (SMB/Windows Admin Shares)** + **T1550.002 (Pass-the-Hash)** |

## 3. Prioritization

| Dim | Value | Justification |
|---|---|---|
| Functional | Medium | Lateral movement = attack chain progressing |
| Information | Privacy Breach (potential) | Auth via NTLM hash instead of password |
| Recoverability | Extended | Rotate NTLM hash = force password reset all users |
| **Priority** | **Critical** | Level 14, PtH signal |

## 4. Detection & Analysis

**Sensor**: Windows Security EID **4624** (Logon Success), LogonType=**3** (Network), authenticationPackageName=**NTLM**.

**Rule chain**: 60000 → 60103 → 60106 → 92652 → **92657 (built-in, level 6, T1550.002)** → **100106 (custom, level 14)**.

**Trigger** (từ Linux ep gnid → Windows ep labuser):
```bash
echo BlueLab2026! | smbclient -L //192.168.154.164 -U labuser
```

**Findings**: **1 alert rule 100106 level 14 T1550.002**.

```json
{
  "rule": {"id": "100106", "level": 14, "mitre": {"id": ["T1550.002"]}},
  "data": {"win": {"eventdata": {
    "targetUserName": "labuser",
    "ipAddress": "192.168.154.166",
    "workstationName": "linux-ep-01",
    "logonType": "3",
    "authenticationPackageName": "NTLM",
    "logonProcessName": "NtLmSsp"
  }}}
}
```

**Note**: rule 100103 (T1021.002) không fire riêng biệt vì Wazuh rule engine chọn child có level cao nhất (100106 level 14 > 100103 level 10) trong cùng chain. Alert 1 cái đã cover đủ 2 technique (T1021.002 + T1550.002).

## 5. Timeline

| T | Actor | Action |
|---|---|---|
| T+0 | gnid (linux-ep) | `smbclient -L //win-ep -U labuser` |
| T+1s | Windows LSA | Receive NTLM auth from linux-ep-01 (192.168.154.166) |
| T+2s | Windows Security | Log 4624 LogonType 3 NTLM |
| **T+3s** | Manager | **Rule 100106 level 14 fires** |

## 6. Scope

- **Source**: linux-ep-01 (192.168.154.166) via smbclient
- **Target**: win-ep-01 (192.168.154.164), account `labuser`
- **IOCs**:
  - Source IP `192.168.154.166` (Linux VM, internal lab)
  - Target account `labuser` (Admin group)
  - NTLM auth from workstationName=`linux-ep-01` (unusual — Windows client dùng Kerberos)
- **Enrichment**: skip (nội bộ RFC1918 IP — VT/AbuseIPDB không có data)

## 7. Containment/Eradication

- **Contain**: block SMB port 445 inbound trên win-ep-01 (`New-NetFirewallRule -DisplayName "Block-SMB" -Direction Inbound -LocalPort 445 -Action Block`)
- **Investigate**:
  - Grep memory dump LSASS trên win-ep-01 tìm evidence Mimikatz đã dump hash
  - Check Kerberos preferred setting — nếu NTLM là fallback path, disable NTLMv1
- **Eradicate**: force password reset labuser + all users; revoke Kerberos tickets (`klist purge`)
- **Recover**: enable Kerberos-only auth qua GPO ("Restrict NTLM: Outgoing NTLM traffic to remote servers = Deny all")

## 8. Post-Incident

- **✅ Rule 100106 fire lần đầu — nhờ chain from 92657 built-in** (best practice)
- **Rule 100103 dedup by design**: khi 100106 (level 14) match, 100103 (level 10) không sinh alert riêng — 1 event / 1 alert
- **Detection improvement**: correlation rule level 15 nếu ≥3 host bị PtH login trong 1h
- **Prevention**:
  - Disable NTLM auth cho non-domain user
  - Enforce SMB signing
  - LAPS (Local Admin Password Solution) để mỗi máy có admin password khác nhau

## 9. Communications

Level 14 → auto-page SOC lead + notify IT security manager.

## 10. References

- MITRE T1021.002: https://attack.mitre.org/techniques/T1021/002/
- MITRE T1550.002: https://attack.mitre.org/techniques/T1550/002/
- Rule: `wazuh-rules/local_rules.xml` — 100103, 100106
- Built-in reference: rule 92657 (Wazuh 4.9 `0840-win_event_channel.xml`)
