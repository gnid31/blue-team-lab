"""TI providers: VirusTotal v3 + AbuseIPDB v2."""
from __future__ import annotations
import time
from dataclasses import dataclass
from typing import Optional

import requests


@dataclass
class Verdict:
    provider: str
    ioc_type: str
    value: str
    malicious: int          # 0..N (số engine flag / confidence score)
    total: int              # tổng engine / max score
    verdict_label: str      # "clean" | "suspicious" | "malicious" | "unknown"
    link: str
    raw: dict

    def score(self) -> str:
        return f"{self.malicious}/{self.total}"


def _label_from_ratio(malicious: int, total: int, sus_threshold: float = 0.05,
                     mal_threshold: float = 0.15) -> str:
    if total == 0:
        return "unknown"
    ratio = malicious / total
    if ratio >= mal_threshold:
        return "malicious"
    if ratio >= sus_threshold or malicious >= 1:
        return "suspicious"
    return "clean"


class VirusTotal:
    """VT v3. Free tier: 4 req/min, 500 req/day."""
    BASE = "https://www.virustotal.com/api/v3"
    MIN_INTERVAL = 15.5   # ~ 4 req/min = 1 req / 15s (thêm buffer)

    def __init__(self, api_key: str):
        self.api_key = api_key
        self._last_call = 0.0
        self._session = requests.Session()
        self._session.headers.update({"x-apikey": api_key, "accept": "application/json"})

    def _rate_limit(self) -> None:
        elapsed = time.time() - self._last_call
        if elapsed < self.MIN_INTERVAL:
            time.sleep(self.MIN_INTERVAL - elapsed)
        self._last_call = time.time()

    def _get(self, endpoint: str) -> Optional[dict]:
        self._rate_limit()
        try:
            r = self._session.get(f"{self.BASE}/{endpoint}", timeout=30)
        except requests.RequestException as e:
            return {"error": str(e)}
        if r.status_code == 404:
            return {"not_found": True}
        if r.status_code == 429:
            time.sleep(30)
            return {"rate_limited": True}
        if r.status_code >= 400:
            return {"error": f"HTTP {r.status_code}: {r.text[:200]}"}
        return r.json()

    def lookup(self, ioc_type: str, value: str) -> Verdict:
        if ioc_type in ("md5", "sha1", "sha256"):
            endpoint = f"files/{value}"
        elif ioc_type == "ip":
            endpoint = f"ip_addresses/{value}"
        elif ioc_type == "domain":
            endpoint = f"domains/{value}"
        else:
            return Verdict("virustotal", ioc_type, value, 0, 0, "unknown",
                           "", {"error": "unsupported ioc type"})

        data = self._get(endpoint)
        if not data or "error" in data or data.get("rate_limited"):
            return Verdict("virustotal", ioc_type, value, 0, 0, "unknown",
                           "", data or {})
        if data.get("not_found"):
            return Verdict("virustotal", ioc_type, value, 0, 0, "unknown",
                           self._link(ioc_type, value), {"not_found": True})

        attr = (data.get("data") or {}).get("attributes", {})
        stats = attr.get("last_analysis_stats", {}) or {}
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))
        total = malicious + suspicious + harmless + undetected

        return Verdict(
            provider="virustotal",
            ioc_type=ioc_type,
            value=value,
            malicious=malicious + suspicious,
            total=total,
            verdict_label=_label_from_ratio(malicious + suspicious, total),
            link=self._link(ioc_type, value),
            raw={
                "stats": stats,
                "reputation": attr.get("reputation"),
                "last_analysis_date": attr.get("last_analysis_date"),
                "meaningful_name": attr.get("meaningful_name"),
                "type_description": attr.get("type_description"),
                "country": attr.get("country"),
                "as_owner": attr.get("as_owner"),
            },
        )

    @staticmethod
    def _link(ioc_type: str, value: str) -> str:
        if ioc_type in ("md5", "sha1", "sha256"):
            return f"https://www.virustotal.com/gui/file/{value}"
        if ioc_type == "ip":
            return f"https://www.virustotal.com/gui/ip-address/{value}"
        if ioc_type == "domain":
            return f"https://www.virustotal.com/gui/domain/{value}"
        return ""


class AbuseIPDB:
    """AbuseIPDB v2. Free tier: 1000 req/day. Không phải per-min limit."""
    BASE = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: str):
        self.api_key = api_key
        self._session = requests.Session()
        self._session.headers.update({"Key": api_key, "Accept": "application/json"})

    def lookup(self, ioc_type: str, value: str) -> Verdict:
        if ioc_type != "ip":
            return Verdict("abuseipdb", ioc_type, value, 0, 0, "unknown",
                           "", {"skipped": "abuseipdb only supports ip"})

        try:
            r = self._session.get(
                f"{self.BASE}/check",
                params={"ipAddress": value, "maxAgeInDays": 90, "verbose": ""},
                timeout=30,
            )
        except requests.RequestException as e:
            return Verdict("abuseipdb", ioc_type, value, 0, 0, "unknown", "", {"error": str(e)})

        if r.status_code == 429:
            return Verdict("abuseipdb", ioc_type, value, 0, 0, "unknown", "", {"rate_limited": True})
        if r.status_code >= 400:
            return Verdict("abuseipdb", ioc_type, value, 0, 0, "unknown", "",
                           {"error": f"HTTP {r.status_code}"})

        data = (r.json() or {}).get("data", {}) or {}
        score = int(data.get("abuseConfidenceScore", 0))
        # AbuseIPDB dùng 0..100 confidence; normalise vào label
        if score >= 75:
            label = "malicious"
        elif score >= 25:
            label = "suspicious"
        elif score > 0:
            label = "suspicious"
        else:
            label = "clean"

        return Verdict(
            provider="abuseipdb",
            ioc_type=ioc_type,
            value=value,
            malicious=score,
            total=100,
            verdict_label=label,
            link=f"https://www.abuseipdb.com/check/{value}",
            raw={
                "countryCode": data.get("countryCode"),
                "usageType": data.get("usageType"),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
                "totalReports": data.get("totalReports"),
                "lastReportedAt": data.get("lastReportedAt"),
            },
        )
