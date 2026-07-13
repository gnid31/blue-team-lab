"""IOC extraction from Wazuh alert JSON."""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Any, Iterable


IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b",
    re.IGNORECASE,
)
# Extensions không phải TLD — filter khỏi domain match (Windows binary, file ext)
NON_TLD_SUFFIX = {
    "exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "js", "hta", "msi",
    "log", "tmp", "cab", "dat", "ini", "conf", "cfg", "yml", "yaml",
    "xml", "json", "txt", "md", "png", "jpg", "jpeg", "gif", "pdf",
    "zip", "rar", "gz", "tar", "7z",
    "py", "sh", "rb", "go", "rs", "c", "h", "cpp", "hpp",
    "so", "ko", "img", "iso", "bin",
}
MD5_RE = re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE)
SHA1_RE = re.compile(r"\b[a-f0-9]{40}\b", re.IGNORECASE)
SHA256_RE = re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE)

# RFC1918 / loopback / multicast to skip (không có ý nghĩa TI)
PRIVATE_NETS = (
    "10.", "127.", "169.254.", "224.", "255.",
    "192.168.",
    *[f"172.{i}." for i in range(16, 32)],
    "0.0.0.0",
)

# Extension domain phổ biến trong log Windows / Linux (skip để giảm noise)
NOISE_DOMAINS = {
    "microsoft.com", "windows.com", "windowsupdate.com",
    "office.com", "office365.com", "live.com", "msn.com",
    "google.com", "gstatic.com", "googleapis.com",
    "ubuntu.com", "canonical.com", "debian.org",
    "wazuh.com",
}


@dataclass
class Ioc:
    """1 IOC extracted from alert."""
    type: str          # "ip" | "domain" | "md5" | "sha1" | "sha256"
    value: str
    source_field: str  # field name trong alert JSON (để trace back)

    def key(self) -> str:
        return f"{self.type}:{self.value.lower()}"


@dataclass
class ExtractedAlert:
    alert_id: str
    timestamp: str
    agent: str
    rule_id: str
    rule_level: int
    rule_desc: str
    mitre: list[str] = field(default_factory=list)
    iocs: list[Ioc] = field(default_factory=list)
    raw: dict = field(default_factory=dict)


def _is_public_ip(ip: str) -> bool:
    return not any(ip.startswith(p) for p in PRIVATE_NETS)


def _is_meaningful_domain(d: str) -> bool:
    d = d.lower().rstrip(".")
    if d in NOISE_DOMAINS:
        return False
    tld = d.rsplit(".", 1)[-1]
    if tld in NON_TLD_SUFFIX:
        return False
    return not any(d.endswith("." + n) or d == n for n in NOISE_DOMAINS)


def _walk_strings(obj: Any) -> Iterable[tuple[str, str]]:
    """Yield (dotted_path, string_value) cho mọi string trong nested dict/list."""
    def _walk(node, path):
        if isinstance(node, dict):
            for k, v in node.items():
                yield from _walk(v, f"{path}.{k}" if path else k)
        elif isinstance(node, list):
            for i, v in enumerate(node):
                yield from _walk(v, f"{path}[{i}]")
        elif isinstance(node, str):
            yield path, node
    yield from _walk(obj, "")


def extract_iocs(alert: dict) -> ExtractedAlert:
    """Từ 1 Wazuh alert JSON, extract structured IOCs."""
    src = alert.get("_source", alert)
    rule = src.get("rule", {}) or {}
    agent = (src.get("agent") or {}).get("name", "unknown")

    ea = ExtractedAlert(
        alert_id=alert.get("_id", "n/a"),
        timestamp=src.get("@timestamp", ""),
        agent=agent,
        rule_id=str(rule.get("id", "0")),
        rule_level=int(rule.get("level", 0)),
        rule_desc=rule.get("description", "")[:200],
        mitre=[m for m in (rule.get("mitre", {}) or {}).get("id", []) if m],
        raw=src,
    )

    seen: set[str] = set()

    def _add(ioc: Ioc) -> None:
        if ioc.key() not in seen:
            seen.add(ioc.key())
            ea.iocs.append(ioc)

    for path, text in _walk_strings(src):
        # Skip các field noise phổ biến
        low = path.lower()
        if any(x in low for x in ("timestamp", "@timestamp", "manager.name", "location")):
            continue

        for m in IPV4_RE.finditer(text):
            ip = m.group(0)
            if _is_public_ip(ip):
                _add(Ioc("ip", ip, path))

        for h_re, h_type in ((SHA256_RE, "sha256"), (SHA1_RE, "sha1"), (MD5_RE, "md5")):
            for m in h_re.finditer(text):
                _add(Ioc(h_type, m.group(0).lower(), path))

        for m in DOMAIN_RE.finditer(text):
            d = m.group(0).lower()
            # Loại IPv4 match trùng DOMAIN_RE
            if IPV4_RE.fullmatch(d):
                continue
            if _is_meaningful_domain(d):
                _add(Ioc("domain", d, path))

    return ea
