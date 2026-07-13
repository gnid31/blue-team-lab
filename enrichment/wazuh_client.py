"""Wazuh Indexer client — fetch alerts từ OpenSearch."""
from __future__ import annotations
import urllib3
from typing import Optional

import requests


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WazuhIndexer:
    def __init__(self, url: str, user: str, password: str, verify_tls: bool = False):
        self.url = url.rstrip("/")
        self.session = requests.Session()
        self.session.auth = (user, password)
        self.session.verify = verify_tls

    def search(
        self,
        min_level: int = 7,
        agent: Optional[str] = None,
        rule_id: Optional[str] = None,
        since: str = "now-1h",
        limit: int = 20,
    ) -> list[dict]:
        """Fetch alerts filtered by level/agent/rule/time. Returns raw hits."""
        must: list[dict] = [
            {"range": {"rule.level": {"gte": min_level}}},
            {"range": {"@timestamp": {"gte": since}}},
        ]
        if agent:
            must.append({"match": {"agent.name": agent}})
        if rule_id:
            must.append({"match": {"rule.id": rule_id}})

        body = {
            "size": limit,
            "sort": [{"@timestamp": "desc"}],
            "query": {"bool": {"must": must}},
        }

        r = self.session.post(
            f"{self.url}/wazuh-alerts-*/_search",
            json=body,
            timeout=30,
        )
        r.raise_for_status()
        return (r.json().get("hits") or {}).get("hits") or []
