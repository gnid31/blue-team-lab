"""Wazuh Indexer client — fetch alerts từ OpenSearch + writeback verdict."""
from __future__ import annotations
import datetime as _dt
import urllib3
from typing import Optional

import requests


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


VERDICT_INDEX_PREFIX = "enrichment-verdicts"

VERDICT_INDEX_TEMPLATE = {
    "index_patterns": [f"{VERDICT_INDEX_PREFIX}-*"],
    "priority": 100,
    "template": {
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "alert_id": {"type": "keyword"},
                "alert_timestamp": {"type": "date"},
                "agent_name": {"type": "keyword"},
                "rule_id": {"type": "keyword"},
                "rule_level": {"type": "integer"},
                "rule_description": {"type": "text"},
                "mitre": {"type": "keyword"},
                "ioc_type": {"type": "keyword"},
                "ioc_value": {"type": "keyword"},
                "ioc_source_field": {"type": "keyword"},
                "provider": {"type": "keyword"},
                "verdict_label": {"type": "keyword"},
                "malicious": {"type": "integer"},
                "total": {"type": "integer"},
                "score": {"type": "keyword"},
                "link": {"type": "keyword"},
            }
        },
    },
}


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

    def ensure_verdict_index_template(self) -> None:
        """Tạo/update index template `enrichment-verdicts-*` (idempotent)."""
        r = self.session.put(
            f"{self.url}/_index_template/enrichment-verdicts-template",
            json=VERDICT_INDEX_TEMPLATE,
            timeout=30,
        )
        r.raise_for_status()

    def write_verdict(self, doc: dict) -> str:
        """POST 1 verdict document. Trả về _id document."""
        today = _dt.datetime.now(_dt.timezone.utc).strftime("%Y.%m.%d")
        idx = f"{VERDICT_INDEX_PREFIX}-{today}"
        r = self.session.post(
            f"{self.url}/{idx}/_doc",
            json=doc,
            timeout=30,
        )
        r.raise_for_status()
        return r.json().get("_id", "")
