"""CLI enrich: Wazuh alerts → IOC extract → VT/AbuseIPDB verdict → pretty console."""
from __future__ import annotations
import datetime as _dt
import os
import sys
from pathlib import Path

import click
from dotenv import load_dotenv
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cache import Cache
from ioc import ExtractedAlert, Ioc, extract_iocs
from providers import AbuseIPDB, Verdict, VirusTotal
from wazuh_client import WazuhIndexer


console = Console()

VERDICT_STYLE = {
    "malicious": "bold white on red",
    "suspicious": "bold black on yellow",
    "clean": "bold white on green",
    "unknown": "dim",
}


def _load_env() -> dict:
    env_path = Path(__file__).resolve().parent / ".env"
    if not env_path.exists():
        console.print(f"[red]Missing {env_path} — copy .env.example → .env và điền key[/red]")
        sys.exit(2)
    load_dotenv(env_path)
    required = ("WAZUH_INDEXER_URL", "WAZUH_INDEXER_USER", "WAZUH_INDEXER_PASS",
                "VT_API_KEY", "ABUSEIPDB_API_KEY", "CACHE_DB")
    cfg = {k: os.getenv(k, "") for k in required}
    cfg["CACHE_TTL_HOURS"] = int(os.getenv("CACHE_TTL_HOURS", "24"))
    cfg["WAZUH_INDEXER_VERIFY_TLS"] = os.getenv("WAZUH_INDEXER_VERIFY_TLS", "false").lower() == "true"
    missing = [k for k in required if not cfg[k] or cfg[k] == "CHANGE_ME"]
    if missing:
        console.print(f"[red]Missing env vars: {missing}[/red]")
        sys.exit(2)
    return cfg


def _enrich_ioc(ioc: Ioc, vt: VirusTotal, abuse: AbuseIPDB, cache: Cache) -> list[Verdict]:
    """Trả về list Verdict cho 1 IOC. Với IP: cả 2 provider; với hash/domain: chỉ VT."""
    verdicts: list[Verdict] = []

    # VirusTotal
    cached = cache.get(ioc.value, "virustotal")
    if cached:
        verdicts.append(Verdict(**cached))
    else:
        v = vt.lookup(ioc.type, ioc.value)
        cache.put(ioc.value, "virustotal", v.__dict__)
        verdicts.append(v)

    # AbuseIPDB (chỉ IP)
    if ioc.type == "ip":
        cached = cache.get(ioc.value, "abuseipdb")
        if cached:
            verdicts.append(Verdict(**cached))
        else:
            v = abuse.lookup(ioc.type, ioc.value)
            cache.put(ioc.value, "abuseipdb", v.__dict__)
            verdicts.append(v)

    return verdicts


def _render_alert(ea: ExtractedAlert, enriched: dict[str, list[Verdict]]) -> None:
    """Vẽ 1 alert + verdict lên console."""
    mitre = ", ".join(ea.mitre) if ea.mitre else "-"
    header = (
        f"[bold]{ea.timestamp}[/bold]  "
        f"agent=[cyan]{ea.agent}[/cyan]  "
        f"rule=[magenta]{ea.rule_id}[/magenta] "
        f"lvl=[bold yellow]{ea.rule_level}[/bold yellow]  "
        f"mitre=[green]{mitre}[/green]"
    )
    body = f"[dim]{ea.rule_desc}[/dim]"
    console.print(Panel(f"{header}\n{body}", box=box.ROUNDED, expand=False))

    if not ea.iocs:
        console.print("  [dim](no IOCs extracted)[/dim]\n")
        return

    tbl = Table(box=box.MINIMAL, show_header=True, header_style="bold cyan")
    tbl.add_column("type", width=8)
    tbl.add_column("value", overflow="fold", max_width=50)
    tbl.add_column("provider", width=11)
    tbl.add_column("verdict", width=11)
    tbl.add_column("score", width=8, justify="right")
    tbl.add_column("info / link", overflow="fold")

    for ioc in ea.iocs:
        verdicts = enriched.get(ioc.key(), [])
        if not verdicts:
            tbl.add_row(ioc.type, ioc.value, "[dim]—[/dim]",
                        "[dim]dry-run[/dim]", "", f"[dim]source={ioc.source_field}[/dim]")
            continue
        for v in verdicts:
            style = VERDICT_STYLE.get(v.verdict_label, "")
            info = v.raw.get("as_owner") or v.raw.get("isp") or \
                   v.raw.get("countryCode") or v.raw.get("meaningful_name") or ""
            info_line = f"{info}\n[link={v.link}]{v.link}[/link]" if v.link else info
            tbl.add_row(
                ioc.type, ioc.value, v.provider,
                f"[{style}] {v.verdict_label} [/]",
                v.score(), info_line,
            )
    console.print(tbl)
    console.print()


@click.command()
@click.option("--min-level", "-l", type=int, default=7, show_default=True,
              help="Chỉ enrich alert có rule.level ≥ giá trị này")
@click.option("--agent", "-a", default=None, help="Filter theo agent name")
@click.option("--rule-id", "-r", default=None, help="Filter theo rule ID cụ thể")
@click.option("--since", "-s", default="now-1h", show_default=True,
              help="Time range OpenSearch (vd: now-15m, now-24h)")
@click.option("--limit", "-n", type=int, default=10, show_default=True,
              help="Số alert tối đa fetch")
@click.option("--dry-run", is_flag=True, help="In IOC extract, không call API")
@click.option("--writeback/--no-writeback", default=False,
              help="Ghi verdict vào Wazuh Indexer (index enrichment-verdicts-YYYY.MM.DD)")
def main(min_level, agent, rule_id, since, limit, dry_run, writeback):
    """Fetch Wazuh alerts → extract IOCs → enrich với VirusTotal + AbuseIPDB."""
    cfg = _load_env()

    console.rule(f"[bold]Blue Team Lab — IOC Enrichment[/bold]  "
                 f"(min_level={min_level}, since={since}, limit={limit})")

    idx = WazuhIndexer(
        cfg["WAZUH_INDEXER_URL"], cfg["WAZUH_INDEXER_USER"],
        cfg["WAZUH_INDEXER_PASS"], verify_tls=cfg["WAZUH_INDEXER_VERIFY_TLS"],
    )

    try:
        hits = idx.search(min_level=min_level, agent=agent, rule_id=rule_id,
                          since=since, limit=limit)
    except Exception as e:
        console.print(f"[red]Failed to fetch alerts:[/red] {e}")
        console.print("[dim]Tip: nếu chạy trên Kali, mở SSH tunnel trước:[/dim]")
        console.print("[dim]  ssh -N -L 9200:localhost:9200 namth@43.228.215.234 &[/dim]")
        sys.exit(1)

    console.print(f"[green]Fetched {len(hits)} alerts[/green]\n")
    if not hits:
        return

    extracted = [extract_iocs(h) for h in hits]
    total_iocs = sum(len(e.iocs) for e in extracted)
    unique_iocs = {ioc.key(): ioc for e in extracted for ioc in e.iocs}
    console.print(f"Extracted [bold]{total_iocs}[/bold] IOC instances "
                  f"([bold]{len(unique_iocs)}[/bold] unique)\n")

    if dry_run:
        for e in extracted:
            _render_alert(e, {})
        return

    vt = VirusTotal(cfg["VT_API_KEY"])
    abuse = AbuseIPDB(cfg["ABUSEIPDB_API_KEY"])
    cache = Cache(cfg["CACHE_DB"], ttl_hours=cfg["CACHE_TTL_HOURS"])

    enriched: dict[str, list[Verdict]] = {}
    with console.status("[cyan]Enriching IOCs …[/cyan]") as st:
        for i, (key, ioc) in enumerate(unique_iocs.items(), 1):
            st.update(f"[cyan]Enriching {i}/{len(unique_iocs)}: {ioc.type}={ioc.value}[/cyan]")
            enriched[key] = _enrich_ioc(ioc, vt, abuse, cache)

    for e in extracted:
        _render_alert(e, enriched)

    # ---- Writeback to Indexer (Option A) ----
    if writeback:
        try:
            idx.ensure_verdict_index_template()
        except Exception as e:
            console.print(f"[red]Failed to create index template:[/red] {e}")
        else:
            written = 0
            now = _dt.datetime.now(_dt.timezone.utc)
            now_iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")
            for ea in extracted:
                for ioc in ea.iocs:
                    for v in enriched.get(ioc.key(), []):
                        doc = {
                            "@timestamp": now_iso,
                            "alert_id": ea.alert_id,
                            "alert_timestamp": ea.timestamp,
                            "agent_name": ea.agent,
                            "rule_id": ea.rule_id,
                            "rule_level": ea.rule_level,
                            "rule_description": ea.rule_desc,
                            "mitre": ea.mitre,
                            "ioc_type": ioc.type,
                            "ioc_value": ioc.value,
                            "ioc_source_field": ioc.source_field,
                            "provider": v.provider,
                            "verdict_label": v.verdict_label,
                            "malicious": v.malicious,
                            "total": v.total,
                            "score": v.score(),
                            "link": v.link,
                        }
                        try:
                            idx.write_verdict(doc)
                            written += 1
                        except Exception as e:
                            console.print(f"[red]Writeback failed:[/red] {e}")
            console.print(f"[green]Writeback: indexed {written} verdicts into "
                          f"enrichment-verdicts-{now:%Y.%m.%d}[/green]")

    cache.close()

    # Summary
    all_v = [v for lst in enriched.values() for v in lst]
    mal = sum(1 for v in all_v if v.verdict_label == "malicious")
    sus = sum(1 for v in all_v if v.verdict_label == "suspicious")
    console.rule(f"[bold]Summary[/bold]  "
                 f"malicious=[red]{mal}[/red]  suspicious=[yellow]{sus}[/yellow]  "
                 f"total_verdicts={len(all_v)}")


if __name__ == "__main__":
    main()
