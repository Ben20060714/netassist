from __future__ import annotations

import csv
import json
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any

from .models import IDSAlert, ScanReport


def _alert_from_mapping(item: dict[str, Any]) -> IDSAlert:
    """Normalize common Suricata/Snort-style exported alert fields."""
    nested = item.get("alert") if isinstance(item.get("alert"), dict) else {}
    return IDSAlert(
        timestamp=str(item.get("timestamp", item.get("time", "unknown"))),
        signature=str(nested.get("signature", item.get("signature", item.get("msg", "unknown")))),
        severity=str(nested.get("severity", item.get("severity", "unknown"))),
        category=str(nested.get("category", item.get("category", "unknown"))),
        source_ip=str(item.get("src_ip", item.get("source_ip", ""))),
        destination_ip=str(item.get("dest_ip", item.get("destination_ip", ""))),
        destination_port=str(item.get("dest_port", item.get("destination_port", ""))),
        action=str(nested.get("action", item.get("action", ""))),
    )


def load_alerts(path: Path) -> list[IDSAlert]:
    """Read a JSON array, JSONL file, or CSV export without contacting an IDS."""
    if path.suffix.lower() == ".csv":
        with path.open(newline="", encoding="utf-8") as handle:
            return [_alert_from_mapping(row) for row in csv.DictReader(handle)]
    raw = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".jsonl", ".ndjson"}:
        items = [json.loads(line) for line in raw.splitlines() if line.strip()]
    else:
        data = json.loads(raw)
        items = data if isinstance(data, list) else data.get("events", [data])
    return [_alert_from_mapping(item) for item in items if isinstance(item, dict)]


def _target_match(alert: IDSAlert, target: str) -> bool:
    values = {alert.source_ip, alert.destination_ip}
    try:
        scope = ip_network(target, strict=False)
        return any(ip_address(value) in scope for value in values if value)
    except ValueError:
        return target in values


def correlate_alerts(alerts: list[IDSAlert], report: ScanReport) -> list[IDSAlert]:
    """Keep alerts involving the authorized target; no evasive action is taken."""
    return [alert for alert in alerts if _target_match(alert, report.target)]
