import json

from netassist.ids import correlate_alerts, load_alerts
from netassist.models import Host, ScanReport
from datetime import datetime


def test_load_and_correlate_suricata_json(tmp_path):
    source = tmp_path / "eve.jsonl"
    source.write_text(json.dumps({
        "timestamp": "2026-10-08T10:30:00Z",
        "src_ip": "192.0.2.55",
        "dest_ip": "192.168.0.10",
        "dest_port": 443,
        "alert": {"signature": "Test rule", "severity": 2, "category": "Attempted Scan", "action": "allowed"},
    }) + "\n", encoding="utf-8")
    alerts = load_alerts(source)
    report = ScanReport("192.168.0.0/24", "service", datetime.now(), 1.0, [Host("192.168.0.10")])
    matched = correlate_alerts(alerts, report)
    assert len(matched) == 1
    assert matched[0].signature == "Test rule"
