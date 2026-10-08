import json

from netassist.ids import charger_alertes, correler_alertes
from netassist.models import Hote, RapportScan
from datetime import datetime


def test_charger_et_corréler_json_suricata(tmp_path):
    chemin = tmp_path / "eve.jsonl"
    chemin.write_text(json.dumps({
        "timestamp": "2026-10-08T10:30:00Z",
        "src_ip": "192.0.2.55",
        "dest_ip": "192.168.0.10",
        "dest_port": 443,
        "alert": {"signature": "Test rule", "severity": 2, "category": "Attempted Scan", "action": "allowed"},
    }) + "\n", encoding="utf-8")
    alertes = charger_alertes(chemin)
    rapport = RapportScan("192.168.0.0/24", "service", datetime.now(), 1.0, [Hote("192.168.0.10")])
    correspondances = correler_alertes(alertes, rapport)
    assert len(correspondances) == 1
    assert correspondances[0].signature == "Test rule"
