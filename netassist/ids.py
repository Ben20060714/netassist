from __future__ import annotations

import csv
import json
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any

from .models import AlerteIDS, RapportScan


def _creer_alerte_depuis_donnees(donnees: dict[str, Any]) -> AlerteIDS:
    """Normalize common Suricata/Snort-style exported alert fields."""
    alerte = donnees.get("alert") if isinstance(donnees.get("alert"), dict) else {}
    return AlerteIDS(
        horodatage=str(donnees.get("timestamp", donnees.get("time", "inconnu"))),
        signature=str(alerte.get("signature", donnees.get("signature", donnees.get("msg", "inconnue")))),
        severite=str(alerte.get("severity", donnees.get("severity", "inconnue"))),
        categorie=str(alerte.get("category", donnees.get("category", "inconnue"))),
        adresse_source=str(donnees.get("src_ip", donnees.get("source_ip", ""))),
        adresse_destination=str(donnees.get("dest_ip", donnees.get("destination_ip", ""))),
        port_destination=str(donnees.get("dest_port", donnees.get("destination_port", ""))),
        action=str(alerte.get("action", donnees.get("action", ""))),
    )


def charger_alertes(chemin: Path) -> list[AlerteIDS]:
    """Read a JSON array, JSONL file, or CSV export without contacting an IDS."""
    if chemin.suffix.lower() == ".csv":
        with chemin.open(newline="", encoding="utf-8") as fichier:
            return [_creer_alerte_depuis_donnees(ligne) for ligne in csv.DictReader(fichier)]
    contenu = chemin.read_text(encoding="utf-8")
    if chemin.suffix.lower() in {".jsonl", ".ndjson"}:
        elements = [json.loads(ligne) for ligne in contenu.splitlines() if ligne.strip()]
    else:
        donnees = json.loads(contenu)
        elements = donnees if isinstance(donnees, list) else donnees.get("events", [donnees])
    return [_creer_alerte_depuis_donnees(element) for element in elements if isinstance(element, dict)]


def _alerte_concerne_cible(alerte: AlerteIDS, cible: str) -> bool:
    valeurs = {alerte.adresse_source, alerte.adresse_destination}
    try:
        perimetre = ip_network(cible, strict=False)
        return any(ip_address(valeur) in perimetre for valeur in valeurs if valeur)
    except ValueError:
        return cible in valeurs


def correler_alertes(alertes: list[AlerteIDS], rapport: RapportScan) -> list[AlerteIDS]:
    """Keep alerts involving the authorized target; no evasive action is taken."""
    return [alerte for alerte in alertes if _alerte_concerne_cible(alerte, rapport.cible)]
