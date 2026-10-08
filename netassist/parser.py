from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

from .models import Hote, RapportScan

_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def analyser_xml_nmap(chemin: Path, *, cible: str, profil: str) -> RapportScan:
    racine = ET.parse(chemin).getroot()
    hotes: list[Hote] = []
    for noeud in racine.findall("host"):
        adresse = next(
            (element.get("addr", "") for element in noeud.findall("address") if element.get("addrtype") == "ipv4"),
            next((element.get("addr", "") for element in noeud.findall("address")), "inconnu"),
        )
        statut = noeud.find("status")
        etat = statut.get("state", "inconnu") if statut is not None else "inconnu"
        noms_hotes = [element.get("name", "") for element in noeud.findall("hostnames/hostname")]
        ports: list[dict[str, str]] = []
        scripts: list[str] = []
        cves: set[str] = set()
        for port in noeud.findall("ports/port"):
            service = port.find("service")
            enregistrement = {
                "port": port.get("portid", "?"),
                "protocol": port.get("protocol", "?"),
                "state": port.findtext("state[@state]", default="inconnu"),
                "service": service.get("name", "") if service is not None else "",
                "product": service.get("product", "") if service is not None else "",
                "version": service.get("version", "") if service is not None else "",
            }
            ports.append(enregistrement)
            for script in port.findall("script"):
                contenu = ET.tostring(script, encoding="unicode")
                scripts.append(script.get("id", "") + ": " + " ".join("".join(contenu.split()).split("<"))[:400])
                cves.update(cve.upper() for cve in _CVE.findall(contenu))
        for script in noeud.findall("hostscript/script"):
            contenu = ET.tostring(script, encoding="unicode")
            scripts.append(script.get("id", "") + ": " + " ".join("".join(contenu.split()).split("<"))[:400])
            cves.update(cve.upper() for cve in _CVE.findall(contenu))
        hotes.append(Hote(adresse, etat, noms_hotes, ports, sorted(cves), scripts))

    debut = datetime.fromtimestamp(float(racine.get("start", "0"))) if racine.get("start") else datetime.now()
    fin = racine.find("runstats/finished")
    duree = float(fin.get("elapsed")) if fin is not None and fin.get("elapsed") else None
    return RapportScan(cible, profil, debut, duree, hotes, racine.get("args", ""), str(chemin))
