from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(slots=True)
class Hote:
    adresse: str
    etat: str = "inconnu"
    noms_hotes: list[str] = field(default_factory=list)
    ports: list[dict[str, str]] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)


@dataclass(slots=True)
class AlerteIDS:
    horodatage: str
    signature: str
    severite: str = "inconnue"
    categorie: str = "inconnue"
    adresse_source: str = ""
    adresse_destination: str = ""
    port_destination: str = ""
    action: str = ""


@dataclass(slots=True)
class RapportScan:
    cible: str
    profil: str
    debut: datetime
    duree_secondes: float | None
    hotes: list[Hote]
    arguments_nmap: str = ""
    source_xml: str = ""
    alertes_ids: list[AlerteIDS] = field(default_factory=list)
    source_ids: str = ""

    @property
    def cves(self) -> list[str]:
        return sorted({cve for hote in self.hotes for cve in hote.cves})

    @property
    def hotes_actifs(self) -> list[Hote]:
        return [hote for hote in self.hotes if hote.etat == "up"]
