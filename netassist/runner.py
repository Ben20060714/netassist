from __future__ import annotations

import shutil
import subprocess
from collections.abc import Callable
from dataclasses import asdict
import json
from pathlib import Path

from .commands import ProfilAnalyse, construire_commande
from .ids import charger_alertes, correler_alertes
from .parser import analyser_xml_nmap
from .render import ecrire_rapport
from .security import valider_cible


class LanceurNmap:
    def __init__(self, racine_sortie: Path, journaliser: Callable[[str], None] = print) -> None:
        self.racine_sortie = racine_sortie
        self.journaliser = journaliser

    def lancer(
        self,
        cible: str,
        profil: ProfilAnalyse,
        chemin_alertes_ids: Path | None = None,
        perimetre_ports: str | None = None,
    ) -> Path:
        cible = valider_cible(cible)
        if shutil.which("nmap") is None:
            raise RuntimeError("nmap est introuvable dans le PATH.")
        dossier_scan = self.racine_sortie / self._nom_dossier(cible, profil.nom)
        dossier_scan.mkdir(parents=True, exist_ok=False)
        base = dossier_scan / "scan"
        commande = construire_commande(profil, cible, str(base), perimetre_ports)
        self.journaliser("Exécution de Nmap en cours…")
        resultat = subprocess.run(commande, text=True, capture_output=True, check=False)
        dossier_scan.joinpath("command.stderr.txt").write_text(resultat.stderr, encoding="utf-8")
        dossier_scan.joinpath("command.stdout.txt").write_text(resultat.stdout, encoding="utf-8")
        if resultat.returncode != 0:
            raise RuntimeError(f"Nmap a échoué (code {resultat.returncode}). Voir command.stderr.txt.")
        chemin_xml = dossier_scan / "scan.xml"
        if not chemin_xml.exists():
            raise RuntimeError("Nmap n'a pas produit le fichier XML attendu.")
        shutil.copyfile(dossier_scan / "scan.nmap", dossier_scan / "scan.txt")
        rapport = analyser_xml_nmap(chemin_xml, cible=cible, profil=profil.nom)
        if chemin_alertes_ids is not None:
            rapport.source_ids = str(chemin_alertes_ids)
            rapport.alertes_ids = correler_alertes(charger_alertes(chemin_alertes_ids), rapport)
            dossier_scan.joinpath("ids-alerts.json").write_text(
                json.dumps([asdict(alerte) for alerte in rapport.alertes_ids], ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        ecrire_rapport(rapport, dossier_scan)
        return dossier_scan

    @staticmethod
    def _nom_dossier(cible: str, profil: str) -> str:
        nom_sure = "".join(caractere if caractere.isalnum() else "_" for caractere in cible).strip("_")
        from datetime import datetime

        return f"{datetime.now():%Y%m%d_%H%M%S}_{nom_sure}_{profil}"
