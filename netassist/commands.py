from __future__ import annotations

from dataclasses import dataclass
import re


@dataclass(frozen=True, slots=True)
class ProfilAnalyse:
    nom: str
    description: str
    options: tuple[str, ...]


class ErreurPerimetrePorts(ValueError):
    """Raised when a custom port selection is invalid."""


PROFILS: dict[str, ProfilAnalyse] = {
    "discovery": ProfilAnalyse(
        "discovery", "Découverte d’hôtes uniquement, faible impact.", ("-sn",)
    ),
    "service": ProfilAnalyse(
        "service",
        "Ports courants et versions de services, sans scripts intrusifs.",
        ("-sT", "-sV", "--version-light", "--top-ports", "100"),
    ),
    "vulnerability": ProfilAnalyse(
        "vulnerability",
        "Évaluation NSE vuln : à réserver aux systèmes explicitement autorisés.",
        ("-sT", "-sV", "--version-light", "--script", "vuln"),
    ),
}


def normaliser_perimetre_ports(valeur: str) -> str:
    perimetre = valeur.strip().lower()
    if perimetre in {"top100", "top1000", "all"}:
        return perimetre
    if not re.fullmatch(r"\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*", perimetre):
        raise ErreurPerimetrePorts("Ports invalides. Exemple accepté : 22,80,443,8000-8100.")
    for element in perimetre.split(","):
        bornes = [int(nombre) for nombre in element.split("-")]
        if any(nombre < 1 or nombre > 65535 for nombre in bornes) or (len(bornes) == 2 and bornes[0] > bornes[1]):
            raise ErreurPerimetrePorts("Chaque port doit être compris entre 1 et 65535.")
    return perimetre


def construire_commande(
    profil: ProfilAnalyse, cible: str, base_sortie: str, perimetre_ports: str | None = None
) -> list[str]:
    """Build argv without a shell, preventing target option injection."""
    options = list(profil.options)
    if profil.nom in {"service", "vulnerability"} and perimetre_ports is not None:
        perimetre = normaliser_perimetre_ports(perimetre_ports)
        if "--top-ports" in options:
            index = options.index("--top-ports")
            del options[index : index + 2]
        if perimetre == "all":
            options.append("-p-")
        elif perimetre == "top1000":
            options.extend(["--top-ports", "1000"])
        elif perimetre == "top100":
            options.extend(["--top-ports", "100"])
        else:
            options.extend(["-p", perimetre])
    return ["nmap", *options, "-oA", base_sortie, cible]
