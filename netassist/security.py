from __future__ import annotations

import ipaddress
import re


class ErreurPerimetre(ValueError):
    """Raised when a target is unsafe or malformed."""


_HOSTNAME = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?)$")


def valider_cible(valeur: str) -> str:
    """Accept an IP, CIDR, or hostname, but never an option-like value."""
    cible = valeur.strip()
    if not cible or cible.startswith("-") or any(caractere.isspace() for caractere in cible):
        raise ErreurPerimetre("Cible invalide : utilisez une IP, un CIDR ou un nom DNS.")
    try:
        ipaddress.ip_network(cible, strict=False)
        return cible
    except ValueError:
        pass
    if _HOSTNAME.fullmatch(cible) and ".." not in cible:
        return cible
    raise ErreurPerimetre("Cible invalide : utilisez une IP, un CIDR ou un nom DNS.")


def texte_autorisation(cible: str, commande: list[str]) -> str:
    commande_affichee = " ".join(commande)
    return (
        f"Cible : {cible}\n"
        "Vous devez disposer d'une autorisation écrite et d'un périmètre défini.\n"
        f"Commande exacte qui sera exécutée :\n  {commande_affichee}\n"
        "Effet : interrogation réseau du périmètre indiqué et enregistrement des résultats.\n"
        "Confirmez en tapant exactement : I CONFIRM"
    )
