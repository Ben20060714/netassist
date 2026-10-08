from __future__ import annotations

import ipaddress
import re


class ScopeError(ValueError):
    """Raised when a target is unsafe or malformed."""


_HOSTNAME = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?)$")


def validate_target(value: str) -> str:
    """Accept an IP, CIDR, or hostname, but never an option-like value."""
    target = value.strip()
    if not target or target.startswith("-") or any(char.isspace() for char in target):
        raise ScopeError("Cible invalide : utilisez une IP, un CIDR ou un nom DNS.")
    try:
        ipaddress.ip_network(target, strict=False)
        return target
    except ValueError:
        pass
    if _HOSTNAME.fullmatch(target) and ".." not in target:
        return target
    raise ScopeError("Cible invalide : utilisez une IP, un CIDR ou un nom DNS.")


def authorization_text(target: str, command: list[str]) -> str:
    rendered = " ".join(command)
    return (
        f"Cible : {target}\n"
        "Vous devez disposer d'une autorisation écrite et d'un périmètre défini.\n"
        f"Commande exacte qui sera exécutée :\n  {rendered}\n"
        "Effet : interrogation réseau du périmètre indiqué et enregistrement des résultats.\n"
        "Confirmez en tapant exactement : I CONFIRM"
    )
