from __future__ import annotations

from dataclasses import dataclass
import re


@dataclass(frozen=True, slots=True)
class ScanProfile:
    name: str
    description: str
    options: tuple[str, ...]


class PortScopeError(ValueError):
    """Raised when a custom port selection is invalid."""


PROFILES: dict[str, ScanProfile] = {
    "discovery": ScanProfile(
        "discovery", "Découverte d’hôtes uniquement, faible impact.", ("-sn",)
    ),
    "service": ScanProfile(
        "service",
        "Ports courants et versions de services, sans scripts intrusifs.",
        ("-sT", "-sV", "--version-light", "--top-ports", "100"),
    ),
    "vulnerability": ScanProfile(
        "vulnerability",
        "Évaluation NSE vuln : à réserver aux systèmes explicitement autorisés.",
        ("-sT", "-sV", "--version-light", "--script", "vuln"),
    ),
}


def normalize_port_scope(value: str) -> str:
    scope = value.strip().lower()
    if scope in {"top100", "top1000", "all"}:
        return scope
    if not re.fullmatch(r"\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*", scope):
        raise PortScopeError("Ports invalides. Exemple accepté : 22,80,443,8000-8100.")
    for part in scope.split(","):
        bounds = [int(number) for number in part.split("-")]
        if any(number < 1 or number > 65535 for number in bounds) or (len(bounds) == 2 and bounds[0] > bounds[1]):
            raise PortScopeError("Chaque port doit être compris entre 1 et 65535.")
    return scope


def build_command(
    profile: ScanProfile, target: str, output_base: str, port_scope: str | None = None
) -> list[str]:
    """Build argv without a shell, preventing target option injection."""
    options = list(profile.options)
    if profile.name in {"service", "vulnerability"} and port_scope is not None:
        scope = normalize_port_scope(port_scope)
        if "--top-ports" in options:
            index = options.index("--top-ports")
            del options[index : index + 2]
        if scope == "all":
            options.append("-p-")
        elif scope == "top1000":
            options.extend(["--top-ports", "1000"])
        elif scope == "top100":
            options.extend(["--top-ports", "100"])
        else:
            options.extend(["-p", scope])
    return ["nmap", *options, "-oA", output_base, target]
