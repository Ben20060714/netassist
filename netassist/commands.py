from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ScanProfile:
    name: str
    description: str
    options: tuple[str, ...]


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


def build_command(profile: ScanProfile, target: str, output_base: str) -> list[str]:
    """Build argv without a shell, preventing target option injection."""
    return ["nmap", *profile.options, "-oA", output_base, target]
