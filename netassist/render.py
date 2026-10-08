from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from .models import RapportScan


def rendre_markdown(rapport: RapportScan) -> str:
    lines = [
        "# Netassist — rapport de scan",
        "",
        "> Usage autorisé uniquement. Ce rapport décrit des observations ; il ne prouve pas l'exploitabilité.",
        "",
        f"- **Cible :** `{rapport.cible}`",
        f"- **Profil :** `{rapport.profil}`",
        f"- **Début :** `{rapport.debut.isoformat()}`",
        f"- **Hôtes actifs :** `{len(rapport.hotes_actifs)}` / `{len(rapport.hotes)}`",
        f"- **Durée :** `{rapport.duree_secondes if rapport.duree_secondes is not None else 'inconnue'}` s",
        "",
        "## Hôtes et services",
        "",
        "| Hôte | État | Nom | Ports détectés |",
        "|---|---|---|---:|",
    ]
    for hote in rapport.hotes:
        lines.append(f"| `{hote.adresse}` | {hote.etat} | {', '.join(hote.noms_hotes) or '—'} | {len(hote.ports)} |")
    lines.extend(["", "## Détails techniques", ""])
    for hote in rapport.hotes:
        lines.append(f"### {hote.adresse}")
        for port in hote.ports:
            lines.append(
                f"- `{port['protocol']}/{port['port']}` — {port['state']} — "
                f"{port['service']} {port['product']} {port['version']}".strip()
            )
        if not hote.ports:
            lines.append("- Aucun port rapporté par le fichier XML.")
    lines.extend(["", "## CVE signalées par les scripts Nmap", ""])
    lines.extend(f"- `{cve}` — à vérifier dans une source de vulnérabilités à jour." for cve in rapport.cves)
    if not rapport.cves:
        lines.append("Aucune CVE signalée dans les résultats fournis.")
    lines.extend(["", "## Alertes IDS/IPS corrélées", ""])
    if rapport.source_ids:
        lines.append(f"Source fournie : `{rapport.source_ids}`")
    if rapport.alertes_ids:
        lines.extend([
            "",
            "| Date | Sévérité | Signature | Source | Destination | Action |",
            "|---|---|---|---|---|---|",
        ])
        for alerte in rapport.alertes_ids:
            destination = alerte.adresse_destination + (f":{alerte.port_destination}" if alerte.port_destination else "")
            lines.append(
                f"| {alerte.horodatage} | {alerte.severite} | {alerte.signature} | "
                f"{alerte.adresse_source or '—'} | {destination or '—'} | {alerte.action or '—'} |"
            )
    else:
        lines.append("Aucune alerte corrélée. Si aucun export IDS/IPS n’a été fourni, cela ne signifie pas qu’aucune alerte n’a existé.")
    lines.extend(["", "## Commande source", "", f"`{rapport.arguments_nmap or 'non disponible'}`", ""])
    return "\n".join(lines)


def ecrire_rapport(rapport: RapportScan, dossier: Path) -> None:
    dossier.joinpath("report.md").write_text(rendre_markdown(rapport), encoding="utf-8")
    dossier.joinpath("report.json").write_text(
        json.dumps(asdict(rapport), ensure_ascii=False, indent=2, default=str), encoding="utf-8"
    )
