from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from .models import ScanReport


def render_markdown(report: ScanReport) -> str:
    lines = [
        "# Netassist — rapport de scan",
        "",
        "> Usage autorisé uniquement. Ce rapport décrit des observations ; il ne prouve pas l'exploitabilité.",
        "",
        f"- **Cible :** `{report.target}`",
        f"- **Profil :** `{report.profile}`",
        f"- **Début :** `{report.started_at.isoformat()}`",
        f"- **Hôtes actifs :** `{len(report.up_hosts)}` / `{len(report.hosts)}`",
        f"- **Durée :** `{report.duration_seconds if report.duration_seconds is not None else 'inconnue'}` s",
        "",
        "## Hôtes et services",
        "",
        "| Hôte | État | Nom | Ports détectés |",
        "|---|---|---|---:|",
    ]
    for host in report.hosts:
        lines.append(f"| `{host.address}` | {host.state} | {', '.join(host.hostnames) or '—'} | {len(host.ports)} |")
    lines.extend(["", "## Détails techniques", ""])
    for host in report.hosts:
        lines.append(f"### {host.address}")
        for port in host.ports:
            lines.append(
                f"- `{port['protocol']}/{port['port']}` — {port['state']} — "
                f"{port['service']} {port['product']} {port['version']}".strip()
            )
        if not host.ports:
            lines.append("- Aucun port rapporté par le fichier XML.")
    lines.extend(["", "## CVE signalées par les scripts Nmap", ""])
    lines.extend(f"- `{cve}` — à vérifier dans une source de vulnérabilités à jour." for cve in report.cves)
    if not report.cves:
        lines.append("Aucune CVE signalée dans les résultats fournis.")
    lines.extend(["", "## Alertes IDS/IPS corrélées", ""])
    if report.ids_source:
        lines.append(f"Source fournie : `{report.ids_source}`")
    if report.ids_alerts:
        lines.extend([
            "",
            "| Date | Sévérité | Signature | Source | Destination | Action |",
            "|---|---|---|---|---|---|",
        ])
        for alert in report.ids_alerts:
            destination = alert.destination_ip + (f":{alert.destination_port}" if alert.destination_port else "")
            lines.append(
                f"| {alert.timestamp} | {alert.severity} | {alert.signature} | "
                f"{alert.source_ip or '—'} | {destination or '—'} | {alert.action or '—'} |"
            )
    else:
        lines.append("Aucune alerte corrélée. Si aucun export IDS/IPS n’a été fourni, cela ne signifie pas qu’aucune alerte n’a existé.")
    lines.extend(["", "## Commande source", "", f"`{report.nmap_args or 'non disponible'}`", ""])
    return "\n".join(lines)


def write_report(report: ScanReport, directory: Path) -> None:
    directory.joinpath("report.md").write_text(render_markdown(report), encoding="utf-8")
    directory.joinpath("report.json").write_text(
        json.dumps(asdict(report), ensure_ascii=False, indent=2, default=str), encoding="utf-8"
    )
