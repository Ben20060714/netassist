from __future__ import annotations

import shlex
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from .commands import PROFILES, PortScopeError, build_command, normalize_port_scope
from .runner import NmapRunner
from .security import ScopeError, authorization_text, validate_target


class NetassistApp:
    def __init__(self, output_root: Path | None = None) -> None:
        self.console = Console()
        self.output_root = output_root or Path("scans")
        self.runner = NmapRunner(self.output_root, self.console.print)

    def run(self) -> None:
        self.console.print(Panel.fit("[bold cyan]netassist[/bold cyan]\n[dim]Nmap autorisé, rapports lisibles, mode interactif[/dim]"))
        self.console.print("[yellow]Aucun mécanisme d'évasion IDS/IPS/pare-feu/antivirus n'est fourni.[/yellow]")
        self.console.print("[dim]Commandes : profiles, scan, help, exit[/dim]")
        while True:
            try:
                command = Prompt.ask("[bold green]netassist>[/bold green]").strip()
            except (EOFError, KeyboardInterrupt):
                self.console.print("\nAu revoir.")
                return
            if command in {"exit", "quit", "q"}:
                self.console.print("Au revoir.")
                return
            if command == "profiles":
                self.show_profiles()
            elif command == "scan":
                self.scan_flow()
            elif command in {"help", "?", ""}:
                self.console.print("[cyan]profiles[/cyan] liste les profils | [cyan]scan[/cyan] lance un scan autorisé | [cyan]exit[/cyan] quitte")
            else:
                self.console.print("Commande inconnue. Tapez [cyan]help[/cyan].")

    def show_profiles(self) -> None:
        table = Table(title="Profils disponibles")
        table.add_column("Nom", style="cyan")
        table.add_column("Description")
        for profile in PROFILES.values():
            table.add_row(profile.name, profile.description)
        self.console.print(table)

    def scan_flow(self) -> None:
        try:
            target = validate_target(Prompt.ask("Cible IP/CIDR/nom DNS"))
            profile_name = Prompt.ask("Profil", choices=list(PROFILES), default="discovery")
            profile = PROFILES[profile_name]
            port_scope: str | None = None
            if profile_name != "discovery":
                selected = Prompt.ask("Ports", choices=["top100", "top1000", "all", "custom"], default="top100")
                if selected == "custom":
                    port_scope = normalize_port_scope(Prompt.ask("Liste/ranges de ports"))
                else:
                    port_scope = selected
            command = build_command(profile, target, "scans/<dossier>/scan", port_scope)
            self.console.print(Panel(authorization_text(target, command), title="Confirmation obligatoire", border_style="yellow"))
            if Prompt.ask("Autorisation", default="NON") != "I CONFIRM":
                self.console.print("Scan annulé : confirmation exacte non fournie.")
                return
            self.console.print(f"Commande : [dim]{shlex.join(command)}[/dim]")
            ids_path_text = Prompt.ask("Export IDS/IPS JSON/JSONL/CSV (optionnel)", default="")
            ids_path = Path(ids_path_text).expanduser() if ids_path_text else None
            if ids_path is not None and not ids_path.is_file():
                raise RuntimeError("Le fichier d’alertes IDS/IPS indiqué est introuvable.")
            directory = self.runner.run(target, profile, ids_path, port_scope)
            self.console.print(Panel(f"Rapports créés dans [bold]{directory}[/bold]", title="Terminé", border_style="green"))
        except (ScopeError, PortScopeError, RuntimeError, FileExistsError, OSError) as exc:
            self.console.print(f"[red]Erreur : {exc}[/red]")


def main() -> None:
    NetassistApp().run()
