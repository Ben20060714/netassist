from __future__ import annotations

import shlex
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from .commands import PROFILS, ErreurPerimetrePorts, construire_commande, normaliser_perimetre_ports
from .runner import LanceurNmap
from .security import ErreurPerimetre, texte_autorisation, valider_cible


class NetassistApp:
    def __init__(self, racine_sortie: Path | None = None) -> None:
        self.console = Console()
        self.racine_sortie = racine_sortie or Path("scans")
        self.lanceur = LanceurNmap(self.racine_sortie, self.console.print)

    def run(self) -> None:
        self.console.print(Panel.fit("[bold cyan]netassist[/bold cyan]\n[dim]Nmap autorisé, rapports lisibles, mode interactif[/dim]"))
        self.console.print("[yellow]Aucun mécanisme d'évasion IDS/IPS/pare-feu/antivirus n'est fourni.[/yellow]")
        self.console.print("[dim]Commandes : profiles, scan, help, exit[/dim]")
        while True:
            try:
                commande_interface = Prompt.ask("[bold green]netassist>[/bold green]").strip()
            except (EOFError, KeyboardInterrupt):
                self.console.print("\nAu revoir.")
                return
            if commande_interface in {"exit", "quit", "q"}:
                self.console.print("Au revoir.")
                return
            if commande_interface == "profiles":
                self.show_profiles()
            elif commande_interface == "scan":
                self.scan_flow()
            elif commande_interface in {"help", "?", ""}:
                self.console.print("[cyan]profiles[/cyan] liste les profils | [cyan]scan[/cyan] lance un scan autorisé | [cyan]exit[/cyan] quitte")
            else:
                self.console.print("Commande inconnue. Tapez [cyan]help[/cyan].")

    def show_profiles(self) -> None:
        tableau = Table(title="Profils disponibles")
        tableau.add_column("Nom", style="cyan")
        tableau.add_column("Description")
        for profil in PROFILS.values():
            tableau.add_row(profil.nom, profil.description)
        self.console.print(tableau)

    def scan_flow(self) -> None:
        try:
            cible = valider_cible(Prompt.ask("Cible IP/CIDR/nom DNS"))
            nom_profil = Prompt.ask("Profil", choices=list(PROFILS), default="discovery")
            profil = PROFILS[nom_profil]
            perimetre_ports: str | None = None
            if nom_profil != "discovery":
                choix = Prompt.ask("Ports", choices=["top100", "top1000", "all", "custom"], default="top100")
                if choix == "custom":
                    perimetre_ports = normaliser_perimetre_ports(Prompt.ask("Liste/ranges de ports"))
                else:
                    perimetre_ports = choix
            commande = construire_commande(profil, cible, "scans/<dossier>/scan", perimetre_ports)
            self.console.print(Panel(texte_autorisation(cible, commande), title="Confirmation obligatoire", border_style="yellow"))
            if Prompt.ask("Autorisation", default="NON") != "I CONFIRM":
                self.console.print("Scan annulé : confirmation exacte non fournie.")
                return
            self.console.print(f"Commande : [dim]{shlex.join(commande)}[/dim]")
            texte_chemin_ids = Prompt.ask("Export IDS/IPS JSON/JSONL/CSV (optionnel)", default="")
            chemin_ids = Path(texte_chemin_ids).expanduser() if texte_chemin_ids else None
            if chemin_ids is not None and not chemin_ids.is_file():
                raise RuntimeError("Le fichier d’alertes IDS/IPS indiqué est introuvable.")
            dossier = self.lanceur.lancer(cible, profil, chemin_ids, perimetre_ports)
            self.console.print(Panel(f"Rapports créés dans [bold]{dossier}[/bold]", title="Terminé", border_style="green"))
        except (ErreurPerimetre, ErreurPerimetrePorts, RuntimeError, FileExistsError, OSError) as exc:
            self.console.print(f"[red]Erreur : {exc}[/red]")


def main() -> None:
    NetassistApp().run()
