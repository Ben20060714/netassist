from __future__ import annotations

import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path

from .commands import ScanProfile, build_command
from .parser import parse_nmap_xml
from .render import write_report
from .security import validate_target


class NmapRunner:
    def __init__(self, output_root: Path, log: Callable[[str], None] = print) -> None:
        self.output_root = output_root
        self.log = log

    def run(self, target: str, profile: ScanProfile) -> Path:
        target = validate_target(target)
        if shutil.which("nmap") is None:
            raise RuntimeError("nmap est introuvable dans le PATH.")
        scan_dir = self.output_root / self._folder_name(target, profile.name)
        scan_dir.mkdir(parents=True, exist_ok=False)
        base = scan_dir / "scan"
        command = build_command(profile, target, str(base))
        self.log("Exécution de Nmap en cours…")
        result = subprocess.run(command, text=True, capture_output=True, check=False)
        scan_dir.joinpath("command.stderr.txt").write_text(result.stderr, encoding="utf-8")
        scan_dir.joinpath("command.stdout.txt").write_text(result.stdout, encoding="utf-8")
        if result.returncode != 0:
            raise RuntimeError(f"Nmap a échoué (code {result.returncode}). Voir command.stderr.txt.")
        xml_path = scan_dir / "scan.xml"
        if not xml_path.exists():
            raise RuntimeError("Nmap n'a pas produit le fichier XML attendu.")
        shutil.copyfile(scan_dir / "scan.nmap", scan_dir / "scan.txt")
        report = parse_nmap_xml(xml_path, target=target, profile=profile.name)
        write_report(report, scan_dir)
        return scan_dir

    @staticmethod
    def _folder_name(target: str, profile: str) -> str:
        safe = "".join(char if char.isalnum() else "_" for char in target).strip("_")
        from datetime import datetime

        return f"{datetime.now():%Y%m%d_%H%M%S}_{safe}_{profile}"
