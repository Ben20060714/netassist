from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(slots=True)
class Host:
    address: str
    state: str = "unknown"
    hostnames: list[str] = field(default_factory=list)
    ports: list[dict[str, str]] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ScanReport:
    target: str
    profile: str
    started_at: datetime
    duration_seconds: float | None
    hosts: list[Host]
    nmap_args: str = ""
    source_xml: str = ""

    @property
    def cves(self) -> list[str]:
        return sorted({cve for host in self.hosts for cve in host.cves})

    @property
    def up_hosts(self) -> list[Host]:
        return [host for host in self.hosts if host.state == "up"]
