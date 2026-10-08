from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

from .models import Host, ScanReport

_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def parse_nmap_xml(path: Path, *, target: str, profile: str) -> ScanReport:
    root = ET.parse(path).getroot()
    hosts: list[Host] = []
    for node in root.findall("host"):
        address = next(
            (item.get("addr", "") for item in node.findall("address") if item.get("addrtype") == "ipv4"),
            next((item.get("addr", "") for item in node.findall("address")), "unknown"),
        )
        status = node.find("status")
        state = status.get("state", "unknown") if status is not None else "unknown"
        hostnames = [item.get("name", "") for item in node.findall("hostnames/hostname")]
        ports: list[dict[str, str]] = []
        scripts: list[str] = []
        cves: set[str] = set()
        for port in node.findall("ports/port"):
            service = port.find("service")
            record = {
                "port": port.get("portid", "?"),
                "protocol": port.get("protocol", "?"),
                "state": port.findtext("state[@state]", default="unknown"),
                "service": service.get("name", "") if service is not None else "",
                "product": service.get("product", "") if service is not None else "",
                "version": service.get("version", "") if service is not None else "",
            }
            ports.append(record)
            for script in port.findall("script"):
                text = ET.tostring(script, encoding="unicode")
                scripts.append(script.get("id", "") + ": " + " ".join("".join(text.split()).split("<"))[:400])
                cves.update(match.upper() for match in _CVE.findall(text))
        for script in node.findall("hostscript/script"):
            text = ET.tostring(script, encoding="unicode")
            scripts.append(script.get("id", "") + ": " + " ".join("".join(text.split()).split("<"))[:400])
            cves.update(match.upper() for match in _CVE.findall(text))
        hosts.append(Host(address, state, hostnames, ports, sorted(cves), scripts))

    started = datetime.fromtimestamp(float(root.get("start", "0"))) if root.get("start") else datetime.now()
    finished = root.find("runstats/finished")
    duration = float(finished.get("elapsed")) if finished is not None and finished.get("elapsed") else None
    return ScanReport(target, profile, started, duration, hosts, root.get("args", ""), str(path))
