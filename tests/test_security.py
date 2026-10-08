import pytest

from netassist.security import ErreurPerimetre, valider_cible
from netassist.commands import ErreurPerimetrePorts, normaliser_perimetre_ports


@pytest.mark.parametrize("cible", ["192.168.1.1", "192.168.1.0/24", "example.org"])
def test_valider_cible(cible: str) -> None:
    assert valider_cible(cible) == cible


@pytest.mark.parametrize("cible", ["-p-", "", "bad target", "--script vuln"])
def test_rejeter_injection_options(cible: str) -> None:
    with pytest.raises(ErreurPerimetre):
        valider_cible(cible)


def test_perimetre_ports_configurable() -> None:
    assert normaliser_perimetre_ports("top1000") == "top1000"
    assert normaliser_perimetre_ports("22,80,443,8000-8100") == "22,80,443,8000-8100"


def test_perimetre_ports_rejette_valeurs_invalides() -> None:
    with pytest.raises(ErreurPerimetrePorts):
        normaliser_perimetre_ports("--script vuln")
