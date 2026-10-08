import pytest

from netassist.security import ScopeError, validate_target
from netassist.commands import PortScopeError, normalize_port_scope


@pytest.mark.parametrize("target", ["192.168.1.1", "192.168.1.0/24", "example.org"])
def test_validate_target(target: str) -> None:
    assert validate_target(target) == target


@pytest.mark.parametrize("target", ["-p-", "", "bad target", "--script vuln"])
def test_reject_option_injection(target: str) -> None:
    with pytest.raises(ScopeError):
        validate_target(target)


def test_port_scope_is_configurable() -> None:
    assert normalize_port_scope("top1000") == "top1000"
    assert normalize_port_scope("22,80,443,8000-8100") == "22,80,443,8000-8100"


def test_port_scope_rejects_invalid_values() -> None:
    with pytest.raises(PortScopeError):
        normalize_port_scope("--script vuln")
