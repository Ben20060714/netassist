import pytest

from netassist.security import ScopeError, validate_target


@pytest.mark.parametrize("target", ["192.168.1.1", "192.168.1.0/24", "example.org"])
def test_validate_target(target: str) -> None:
    assert validate_target(target) == target


@pytest.mark.parametrize("target", ["-p-", "", "bad target", "--script vuln"])
def test_reject_option_injection(target: str) -> None:
    with pytest.raises(ScopeError):
        validate_target(target)
