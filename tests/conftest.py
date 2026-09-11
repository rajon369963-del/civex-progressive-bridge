import pytest


@pytest.fixture(autouse=True)
def explicit_test_court_authority(monkeypatch):
    """Tests opt in to explicit authority; production has no repository fallback here.

    Individual negative tests may delete this variable to prove fail-closed behavior.
    This value is intentionally test-only and confers no production authority.
    """
    monkeypatch.setenv(
        "AIR10_COURT_SECRET_KEY",
        "civex-test-suite-only-nonproduction-authority-material",
    )
