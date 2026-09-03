import tempfile

import pytest


@pytest.fixture(autouse=True)
def isolated_home(monkeypatch):
    """Point CODESENTINEL_HOME at a temp directory for every test."""
    with tempfile.TemporaryDirectory() as tmp:
        monkeypatch.setenv("CODESENTINEL_HOME", tmp)
        from codesentinel.config import get_settings
        get_settings.cache_clear()
        yield tmp
        get_settings.cache_clear()
