"""Offline package manifests. No network call at scan time, ever - that is what
makes the firewall safe to run against code you do not trust."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from ..config import get_settings
from ..models import Language


@lru_cache(maxsize=None)
def known_packages(language: Language) -> frozenset[str]:
    settings = get_settings()
    path: Path = (settings.pypi_manifest if language is Language.PYTHON
                  else settings.npm_manifest)
    if not path.exists():
        return frozenset()
    return frozenset(
        line.strip().lower()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    )
