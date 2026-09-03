"""Runtime configuration. Everything tunable lives here, nothing hardcoded downstream."""
from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

PKG_ROOT = Path(__file__).resolve().parent
ROOT = PKG_ROOT.parent

# Data ships inside the package so a wheel install works; a source checkout
# keeps a top-level data/ directory too. Prefer the packaged copy, fall back.
_PKG_DATA = PKG_ROOT / "data"
DATA_DIR = _PKG_DATA if _PKG_DATA.exists() else ROOT / "data"
MODEL_DIR = ROOT / "models"


def home_dir() -> Path:
    """Where per-user state lives. Overridable for tests and for people who
    keep their dotfiles somewhere specific."""
    override = os.environ.get("CODESENTINEL_HOME")
    path = Path(override) if override else Path.home() / ".codesentinel"
    path.mkdir(parents=True, exist_ok=True)
    return path


@dataclass(frozen=True)
class Settings:
    # --- limits ---
    max_file_bytes: int = 1_000_000
    max_lines: int = 20_000

    # --- triage model (Phase 6) ---
    model_path: Path = MODEL_DIR / "triage.onnx"
    scaler_path: Path = MODEL_DIR / "feature_scaler.json"
    needs_review_threshold: float = 0.65

    # --- dependency firewall ---
    pypi_manifest: Path = DATA_DIR / "manifests" / "pypi_top.txt"
    npm_manifest: Path = DATA_DIR / "manifests" / "npm_top.txt"

    # --- grounding ---
    cwe_path: Path = DATA_DIR / "grounding" / "cwe.json"
    owasp_path: Path = DATA_DIR / "grounding" / "owasp.json"
    nist_path: Path = DATA_DIR / "grounding" / "nist.json"
    # NIST control text is long and organisational; off unless asked for.
    show_nist: bool = False

    @property
    def ledger_path(self) -> Path:
        return home_dir() / "ledger.db"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
