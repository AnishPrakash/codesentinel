"""ONNX inference for the triage model. Degrades to a no-op when absent."""
from __future__ import annotations

import json
import logging
from functools import lru_cache

import numpy as np

from ..config import get_settings
from ..features.extract import FEATURE_NAMES, FEATURE_VERSION

log = logging.getLogger(__name__)

# Output order must match the deterministic half of rules.engine.COVERED.
# Advisory classes (CS010-CS013) are never modelled.
CLASS_ORDER = ["CS001", "CS002", "CS003", "CS004", "CS005",
               "CS006", "CS007", "CS008", "CS009"]


class TriageModel:
    """Loads once. Every failure path returns None rather than raising - a broken
    model must never take down a scan the rules could have answered."""

    def __init__(self) -> None:
        self.session = None
        self.mins: np.ndarray | None = None
        self.maxs: np.ndarray | None = None
        self.input_name = ""
        self._load()

    def _load(self) -> None:
        s = get_settings()
        if not (s.model_path.exists() and s.scaler_path.exists()):
            log.info("triage model not present - running rules only")
            return
        try:
            import onnxruntime as ort

            scaler = json.loads(s.scaler_path.read_text(encoding="utf-8"))

            if scaler.get("feature_version") != FEATURE_VERSION:
                log.warning("scaler feature_version %s != %s - refusing to load",
                            scaler.get("feature_version"), FEATURE_VERSION)
                return
            if scaler.get("feature_names") != FEATURE_NAMES:
                log.warning("feature name/order mismatch - refusing to load")
                return

            self.mins = np.asarray(scaler["min"], dtype=np.float32)
            self.maxs = np.asarray(scaler["max"], dtype=np.float32)
            self.session = ort.InferenceSession(
                str(s.model_path), providers=["CPUExecutionProvider"])
            self.input_name = self.session.get_inputs()[0].name
            log.info("triage model loaded")
        except Exception as exc:                      # noqa: BLE001
            log.warning("triage model failed to load: %s", exc)
            self.session = None

    @property
    def ready(self) -> bool:
        return self.session is not None

    def predict(self, features: list[float]) -> dict[str, float] | None:
        if not self.ready or self.mins is None or self.maxs is None:
            return None
        try:
            x = np.asarray(features, dtype=np.float32)
            span = np.where((self.maxs - self.mins) == 0, 1.0, self.maxs - self.mins)
            x = np.clip((x - self.mins) / span, 0.0, 1.0).reshape(1, -1)
            probs = self.session.run(None, {self.input_name: x})[0][0]
            return {cls: float(p) for cls, p in zip(CLASS_ORDER, probs)}
        except Exception as exc:                      # noqa: BLE001
            log.warning("triage inference failed: %s", exc)
            return None


@lru_cache(maxsize=1)
def get_model() -> TriageModel:
    return TriageModel()
