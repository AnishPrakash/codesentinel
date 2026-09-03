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
CLASS_ORDER = ["CS001", "CS002", "CS003", "CS004", "CS005", "CS006", "CS007",
               "CS008", "CS009", "CS014", "CS015", "CS016", "CS017"]


class TriageModel:
    """Loads once. Every failure path returns None rather than raising - a broken
    model must never take down a scan the rules could have answered."""

    def __init__(self) -> None:
        self.session = None
        self.mins: np.ndarray | None = None
        self.maxs: np.ndarray | None = None
        self.input_name = ""
        self.languages: set[str] = set()
        # Fraction of the 52 features allowed to fall outside the training
        # range before we treat the vector as out of distribution. Min-max
        # scaling clamps silently, so without this the model is asked about
        # vectors it has never seen and answers anyway.
        self.max_clipped = 0.30
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
            # A model trained only on Java has no basis for an opinion about
            # Python. Absent the field, assume the model claims nothing.
            self.languages = {str(x).lower() for x in scaler.get("languages", [])}
            self.max_clipped = float(scaler.get("max_clipped_fraction", 0.30))
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

    def covers(self, language: str) -> bool:
        """Was this model trained on this language at all?"""
        if not self.languages:
            return False
        return language.lower() in self.languages

    def predict(self, features: list[float],
                language: str | None = None) -> dict[str, float] | None:
        """Scores, or None when the model has no basis for an opinion.

        Returning None is a real answer, and the caller treats it as "the model
        said nothing" rather than "the model said zero". Three ways to get it:

          * the model is not loaded
          * it was never trained on this language
          * the vector sits outside the range it was trained on, so min-max
            scaling would clamp much of it and the model would be extrapolating

        The third is the one that matters in practice. A model trained on one
        corpus of generated test cases will happily emit 0.02 for every class of
        a real application it has never seen, and 0.02 is indistinguishable from
        a considered judgement once it is printed next to a finding.
        """
        if not self.ready or self.mins is None or self.maxs is None:
            return None
        if language is not None and not self.covers(language):
            log.info("triage model was not trained on %s - no opinion", language)
            return None
        try:
            x = np.asarray(features, dtype=np.float32)
            span = np.where((self.maxs - self.mins) == 0, 1.0, self.maxs - self.mins)
            raw = (x - self.mins) / span
            clipped = float(np.mean((raw < 0.0) | (raw > 1.0)))
            if clipped > self.max_clipped:
                log.info("triage: %.0f%% of features outside the training range "
                         "- out of distribution, no opinion", 100 * clipped)
                return None
            x = np.clip(raw, 0.0, 1.0).reshape(1, -1).astype(np.float32)
            probs = self.session.run(None, {self.input_name: x})[0][0]
            return {cls: float(p) for cls, p in zip(CLASS_ORDER, probs)}
        except Exception as exc:                      # noqa: BLE001
            log.warning("triage inference failed: %s", exc)
            return None


@lru_cache(maxsize=1)
def get_model() -> TriageModel:
    return TriageModel()
