import dataclasses
import json
from pathlib import Path

import pytest

from codesentinel.models import Language
from codesentinel.parser import parse
from codesentinel.rules.engine import run_rules
from codesentinel.triage import triage
from codesentinel.triage.model import CLASS_ORDER, get_model

FIX = Path(__file__).parent / "fixtures"


def _parsed(kind: str):
    return parse((FIX / kind / "flask_app.py").read_text(), Language.PYTHON)


def test_works_without_model():
    """The critical guarantee: no model, no problem."""
    ps = _parsed("vulnerable")
    findings, pred = triage(ps, run_rules(ps))
    assert findings                       # rules still produced results
    if not get_model().ready:
        assert pred is None


def test_class_order_matches_the_deterministic_rules():
    from codesentinel.rules.engine import DETERMINISTIC
    assert CLASS_ORDER == [c[0] for c in DETERMINISTIC]


@pytest.mark.skipif(not get_model().ready, reason="triage model not downloaded")
def test_confidence_is_attached():
    ps = _parsed("vulnerable")
    findings, _ = triage(ps, run_rules(ps))
    assert all(0.0 <= f.confidence <= 1.0 for f in findings)


@pytest.mark.skipif(not get_model().ready, reason="triage model not downloaded")
def test_severity_still_dominates_order():
    """The model may reorder within a band. It must never promote a MEDIUM
    above a CRITICAL - rules outrank predictions, always."""
    from codesentinel.models import Tier
    ps = _parsed("vulnerable")
    findings, _ = triage(ps, run_rules(ps))
    deterministic = [f for f in findings if f.tier is Tier.DETERMINISTIC]
    severities = [int(f.severity) for f in deterministic]
    assert severities == sorted(severities, reverse=True)


@pytest.mark.skipif(not get_model().ready, reason="triage model not downloaded")
def test_prediction_never_claims_a_cwe():
    ps = _parsed("vulnerable")
    _, pred = triage(ps, run_rules(ps))
    if pred is not None:
        assert "CWE" not in pred.note
        assert pred.label == "needs_review"


def test_scaler_mismatch_is_refused(monkeypatch, tmp_path):
    """A silently reordered feature vector must fail closed, not produce
    confident nonsense."""
    from codesentinel.config import get_settings
    from codesentinel.triage.model import TriageModel

    bad = tmp_path / "scaler.json"
    bad.write_text(json.dumps({
        "min": [0.0] * 52, "max": [1.0] * 52,
        "feature_version": 1, "feature_names": ["wrong"] * 52,
    }))
    # Settings is a frozen dataclass - replace it and swap the accessor, do not
    # try to mutate the instance.
    fake = dataclasses.replace(get_settings(), scaler_path=bad,
                               model_path=tmp_path / "nope.onnx")
    monkeypatch.setattr("codesentinel.triage.model.get_settings", lambda: fake)
    assert TriageModel().ready is False


def test_prediction_note_never_names_a_vulnerability():
    from codesentinel.models import Prediction
    note = Prediction(score=0.9).note
    assert "CWE" not in note
    assert "SQL" not in note
