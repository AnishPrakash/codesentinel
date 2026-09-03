from pathlib import Path

from codesentinel.features.extract import FEATURE_NAMES, extract_features
from codesentinel.models import Language
from codesentinel.parser import parse

FIX = Path(__file__).parent / "fixtures"


def _vec(path: Path) -> dict[str, float]:
    code = path.read_text(encoding="utf-8")
    ps = parse(code, Language.PYTHON)
    return dict(zip(FEATURE_NAMES, extract_features(ps)))


def test_vector_length_and_order():
    v = extract_features(parse("x = 1\n", Language.PYTHON))
    assert len(v) == 52
    assert len(FEATURE_NAMES) == len(set(FEATURE_NAMES))


def test_vulnerable_vs_clean_separate():
    bad = _vec(FIX / "vulnerable" / "flask_app.py")
    good = _vec(FIX / "clean" / "flask_app.py")

    assert bad["has_aws_key_literal"] == 1.0
    assert good["has_aws_key_literal"] == 0.0

    assert bad["uses_weak_hash"] == 1.0
    assert good["uses_weak_hash"] == 0.0

    assert bad["has_sql_interpolation"] or bad["has_sql_string_concat"]
    assert bad["n_auth_decorators"] == 0.0
    assert good["n_auth_decorators"] >= 2.0
    assert good["auth_route_ratio"] > bad["auth_route_ratio"]


def test_no_nan_or_inf():
    import math
    for p in (FIX / "vulnerable").glob("*.py"):
        for x in extract_features(parse(p.read_text(), Language.PYTHON)):
            assert math.isfinite(x)


def test_javascript_parses():
    js = "const x = require('express');\napp.get('/a', (req,res) => res.send(req.query.q));"
    v = dict(zip(FEATURE_NAMES, extract_features(parse(js, Language.JAVASCRIPT))))
    assert v["lang_is_javascript"] == 1.0
    assert v["n_routes"] >= 1.0
