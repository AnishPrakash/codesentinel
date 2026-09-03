"""Triage: order findings, and surface risk the rules did not cover.

The model never creates a Finding and never names a CWE. It does two things:

  1. Reorders findings within a severity band, so the ones it also recognises
     float up - a cheap false-positive suppressant that changes presentation,
     not truth.
  2. Emits a Prediction when it scores a class highly and no rule fired for it.
     That surfaces as "needs review", explicitly not as a finding.

With no model installed this is the identity function, which is what keeps
every phase before the model a complete, shippable tool.
"""
from __future__ import annotations

import dataclasses

from ..config import get_settings
from ..deps.manifest import known_packages
from ..features.extract import extract_features
from ..models import Finding, Prediction, Tier
from ..parser import ParsedSource
from .model import get_model


def triage(parsed: ParsedSource,
           findings: list[Finding]) -> tuple[list[Finding], Prediction | None]:
    model = get_model()
    if not model.ready:
        return findings, None

    features = extract_features(parsed, set(known_packages(parsed.language)))
    scores = model.predict(features)
    if scores is None:
        return findings, None

    # 1. annotate confidence; rules stay authoritative, this only affects order
    annotated = [
        dataclasses.replace(f, confidence=round(scores.get(f.rule_id, 0.5), 3))
        for f in findings
    ]
    # Tier first, then severity, then model confidence. Severity from the rules
    # always dominates - the model may only reorder within a band.
    annotated.sort(key=lambda f: (f.tier is Tier.ADVISORY, -int(f.severity),
                                  -f.confidence, f.line))

    # 2. risk the rules did not cover
    matched = {f.rule_id for f in findings}      # includes advisories, deliberately:
    # if CS012 already flagged this file, do not also emit a vague needs-review
    threshold = get_settings().needs_review_threshold
    uncovered = {c: s for c, s in scores.items() if c not in matched and s >= threshold}

    prediction = None
    if uncovered:
        top = max(uncovered.values())
        prediction = Prediction(score=round(top, 3))

    return annotated, prediction
