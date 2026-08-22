from dataclasses import dataclass
from pathlib import Path
import sys

import joblib
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent))

PROJECT_DIR = Path(__file__).resolve().parents[2]
URL_CHECKER_DIR = PROJECT_DIR / "url_checker"
MODEL_DIR = URL_CHECKER_DIR / "model"
if str(URL_CHECKER_DIR) not in sys.path:
    sys.path.insert(0, str(URL_CHECKER_DIR))

from dataset.utils.url_features import extract_url_features
from dataset.utils.url_normalize import normalize_url
from dataset.utils.url_rules import rule_check

# Number of features the current model expects.  When a saved model was trained
# on a different feature count, we pad or truncate at inference time so the
# backend keeps running even before a retrain.
_EXPECTED_FEATURE_COUNT: int | None = None


@dataclass(frozen=True)
class URLRiskAnalysis:
    normalized_url: str
    risk_score: int
    risk_level: str
    category: str
    verdict: str
    confidence: int
    reasons: list[str]
    detected_indicators: list[str]
    recommendation: str
    model_prediction: str
    model_confidence: int
    rule_confidence: int
    domain_valid: bool


_model = None
_model_loaded = False


def _is_whitelisted(netloc: str) -> bool:
    whitelist_file = URL_CHECKER_DIR / "dataset" / "forced_negatives.txt"
    if not whitelist_file.exists():
        return False
    try:
        with open(whitelist_file, "r", encoding="utf-8") as f:
            trusted = {line.strip().lower() for line in f if line.strip()}
        domain = netloc.lower().split(":")[0]
        return domain in trusted or any(domain.endswith("." + t) for t in trusted)
    except Exception:
        return False


def _load_model():
    global _model, _model_loaded, _EXPECTED_FEATURE_COUNT
    if _model_loaded:
        return _model
    _model_loaded = True
    model_path = MODEL_DIR / "url_model_calibrated.pkl"
    if not model_path.exists():
        model_path = MODEL_DIR / "url_model.pkl"
    try:
        _model = joblib.load(model_path)
        # Probe expected feature count from the model if available
        feature_names = getattr(_model, "feature_names_in_", None)
        if feature_names is not None:
            _EXPECTED_FEATURE_COUNT = len(feature_names)
    except Exception:
        _model = None
    return _model


def _risk_level(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def _align_features(features: list, model) -> list:
    """Pad or trim the feature vector to match what the model was trained on.

    This migration fallback lets an old model (trained on fewer features) keep
    working until it is retrained on the new 25-feature vector.  New models
    trained on 25 features will pass through unchanged.
    """
    feature_names = getattr(model, "feature_names_in_", None)
    if feature_names is None:
        return features  # model doesn't advertise shape — pass as-is

    expected = len(feature_names)
    current = len(features)
    if current == expected:
        return features
    if current < expected:
        # Zero-pad: new features default to 0 (neutral/unknown)
        return features + [0.0] * (expected - current)
    # Trim: drop trailing features (old model doesn't know about them)
    return features[:expected]


def _model_score(model, features: list) -> tuple[float, str, int]:
    """Run the ML model and return (fraud_probability, prediction_label, confidence_pct)."""
    if model is None:
        return 0.0, "unavailable", 0
    try:
        aligned = _align_features(features, model)
        feature_names = getattr(model, "feature_names_in_", None)
        model_input = (
            pd.DataFrame([aligned], columns=feature_names)
            if feature_names is not None
            else [aligned]
        )
        probabilities = model.predict_proba(model_input)[0]
        classes = list(getattr(model, "classes_", range(len(probabilities))))
        fraud_index = next(
            (
                idx
                for idx, label in enumerate(classes)
                if str(label).lower() in {"1", "true", "fraud", "phishing", "malicious"}
            ),
            len(probabilities) - 1,
        )
        fraud_probability = float(probabilities[fraud_index])
        prediction = str(model.predict(model_input)[0])
        confidence = round(max(float(v) for v in probabilities) * 100)
        return fraud_probability, prediction, confidence
    except Exception:
        return 0.0, "unavailable", 0


def _confidence_weighted_blend(
    model_prob: float,
    rule_score: float,
    model_confidence_pct: int,
    model_unavailable: bool = False,
) -> float:
    """Blend ML probability and rule score using model-confidence as the weight.

    - When model is unavailable / confidence=0: rules get full weight (1.0).
      This ensures the backend keeps working pre-retrain and still correctly
      flags dangerous URLs based on heuristics alone.
    - When model is highly confident (≥ 85 %): ML dominates (weight up to 0.80).
    - When model is uncertain: rules contribute more (ML weight down to 0.50).

    Returns combined probability in [0.0, 1.0].
    """
    if model_unavailable or model_confidence_pct == 0:
        # No usable ML signal — trust rules entirely
        return min(rule_score, 1.0)

    # Scale model weight between 0.50 (uncertain) and 0.80 (very confident)
    ml_weight = 0.50 + (model_confidence_pct / 100.0) * 0.30
    ml_weight = max(0.50, min(0.80, ml_weight))
    rule_weight = 1.0 - ml_weight
    combined = ml_weight * model_prob + rule_weight * rule_score
    return min(combined, 1.0)


def _derive_rule_score_from_reasons(
    reasons: list[str],
    rule_score_from_rules: float,
) -> float:
    """Return the rule score provided by rule_check directly.

    This replaces the old _rule_score() function which re-computed heuristics
    that rule_check() already calculated, causing double-penalty issues.
    """
    return rule_score_from_rules


def analyze_url(url: str) -> URLRiskAnalysis:
    info = normalize_url(url)
    normalized_url = info.get("normalized_url", "")
    netloc = info.get("netloc", "")

    # Fast-path for trusted whitelist domains
    if _is_whitelisted(netloc):
        return URLRiskAnalysis(
            normalized_url=normalized_url,
            risk_score=0,
            risk_level="LOW",
            category="benign",
            verdict="SAFE",
            confidence=99,
            reasons=[],
            detected_indicators=[],
            recommendation="Legitimate and trusted domain.",
            model_prediction="0",
            model_confidence=99,
            rule_confidence=99,
            domain_valid=True,
        )

    # rule_check now returns a 5-tuple (added rule_score at index 4)
    rule_result = rule_check(info)
    suspicious = rule_result[0]
    reasons = rule_result[1]
    domain_valid = rule_result[2]
    unusual_findings = rule_result[3]
    rule_score = rule_result[4] if len(rule_result) > 4 else 0.0

    features = extract_url_features(normalized_url)
    model_probability, model_prediction, model_confidence = _model_score(
        _load_model(), features
    )

    # Confidence-weighted blending — no hard 60/40 split
    model_unavailable = model_prediction == "unavailable"
    combined_probability = _confidence_weighted_blend(
        model_probability, rule_score, model_confidence,
        model_unavailable=model_unavailable,
    )

    score = round(combined_probability * 100)

    # When model is unavailable and rules find nothing, ensure LOW (cap at 24)
    if model_unavailable and not suspicious:
        score = min(score, 24)

    indicators = list(dict.fromkeys(unusual_findings + reasons))

    if not domain_valid:
        category = "invalid_url"
    elif any(
        "download" in r.lower() or "extension" in r.lower() for r in reasons
    ):
        category = "malicious_download"
    elif suspicious:
        category = "phishing"
    else:
        category = "benign"

    verdict = "FRAUD" if score >= 50 else "SAFE"

    confidence = (
        model_confidence
        if model_prediction != "unavailable"
        else min(100, 45 + len(reasons) * 10)
    )

    recommendation = (
        "Do not open this URL or enter personal information. "
        "Verify the destination through an official source."
        if verdict == "FRAUD"
        else "No major suspicious indicators detected. "
        "Continue only if you recognise the website and expected this link."
    )

    # rule_confidence: continuous scale derived from the rule_score
    rule_confidence = min(100, round(rule_score * 100) + 30)

    return URLRiskAnalysis(
        normalized_url=normalized_url,
        risk_score=score,
        risk_level=_risk_level(score),
        category=category,
        verdict=verdict,
        confidence=confidence,
        reasons=reasons,
        detected_indicators=indicators,
        recommendation=recommendation,
        model_prediction=model_prediction,
        model_confidence=model_confidence,
        rule_confidence=rule_confidence,
        domain_valid=domain_valid,
    )
