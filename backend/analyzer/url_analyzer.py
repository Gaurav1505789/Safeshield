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

from url_checker.dataset.utils.url_features import extract_url_features
from url_checker.dataset.utils.url_normalize import normalize_url
from url_checker.dataset.utils.url_rules import rule_check


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
        # Check exact domain or root domain (e.g., google.com or www.google.com)
        return domain in trusted or any(domain.endswith("." + t) for t in trusted)
    except Exception:
        return False

def _load_model():
    global _model, _model_loaded
    if _model_loaded:
        return _model
    _model_loaded = True
    model_path = MODEL_DIR / "url_model_calibrated.pkl"
    if not model_path.exists():
        model_path = MODEL_DIR / "url_model.pkl"
    try:
        _model = joblib.load(model_path)
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


def _model_score(model, features: list[float]) -> tuple[float, str, int]:
    if model is None:
        return 0.0, "unavailable", 0
    try:
        feature_names = getattr(model, "feature_names_in_", None)
        model_input = pd.DataFrame([features], columns=feature_names) if feature_names is not None else [features]
        probabilities = model.predict_proba(model_input)[0]
        classes = list(getattr(model, "classes_", range(len(probabilities))))
        fraud_index = next((index for index, label in enumerate(classes) if str(label).lower() in {"1", "true", "fraud", "phishing", "malicious"}), len(probabilities) - 1)
        # Extract raw probability
        fraud_probability = float(probabilities[fraud_index])
        prediction = str(model.predict(model_input)[0])
        confidence = round(max(float(value) for value in probabilities) * 100)
        return fraud_probability, prediction, confidence
    except Exception:
        return 0.0, "unavailable", 0


def _rule_score(info: dict, reasons: list[str]) -> float:
    score = 0.0
    text = f"{info.get('netloc', '')} {info.get('path', '')}".lower()
    if any(keyword in text for keyword in ("free", "click", "verify", "confirm", "urgent", "login", "secure", "bank", "account", "prize", "win")):
        score += 0.2
    if info.get("is_ip"):
        score += 0.3
    if len(info.get("netloc", "").split(".")) - 1 > 3:
        score += 0.1
    if len(reasons) > 0:
        score += min(0.4, len(reasons) * 0.08)
    return min(score, 1.0)


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
    info = normalize_url(url)
    normalized_url = info.get("normalized_url", "")
    suspicious, reasons, domain_valid, unusual_findings = rule_check(info)
    features = extract_url_features(normalized_url)
    model_probability, model_prediction, model_confidence = _model_score(_load_model(), features)
    rules_probability = _rule_score(info, reasons)
    combined_probability = min(1.0, model_probability * 0.6 + rules_probability * 0.4)
    if suspicious and combined_probability < 0.25:
        combined_probability = 0.25
    score = round(combined_probability * 100)
    if not suspicious and score < 25:
        score = min(score, 24)

    indicators = list(dict.fromkeys(unusual_findings + reasons))
    if not domain_valid:
        category = "invalid_url"
    elif any("download" in reason.lower() or "extension" in reason.lower() for reason in reasons):
        category = "malicious_download"
    elif suspicious:
        category = "phishing"
    else:
        category = "benign"
    verdict = "FRAUD" if score >= 50 else "SAFE"
    confidence = model_confidence if model_prediction != "unavailable" else min(100, 45 + len(reasons) * 10)
    recommendation = (
        "Do not open this URL or enter personal information. Verify the destination through an official source."
        if verdict == "FRAUD"
        else "No major suspicious indicators detected. Continue only if you recognize the website and expected this link."
    )
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
        rule_confidence=min(100, 40 + len(reasons) * 12),
        domain_valid=domain_valid,
    )