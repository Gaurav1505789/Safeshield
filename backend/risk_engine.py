from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

import joblib

from analyzer.message_analyzer import IndicatorMatch


# ============================================================
# MODEL PATH
# ============================================================

MODEL_FILE = (
    Path(__file__).resolve().parent
    / "ml"
    / "models"
    / "message_model.joblib"
)


# ============================================================
# RESULT MODEL
# ============================================================

@dataclass(frozen=True)
class MessageRiskAnalysis:
    risk_score: int
    risk_level: str
    category: str
    confidence: int
    confidence_level: str
    reasons: list[str]
    detected_indicators: list[str]
    recommendation: str
    model_prediction: str
    model_confidence: int
    rule_confidence: int


# ============================================================
# RISK LEVEL
# ============================================================

def _risk_level_from_score(score: int) -> str:

    if score >= 75:
        return "CRITICAL"

    if score >= 50:
        return "HIGH"

    if score >= 25:
        return "MEDIUM"

    return "LOW"


# ============================================================
# RECOMMENDATION
# ============================================================

def _generate_recommendation(
    score: int,
    reasons: list[str]
) -> str:

    if score <= 24:
        return (
            "No major suspicious indicators detected."
        )

    if any(
        "Download or install instruction detected." in reason
        for reason in reasons
    ):
        return (
            "Potentially suspicious. "
            "Do not click the link, do not install the file, "
            "and verify the sender through a trusted channel."
        )

    if any(
        "Credential, OTP, or account access request detected."
        in reason
        for reason in reasons
    ):
        return (
            "Potentially suspicious. "
            "Do not share passwords, OTP codes, or account details. "
            "Confirm the request through an official channel."
        )

    return (
        "Potentially suspicious. "
        "Avoid interacting with the message and verify the request "
        "through a trusted, independent source."
    )


# ============================================================
# LOAD ML MODEL
# ============================================================

def _load_model():

    if not MODEL_FILE.exists():
        return None

    try:
        return joblib.load(MODEL_FILE)

    except Exception:
        return None


# ============================================================
# CATEGORY DETECTION
# ============================================================

def _category(
    text: str,
    names: set[str],
    suspicious: bool
) -> str:

    normalized = text.lower()

    if not suspicious:
        return "Benign"

    # Malicious download
    if (
        "download" in names
        and (
            "financial" in names
            or "banking" in names
        )
    ):
        return "malicious_download"

    # Scam / lottery / prize
    if any(
        term in normalized
        for term in (
            "prize",
            "lottery",
            "you won",
            "congratulations"
        )
    ):
        return "scam"

    # Credential theft
    if "credential_request" in names:
        return "credential_theft"

    if (
        "sensitive_request" in names
        and "financial" in names
        and "banking" in names
    ):
        return "financial_fraud"

    if "sensitive_request" in names:
        return "credential_theft"

    # Phishing
    if (
        "threat" in names
        and (
            "banking" in names
            or "link" in names
        )
    ):
        return "phishing"

    if (
        "financial" in names
        and "link" in names
    ):
        return "financial_fraud"

    if (
        "financial" in names
        and "urgent_language" in names
    ):
        return "scam"

    if "financial" in names:
        return "financial_fraud"

    if (
        "link" in names
        or "threat" in names
    ):
        return "phishing"

    return "suspicious"


# ============================================================
# MAIN MESSAGE RISK ENGINE
# ============================================================

def evaluate_message_risk(
    indicators: list[IndicatorMatch],
    message: str
) -> MessageRiskAnalysis:

    # --------------------------------------------------------
    # INDICATOR NAMES
    # --------------------------------------------------------

    names = {
        indicator.name
        for indicator in indicators
    }

    # --------------------------------------------------------
    # REASONS
    # Remove duplicate reasons while preserving order
    # --------------------------------------------------------

    reasons = list(
        dict.fromkeys(
            indicator.reason
            for indicator in indicators
        )
    )

    # --------------------------------------------------------
    # ML MODEL
    # --------------------------------------------------------

    model = _load_model()

    model_confidence = 0
    model_prediction = "unavailable"

    if model is not None:

        try:

            prediction = model.predict([message])[0]

            model_prediction = str(prediction)

            if hasattr(model, "predict_proba"):

                probabilities = model.predict_proba([message])[0]

                model_confidence = round(
                    float(max(probabilities)) * 100
                )

        except Exception:

            model_prediction = "unavailable"
            model_confidence = 0

    # --------------------------------------------------------
    # RULE ENGINE
    # --------------------------------------------------------

    strong_indicators = {
        "credential_request",
        "sensitive_request",
        "download",
        "threat"
    }

    strong_rule_count = sum(
        name in names
        for name in strong_indicators
    )

    # Suspicious combinations
    suspicious_pairs = [
        {"urgent_language", "link"},
        {"banking", "link"},
        {"financial", "link"},
        {"threat", "banking"},
    ]

    combination_count = sum(
        pair.issubset(names)
        for pair in suspicious_pairs
    )

    # --------------------------------------------------------
    # RULE CONFIDENCE
    # --------------------------------------------------------

    rule_confidence = min(
        100,
        35
        + strong_rule_count * 20
        + combination_count * 15
    )

    # --------------------------------------------------------
    # RULE SUSPICION
    # --------------------------------------------------------

    non_banking_indicators = names - {"banking"}

    rule_suspicious = (
        strong_rule_count > 0
        or combination_count > 0
        or len(non_banking_indicators) >= 2
    )

    # --------------------------------------------------------
    # ML SUSPICION
    # --------------------------------------------------------

    ml_suspicious = (
        model_prediction.lower()
        in {
            "suspicious",
            "spam",
            "scam",
            "phishing",
            "malicious"
        }
    )

    # --------------------------------------------------------
    # FINAL SUSPICION
    # --------------------------------------------------------

    suspicious = (
        rule_suspicious
        or ml_suspicious
    )

    # --------------------------------------------------------
    # BASE RISK SCORE
    # --------------------------------------------------------

    score = sum(
        indicator.points
        for indicator in indicators
    )

    # Extra points for suspicious combinations
    if combination_count > 0:
        score += 10

    # Extra ML points only when confidence is high
    if (
        ml_suspicious
        and model_confidence >= 70
    ):
        score += 10

    # Limit score
    score = min(score, 100)

    # Benign messages cannot accidentally become high risk
    if not suspicious:
        score = min(score, 24)

    # --------------------------------------------------------
    # RISK LEVEL
    # --------------------------------------------------------

    risk_level = _risk_level_from_score(score)

    # --------------------------------------------------------
    # CATEGORY
    # --------------------------------------------------------

    category = _category(
        message,
        names,
        suspicious
    )

    # --------------------------------------------------------
    # FINAL CONFIDENCE
    # --------------------------------------------------------

    if model_prediction != "unavailable":

        confidence = round(
            (
                rule_confidence
                + model_confidence
            ) / 2
        )

    else:

        confidence = rule_confidence

    confidence = min(
        100,
        max(0, confidence)
    )

    # --------------------------------------------------------
    # CONFIDENCE LEVEL
    # --------------------------------------------------------

    if confidence >= 75:
        confidence_level = "HIGH"

    elif confidence >= 45:
        confidence_level = "MEDIUM"

    else:
        confidence_level = "LOW"

    # --------------------------------------------------------
    # FALLBACK REASON
    # --------------------------------------------------------

    if not reasons and suspicious:

        reasons.append(
            "Message pattern is inconsistent with "
            "ordinary conversation."
        )

    # --------------------------------------------------------
    # RETURN RESULT
    # --------------------------------------------------------

    return MessageRiskAnalysis(

        risk_score=score,

        risk_level=risk_level,

        category=category,

        confidence=confidence,

        confidence_level=confidence_level,

        reasons=reasons,

        detected_indicators=sorted(names),

        recommendation=_generate_recommendation(
            score,
            reasons
        ),

        model_prediction=model_prediction,

        model_confidence=model_confidence,

        rule_confidence=rule_confidence,
    )


# ============================================================
# MESSAGE HASH
# ============================================================

def message_hash(message: str) -> str:

    return sha256(
        message.strip().encode("utf-8")
    ).hexdigest()