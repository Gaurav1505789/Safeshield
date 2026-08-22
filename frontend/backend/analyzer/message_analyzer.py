import re
from dataclasses import dataclass


@dataclass(frozen=True)
class IndicatorMatch:
    name: str
    points: int
    reason: str


PATTERNS = {
    "urgent_language": ["urgent", "immediately", "now", "today", "last chance", "act now"],
    "banking": ["bank", "banking", "account", "transaction", "kyc", "upi", "payment", "card"],
    "credential": ["otp", "password", "pin", "cvv", "login", "username", "verification code"],
    "financial": ["refund", "prize", "lottery", "cash", "money", "payment", "reward"],
    "download": ["download", "install", "apk", "application", "attachment"],
    "link": ["http", "https", "www", "click", "link", "verify"],
    "threat": ["blocked", "suspended", "deactivated", "expire", "expired", "closed"],
    "personal_information": ["aadhaar", "pan", "otp", "password", "pin", "cvv", "account number", "bank details"],
}

REQUEST_WORDS = ["send", "share", "provide", "enter", "confirm", "submit", "verify", "give"]


def _normalize_text(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().lower())


def _has_any(text: str, patterns: list[str]) -> bool:
    return any(re.search(rf"\b{re.escape(pattern)}\b", text) for pattern in patterns)


def analyze_message(message: str) -> list[IndicatorMatch]:
    normalized = _normalize_text(message)
    matches: list[IndicatorMatch] = []

    descriptions = {
        "urgent_language": (10, "Urgent language detected."),
        "banking": (5, "Banking-related language detected."),
        "credential": (20, "Credential or authentication language detected."),
        "financial": (10, "Financial or reward language detected."),
        "download": (20, "Download or install instruction detected."),
        "link": (10, "Link or verification action detected."),
        "threat": (15, "Threat of account suspension or closure detected."),
        "personal_information": (15, "Sensitive personal information language detected."),
    }
    for name, patterns in PATTERNS.items():
        if _has_any(normalized, patterns):
            points, reason = descriptions[name]
            matches.append(IndicatorMatch(name=name, points=points, reason=reason))

    if _has_any(normalized, PATTERNS["credential"]) and _has_any(normalized, REQUEST_WORDS):
        matches.append(IndicatorMatch("credential_request", 25, "Request for OTP, password, PIN, or another credential detected."))
    if _has_any(normalized, PATTERNS["personal_information"]) and _has_any(normalized, REQUEST_WORDS):
        matches.append(IndicatorMatch("sensitive_request", 20, "Request for sensitive personal or financial information detected."))

    return matches
