import re
import unicodedata
from collections.abc import Iterable

URL_RE = re.compile(
    r"(?:(?:https?|ftp)://|www\.)[A-Za-z0-9._~:/?#[\]@!$&'()*+,;=%-]+"
)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}")
REPEATED_CHAR_RE = re.compile(r"(.)\1{2,}")
EXCESSIVE_PUNCT_RE = re.compile(r"[!?.,;:]{3,}")

URGENT_KEYWORDS = [
    "urgent", "immediately", "asap", "act now", "today", "right now",
    "limited time", "expires today", "do it now", "now", "must act"
]
FINANCIAL_KEYWORDS = [
    "refund", "invoice", "bank", "wire transfer", "payment", "wallet",
    "transaction", "credit card", "account update", "salary", "bonus"
]
CREDENTIAL_KEYWORDS = [
    "otp", "one time password", "password", "credentials", "security code",
    "verify your password", "login details", "account blocked", "verify account"
]
KYC_KEYWORDS = [
    "kyc", "know your customer", "identity verification", "verify your account",
    "verify identity", "account verification", "verification required"
]
DOWNLOAD_KEYWORDS = [
    "download", "install", "apk", "click to install", "download now",
    "install app", "app update"
]
REWARD_KEYWORDS = [
    "prize", "lottery", "winner", "claim your reward", "congratulations",
    "free gift", "you won", "reward"
]
INVESTMENT_KEYWORDS = [
    "investment", "guaranteed profit", "double your money", "trading",
    "crypto", "returns", "profit"
]
SUSPICIOUS_KEYWORDS = {
    "urgent": URGENT_KEYWORDS,
    "financial": FINANCIAL_KEYWORDS,
    "credential": CREDENTIAL_KEYWORDS,
    "kyc": KYC_KEYWORDS,
    "download": DOWNLOAD_KEYWORDS,
    "reward": REWARD_KEYWORDS,
    "investment": INVESTMENT_KEYWORDS,
}


def normalize_unicode(value: str) -> str:
    """Normalize Unicode text while keeping cybersecurity-relevant tokens intact."""
    if not isinstance(value, str):
        raise TypeError("Input must be a string.")
    return unicodedata.normalize("NFKC", value)


def normalize_whitespace(value: str) -> str:
    """Collapse repeated whitespace and trim the text."""
    return re.sub(r"\s+", " ", value.strip())


def extract_urls(value: str) -> list[str]:
    return URL_RE.findall(value or "")


def extract_emails(value: str) -> list[str]:
    return EMAIL_RE.findall(value or "")


def extract_phone_numbers(value: str) -> list[str]:
    return PHONE_RE.findall(value or "")


def extract_suspicious_keywords(value: str) -> list[str]:
    text = normalize_whitespace(normalize_unicode(value)).lower()
    found: list[str] = []
    for keyword_group, patterns in SUSPICIOUS_KEYWORDS.items():
        for pattern in patterns:
            if pattern.lower() in text:
                found.append(f"{keyword_group}:{pattern}")
    return sorted(set(found))


def text_length(value: str) -> int:
    return len(normalize_whitespace(value))


def repeated_character_count(value: str) -> int:
    text = normalize_whitespace(value)
    return len(REPEATED_CHAR_RE.findall(text))


def excessive_punctuation_count(value: str) -> int:
    text = normalize_whitespace(value)
    return len(EXCESSIVE_PUNCT_RE.findall(text))


def uppercase_ratio(value: str) -> float:
    text = normalize_whitespace(value)
    letters = [ch for ch in text if ch.isalpha()]
    if not letters:
        return 0.0
    return sum(1 for ch in letters if ch.isupper()) / len(letters)


def digit_ratio(value: str) -> float:
    text = normalize_whitespace(value)
    if not text:
        return 0.0
    digits = sum(1 for ch in text if ch.isdigit())
    return digits / len(text)


def extract_message_features(value: str) -> dict:
    """Create security-oriented message features without destroying signal-rich content."""
    normalized = normalize_whitespace(normalize_unicode(value or ""))
    urls = extract_urls(normalized)
    emails = extract_emails(normalized)
    phones = extract_phone_numbers(normalized)
    suspicious_keywords = extract_suspicious_keywords(normalized)

    return {
        "text": normalized,
        "length": len(normalized),
        "url_count": len(urls),
        "urls": urls,
        "email_count": len(emails),
        "emails": emails,
        "phone_count": len(phones),
        "phones": phones,
        "suspicious_keywords": suspicious_keywords,
        "repeated_character_count": repeated_character_count(normalized),
        "excessive_punctuation_count": excessive_punctuation_count(normalized),
        "uppercase_ratio": round(uppercase_ratio(normalized), 4),
        "digit_ratio": round(digit_ratio(normalized), 4),
        "has_url": bool(urls),
        "has_email": bool(emails),
        "has_phone": bool(phones),
    }


if __name__ == "__main__":
    sample = "URGENT! Your KYC has expired. Click here to verify your identity and download the verification form."
    print(extract_message_features(sample))
