import math
import re
from .url_normalize import normalize_url
from pathlib import Path


DATASET_DIR = Path(__file__).resolve().parents[1]

# Major brand names whose presence or typosquatting in a domain signals phishing
BRAND_NAMES = frozenset([
    'paypal', 'amazon', 'google', 'facebook', 'apple', 'microsoft', 'netflix',
    'instagram', 'twitter', 'linkedin', 'whatsapp', 'youtube', 'ebay', 'walmart',
    'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'hsbc', 'barclays',
    'dropbox', 'icloud', 'onedrive', 'outlook', 'gmail', 'yahoo',
    'fedex', 'ups', 'dhl', 'usps', 'irs', 'ssa', 'medicare', 'binance', 'coinbase', 'stripe', 'adobe'
])

# High-risk / suspicious TLDs frequently abused by phishing campaigns
SUSPICIOUS_TLDS = frozenset([
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'club', 'work', 'buzz', 'fit',
    'icu', 'monster', 'site', 'cc', 'click', 'link', 'live', 'online', 'rest',
    'space', 'website', 'cam', 'quest', 'cfd', 'sbs', 'agency', 'cyou'
])

# Authoritative TLDs for top brands
BRAND_SAFE_TLDS = frozenset(['com', 'net', 'org', 'co', 'io', 'gov', 'edu'])


def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute pure-Python Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def _shannon_entropy(text: str) -> float:
    """Compute Shannon entropy (bits) of a string."""
    if not text:
        return 0.0
    length = len(text)
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    entropy = -sum((c / length) * math.log2(c / length) for c in counts.values())
    return round(entropy, 4)


def _longest_digit_run(text: str) -> int:
    """Return the length of the longest consecutive digit sequence."""
    max_run = 0
    current = 0
    for ch in text:
        if ch.isdigit():
            current += 1
            if current > max_run:
                max_run = current
        else:
            current = 0
    return max_run


def _longest_alnum_token(text: str) -> int:
    """Return the length of the longest alphanumeric token (split on non-alnum)."""
    tokens = re.split(r'[^A-Za-z0-9]', text)
    return max((len(t) for t in tokens if t), default=0)


def _max_consecutive_char_repeat(text: str) -> int:
    """Return the maximum consecutive repetition of any character in text."""
    if not text:
        return 0
    max_rep = 1
    curr = 1
    for i in range(1, len(text)):
        if text[i] == text[i - 1]:
            curr += 1
            if curr > max_rep:
                max_rep = curr
        else:
            curr = 1
    return max_rep


def _vowel_to_consonant_ratio(text: str) -> float:
    """Compute ratio of vowels to consonants in text."""
    vowels = set('aeiouAEIOU')
    consonants = set('bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ')
    v_count = sum(1 for c in text if c in vowels)
    c_count = sum(1 for c in text if c in consonants)
    if c_count == 0:
        return float(v_count)
    return round(v_count / c_count, 4)


def _brand_impersonation(netloc: str) -> int:
    """
    Return 1 if a major brand name appears in the netloc in a suspicious context.
    """
    netloc_lower = netloc.lower()
    labels = netloc_lower.split('.')
    tld = labels[-1] if labels else ''
    registered = labels[-2] if len(labels) >= 2 else netloc_lower

    for brand in BRAND_NAMES:
        if brand in netloc_lower:
            if registered == brand and tld in BRAND_SAFE_TLDS:
                return 0
            return 1
    return 0


def _check_typosquatting_min_dist(netloc: str) -> tuple[int, int, str]:
    """
    Check netloc labels for typosquatting against top brands using Levenshtein distance.
    Returns (min_dist, is_typosquat_flag, matched_brand).
    """
    netloc_lower = netloc.lower().split(':')[0]
    labels = netloc_lower.split('.')
    tld = labels[-1] if labels else ''

    # Strip subdomains and TLD: target registered domain label
    registered = labels[-2] if len(labels) >= 2 else labels[0]

    # Substitutions common in typosquatting (e.g. 0 -> o, 1 -> l/i)
    normalized_registered = (
        registered.replace('0', 'o')
        .replace('1', 'l')
        .replace('3', 'e')
        .replace('5', 's')
    )

    min_dist = 99
    matched_brand = ""

    for brand in BRAND_NAMES:
        if registered == brand:
            # Exact match
            if tld in BRAND_SAFE_TLDS:
                return 0, 0, brand
            continue

        dist_raw = levenshtein_distance(registered, brand)
        dist_norm = levenshtein_distance(normalized_registered, brand)
        dist = min(dist_raw, dist_norm)

        if dist < min_dist:
            min_dist = dist
            matched_brand = brand

    is_typosquat = 1 if (1 <= min_dist <= 2) else 0
    return min_dist, is_typosquat, matched_brand


def extract_url_features(url: str) -> list:
    """
    Extract 30 numeric features from a URL.

    Feature vector (fixed-length, in order):
      0  url_len                — total normalized URL length
      1  dot_count              — number of dots
      2  hyphen_count           — number of hyphens
      3  at_count               — number of '@' symbols
      4  is_https               — 1 if scheme is https
      5  host_dot_count         — dot count in netloc (domain depth)
      6  path_depth             — number of non-empty path segments
      7  digit_count            — total digits in full URL
      8  has_suspicious_kw      — 1 if any suspicious keyword found
      9  underscore_count       — number of underscores
      10 query_param_count      — number of query parameters
      11 is_ip                  — 1 if host is a raw IP address
      12 is_punycode            — 1 if IDN/punycode domain
      13 is_whitelisted         — 1 if host in forced_negatives whitelist
      14 domain_entropy         — Shannon entropy of netloc (host only)
      15 path_entropy           — Shannon entropy of path string
      16 digit_ratio            — digit_count / url_len (0 if url_len == 0)
      17 special_char_count     — count of %, =, &, ~, !, ;, , chars in URL
      18 subdomain_count        — number of sub-labels above registered domain
      19 tld_len                — character length of the TLD
      20 has_port               — 1 if non-default port in netloc
      21 path_token_longest     — length of longest alphanumeric token in path
      22 consecutive_digits_max — longest run of consecutive digits in full URL
      23 brand_impersonation    — 1 if known brand is spoofed in netloc
      24 double_slash_in_path   — 1 if '//' appears in path component
      25 vowel_to_consonant     — ratio of vowels to consonants in URL
      26 consecutive_char_repeat— max consecutive repetition of any char
      27 hex_char_count         — count of hex percent-encoded sequences (%XX)
      28 suspicious_tld_flag    — 1 if TLD is in high-risk suspicious TLD list
      29 typosquatting_flag     — 1 if host is Levenshtein distance 1-2 from top brand
    """

    suspicious_keywords = [
        'free', 'click', 'verify', 'confirm', 'urgent', 'update',
        'login', 'secure', 'bank', 'account', 'claim', 'prize', 'win',
    ]

    info = normalize_url(url)
    n_url = info.get('normalized_url', '')
    host = info.get('netloc', '')
    path = info.get('path', '')
    query = info.get('query', '')

    # ── Structural & lexical basic features (0-13) ───────────────────────────
    url_len = len(n_url)
    dot_count = n_url.count('.')
    hyphen_count = n_url.count('-')
    at_count = n_url.count('@')

    is_https = 1 if info.get('scheme') == 'https' else 0
    host_dot_count = host.count('.')
    path_depth = len([p for p in path.split('/') if p])
    digit_count = sum(1 for c in n_url if c.isdigit())
    has_suspicious = 1 if any(kw in n_url.lower() for kw in suspicious_keywords) else 0
    underscore_count = n_url.count('_')
    query_param_count = 0 if not query else query.count('&') + 1
    is_ip = 1 if info.get('is_ip') else 0
    is_punycode = 1 if info.get('is_punycode') else 0

    # Whitelist check
    is_whitelisted = 0
    try:
        host_lower = host.lower().split(':')[0]
        global _WHITELIST
        if '_WHITELIST' not in globals():
            _WHITELIST = set()
            try:
                wl_path = DATASET_DIR / 'forced_negatives.txt'
                if not wl_path.exists():
                    wl_path = DATASET_DIR / 'whitelist.txt'
                with open(wl_path, 'r', encoding='utf-8') as fh:
                    for line in fh:
                        entry = line.strip().lower()
                        if entry:
                            _WHITELIST.add(entry)
            except Exception:
                _WHITELIST = set()
        if host_lower in _WHITELIST or any(
            host_lower.endswith('.' + t) for t in _WHITELIST
        ):
            is_whitelisted = 1
    except Exception:
        is_whitelisted = 0

    # ── Advanced entropy & lexical features (14-24) ──────────────────────────
    domain_only = host.split(':')[0] if ':' in host else host
    domain_entropy = _shannon_entropy(domain_only)
    path_entropy = _shannon_entropy(path)
    digit_ratio = round(digit_count / url_len, 4) if url_len > 0 else 0.0

    special_chars = set('%=&~!;,')
    special_char_count = sum(1 for c in n_url if c in special_chars)

    labels = domain_only.split('.')
    subdomain_count = max(0, len(labels) - 2)
    tld = labels[-1].lower() if labels else ''
    tld_len = len(tld)

    has_port = 0
    if ':' in host:
        port_str = host.rsplit(':', 1)[-1]
        if port_str.isdigit():
            port = int(port_str)
            scheme = info.get('scheme', '')
            if not (scheme == 'http' and port == 80) and not (scheme == 'https' and port == 443):
                has_port = 1

    path_token_longest = _longest_alnum_token(path)
    consecutive_digits_max = _longest_digit_run(n_url)
    brand_imp = _brand_impersonation(host)
    double_slash_in_path = 1 if '//' in path else 0

    # ── Hackathon Advanced Features (25-29) ──────────────────────────────────
    vowel_to_consonant = _vowel_to_consonant_ratio(n_url)
    consecutive_char_repeat = _max_consecutive_char_repeat(n_url)
    hex_char_count = len(re.findall(r'%[0-9A-Fa-f]{2}', n_url))
    suspicious_tld_flag = 1 if tld in SUSPICIOUS_TLDS else 0

    _min_dist, typosquatting_flag, _brand = _check_typosquatting_min_dist(host)

    return [
        url_len,                 # 0
        dot_count,               # 1
        hyphen_count,            # 2
        at_count,                # 3
        is_https,                # 4
        host_dot_count,          # 5
        path_depth,              # 6
        digit_count,             # 7
        has_suspicious,          # 8
        underscore_count,        # 9
        query_param_count,       # 10
        is_ip,                   # 11
        is_punycode,             # 12
        is_whitelisted,          # 13
        domain_entropy,          # 14
        path_entropy,            # 15
        digit_ratio,             # 16
        special_char_count,      # 17
        subdomain_count,         # 18
        tld_len,                 # 19
        has_port,                # 20
        path_token_longest,      # 21
        consecutive_digits_max,  # 22
        brand_imp,               # 23
        double_slash_in_path,    # 24
        vowel_to_consonant,      # 25
        consecutive_char_repeat, # 26
        hex_char_count,          # 27
        suspicious_tld_flag,     # 28
        typosquatting_flag,      # 29
    ]