import re
import ipaddress
import unicodedata
from collections import Counter
from .url_features import (
    BRAND_NAMES,
    BRAND_SAFE_TLDS,
    SUSPICIOUS_TLDS,
    levenshtein_distance,
    _check_typosquatting_min_dist,
)

# ── Keyword lists ──────────────────────────────────────────────────────────────
SUSPICIOUS_KEYWORDS = [
    'free', 'click', 'verify', 'confirm', 'urgent', 'update', 'login',
    'secure', 'bank', 'account', 'claim', 'prize', 'win',
]

STRONG_PHISH_COMBOS = [
    ('verify', 'account'), ('confirm', 'login'), ('update', 'bank'),
    ('secure', 'verify'), ('claim', 'prize'), ('win', 'prize'),
]

DOWNLOAD_EXTS = [
    '.exe', '.msi', '.zip', '.rar', '.jar', '.apk', '.dmg', '.pkg',
    '.bat', '.scr', '.ps1', '.tar', '.7z', '.iso',
]
DOWNLOAD_KEYWORDS = ['download', 'dl', 'attachment', 'installer', 'setup']

ZERO_WIDTH_CHARS = {'\u200b', '\u200c', '\u200d', '\ufeff'}
RESERVED_TLDS = {'test', 'example', 'invalid', 'localhost'}

# Regex patterns for path noise filtering (routine IDs that are NOT gibberish)
UUID_PATTERN = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
HEX_HASH_PATTERN = re.compile(r'^[0-9a-fA-F]{16,64}$')
ROUTINE_PATH_PATTERN = re.compile(r'^(page|p|ep|episode|slide|pub|item|id|v|doc|presentation|d|e|auth|oauth)[0-9a-zA-Z_-]*$', re.I)

# ── Scoring weights for rule categories ───────────────────────────────────────
_W = {
    'at_sign':          0.35,   # credential-redirect
    'ip_host':          0.30,   # bare IP
    'private_ip':       0.20,   # private/loopback IP
    'punycode':         0.25,   # IDN spoofing
    'typosquatting':    0.40,   # brand spoofing / typosquatting
    'suspicious_tld':   0.20,   # high-risk TLD
    'kw_single':        0.10,   # single suspicious keyword (soft)
    'kw_combo':         0.25,   # co-occurring phish keywords (hard)
    'no_https':         0.05,   # missing TLS (soft)
    'url_long':         0.10,   # URL > 200 chars
    'subdomain_deep':   0.15,   # > 3 subdomain levels
    'bad_chars':        0.15,   # unusual chars
    'download_ext':     0.30,   # suspicious download extension
    'download_kw':      0.20,   # download keyword in path/query
    'token_anomaly':    0.10,   # per token issue
    'unicode_unusual':  0.15,   # non-ASCII / invisible chars
    'domain_invalid':   0.40,   # domain fails basic validation
}


def _is_valid_hostname(hostname: str) -> tuple:
    """Basic syntactic hostname validation. Returns (bool, reason_if_any)."""
    if not hostname:
        return False, 'Empty host'

    if hostname.lower() in ('localhost', '127.0.0.1', '::1'):
        return False, 'Host is localhost or loopback'

    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
            return False, 'IP host is private, loopback, link-local, multicast, or reserved'
        return True, ''
    except Exception:
        pass

    if len(hostname) > 253:
        return False, 'Hostname too long'

    labels = hostname.split('.')
    if len(labels) < 2:
        return False, 'Hostname missing dot/TLD'

    for label in labels:
        if not label:
            return False, 'Empty label in hostname'
        if len(label) > 63:
            return False, 'Hostname label too long'
        if not re.match(r'^[A-Za-z0-9-]+$', label):
            return False, f'Invalid characters in label `{label}`'
        if label.startswith('-') or label.endswith('-'):
            return False, f'Label `{label}` starts/ends with hyphen'

    if len(labels[-1]) < 2:
        return False, 'Top-level domain too short'

    if labels[-1].lower() in RESERVED_TLDS:
        return False, f'Top-level domain "{labels[-1]}" is reserved/special-use'

    return True, ''


def _tokenize(text: str) -> list:
    """Split text into alphanumeric tokens (words)."""
    if not text:
        return []
    tokens = re.split(r'[^A-Za-z0-9]+', text)
    return [t for t in tokens if t]


def _is_routine_path_token(token: str) -> bool:
    """Return True if token is a standard UUID, hex hash, or routine pagination/episode ID."""
    if UUID_PATTERN.match(token) or HEX_HASH_PATTERN.match(token) or ROUTINE_PATH_PATTERN.match(token):
        return True
    return False


def _detect_unusual_chars(text: str) -> list:
    """Return list of findings about unusual unicode characters or symbols."""
    findings = []
    if not text:
        return findings

    non_ascii = [c for c in text if ord(c) > 127]
    if non_ascii:
        ctr = Counter(non_ascii)
        sample = ''.join(list(ctr.keys())[:6])
        findings.append(f'Non-ASCII characters present (sample: {sample})')

    zw = [c for c in text if c in ZERO_WIDTH_CHARS]
    if zw:
        findings.append('Zero-width or invisible characters present')

    combining = [c for c in text if unicodedata.category(c).startswith('M')]
    if combining:
        findings.append('Combining Unicode marks present')

    letters = [c for c in text if c.isalpha()]
    scripts = set()
    for c in letters:
        try:
            name = unicodedata.name(c)
            scripts.add(name.split(' ')[0])
        except Exception:
            scripts.add('UNKNOWN')
    if len(scripts) > 1:
        findings.append('Mixed Unicode scripts detected (e.g., Latin+Cyrillic)')

    unusual_punct = [c for c in text if c in '<>#{}|\\^~[]`']
    if unusual_punct:
        findings.append(f'Unusual punctuation present: {set(unusual_punct)}')

    return findings


def rule_check(normalized_info: dict) -> tuple:
    """Apply deterministic rules to determine if URL is suspicious.

    Returns:
        (is_suspicious: bool, reasons: list[str], domain_valid: bool,
         unusual_findings: list[str], rule_score: float)
    """
    hard_reasons = []
    soft_reasons = []
    unusual_findings = []
    penalty = 0.0

    url = normalized_info.get('normalized_url') or ''
    netloc = normalized_info.get('netloc') or ''
    path = normalized_info.get('path') or ''
    query = normalized_info.get('query') or ''
    scheme = normalized_info.get('scheme') or ''
    is_ip = normalized_info.get('is_ip', False)
    is_punycode = normalized_info.get('is_punycode', False)

    host_only = netloc.split(':')[0]
    host_labels = host_only.split('.')
    tld = host_labels[-1].lower() if host_labels else ''
    registered_domain = host_labels[-2] if len(host_labels) >= 2 else host_only

    # ── Typosquatting Engine (Levenshtein check) ──────────────────────────────
    min_dist, is_typosquat, matched_brand = _check_typosquatting_min_dist(netloc)
    if is_typosquat:
        hard_reasons.append(
            f"Possible typosquatting / domain spoofing detected: '{registered_domain}' is suspiciously close to '{matched_brand}'"
        )
        penalty += _W['typosquatting']

    # ── Suspicious TLD check ──────────────────────────────────────────────────
    if tld in SUSPICIOUS_TLDS:
        soft_reasons.append(f"Uses high-risk top-level domain (.{tld}) frequently abused in phishing")
        penalty += _W['suspicious_tld']

    # ── Rule: '@' in URL ──────────────────────────────────────────────────────
    if '@' in url:
        hard_reasons.append("Contains '@' symbol (likely credential-stealing redirect or obfuscation)")
        penalty += _W['at_sign']

    # ── Rule: IP address in host ──────────────────────────────────────────────
    if is_ip:
        hard_reasons.append('Host is an IP address instead of a domain')
        penalty += _W['ip_host']
        try:
            ip_obj = ipaddress.ip_address(host_only)
            if ip_obj.is_private or ip_obj.is_loopback:
                hard_reasons.append('IP host is private or loopback')
                penalty += _W['private_ip']
        except Exception:
            pass

    # ── Rule: punycode / IDN ──────────────────────────────────────────────────
    if is_punycode:
        hard_reasons.append('Uses punycode (IDN) which can be used to spoof domain')
        penalty += _W['punycode']

    # ── Rule: suspicious keywords ─────────────────────────────────────────────
    lower_text = (netloc + ' ' + path + ' ' + query).lower()
    found_keywords = [k for k in SUSPICIOUS_KEYWORDS if k in lower_text]
    if found_keywords:
        combo_hit = any(
            all(kw in lower_text for kw in combo)
            for combo in STRONG_PHISH_COMBOS
        )
        if combo_hit:
            hard_reasons.append('Phishing keyword combination found: ' + ', '.join(found_keywords))
            penalty += _W['kw_combo']
        else:
            soft_reasons.append('Suspicious keyword(s) found: ' + ', '.join(found_keywords))
            penalty += _W['kw_single']

    # ── Rule: missing HTTPS ───────────────────────────────────────────────────
    if scheme != 'https':
        soft_reasons.append('Not HTTPS (no TLS)')
        penalty += _W['no_https']

    # ── Rule: URL length ──────────────────────────────────────────────────────
    if len(url) > 200:
        hard_reasons.append('Excessive URL length (> 200 characters)')
        penalty += _W['url_long']

    # ── Rule: too many subdomains ─────────────────────────────────────────────
    if len(host_labels) - 1 > 3:
        hard_reasons.append('Unusually deep subdomain nesting')
        penalty += _W['subdomain_deep']

    # ── Rule: unusual characters ──────────────────────────────────────────────
    if re.search(r'[^a-zA-Z0-9\-._:/?=&%+~,;!()*\'@#]', url):
        hard_reasons.append('Unusual characters in URL')
        penalty += _W['bad_chars']

    # ── Rule: suspicious download extensions / keywords ───────────────────────
    p_lower = path.lower()
    q_lower = query.lower()
    file_suspicious = False
    for ext in DOWNLOAD_EXTS:
        if p_lower.endswith(ext) or ext in q_lower:
            file_suspicious = True
            hard_reasons.append(f'Suspicious download extension found: {ext}')
            penalty += _W['download_ext']
            break
    if not file_suspicious:
        if any(k in p_lower or k in q_lower for k in DOWNLOAD_KEYWORDS):
            hard_reasons.append('Download-related keywords found in path or query')
            penalty += _W['download_kw']

    # ── Rule: token-level anomalies with routine path noise filter ────────────
    tokens = _tokenize(netloc + ' ' + path)
    token_issues = []
    for t in tokens:
        # Ignore routine path tokens (UUIDs, hex hashes, pagination/slide IDs)
        if _is_routine_path_token(t):
            continue

        if len(t) > 35:
            token_issues.append(f'Long token `{t[:30]}...`')
        digits = sum(c.isdigit() for c in t)
        if len(t) >= 8 and digits > 0 and (digits / len(t) > 0.85):
            token_issues.append(f'Token with very high digit ratio: `{t}`')
        if any(ch * 5 in t for ch in set(t)):
            token_issues.append(f'Excessive repeated character in token: `{t}`')
        letters = sum(c.isalpha() for c in t)
        if len(t) >= 8 and letters > 0 and (letters / len(t) < 0.25):
            token_issues.append(f'Gibberish token: `{t}`')

    if token_issues:
        token_penalty = min(_W['token_anomaly'] * len(token_issues), 0.25)
        hard_reasons.append('Token-level anomalies: ' + '; '.join(token_issues[:5]))
        penalty += token_penalty

    # ── Rule: unusual unicode / symbols ──────────────────────────────────────
    unusual_findings = _detect_unusual_chars(netloc + path + query)
    if unusual_findings:
        for finding in unusual_findings:
            hard_reasons.append(finding)
        penalty += _W['unicode_unusual']

    # ── Rule: domain syntactic validity ──────────────────────────────────────
    domain_valid, domain_reason = _is_valid_hostname(host_only)
    if not domain_valid:
        hard_reasons.append('Domain validation failed: ' + domain_reason)
        penalty += _W['domain_invalid']

    reasons = hard_reasons + soft_reasons
    rule_score = min(penalty, 1.0)
    is_suspicious = len(hard_reasons) > 0

    return is_suspicious, reasons, domain_valid, unusual_findings, rule_score


# ── Live HTML heuristics (BeautifulSoup) ───────────────────────────────────────
# Called ONLY when a live page fetch succeeds.  The existing rule_check() and
# ML pipeline are unmodified; findings here are merged by the caller (url_analyzer).

_EXECUTABLE_EXTS = {
    '.exe', '.bat', '.apk', '.scr', '.msi', '.iso', '.zip',
    '.rar', '.ps1', '.jar', '.vbs', '.hta', '.dll', '.cab',
    '.cmd', '.com', '.pif', '.lnk',
}

_BRAND_KEYWORDS = frozenset([
    'paypal', 'amazon', 'google', 'facebook', 'apple', 'microsoft', 'netflix',
    'instagram', 'twitter', 'linkedin', 'whatsapp', 'youtube', 'ebay', 'walmart',
    'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'hsbc', 'barclays',
    'binance', 'coinbase', 'adobe', 'dropbox', 'icloud', 'outlook', 'gmail',
])


def inspect_html_content(html: str, url_info: dict, return_details: bool = False) -> tuple:
    """Parse live HTML for phishing, credential-harvesting and drive-by indicators.

    Parameters
    ----------
    html           : Raw HTML string from the live page fetch.
    url_info       : Normalised URL info dict (same schema as normalize_url() output).
    return_details : bool, optional. If True, returns (reasons, indicators, penalty, force_fraud, details_dict).

    Returns
    -------
    (reasons, indicators, extra_penalty, force_fraud)  [or 5-tuple if return_details=True]
    """
    reasons: list[str] = []
    indicators: list[str] = []
    extra_penalty: float = 0.0
    force_fraud: bool = False
    details: dict = {
        "title": "",
        "forms_count": 0,
        "password_inputs_count": 0,
        "iframes_count": 0,
        "hidden_iframes_count": 0,
        "links_checked_count": 0,
        "executable_links_count": 0,
    }

    if not html:
        if return_details:
            return reasons, indicators, extra_penalty, force_fraud, details
        return reasons, indicators, extra_penalty, force_fraud

    try:
        from bs4 import BeautifulSoup
    except ImportError:
        if return_details:
            return reasons, indicators, extra_penalty, force_fraud, details
        return reasons, indicators, extra_penalty, force_fraud

    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        try:
            soup = BeautifulSoup(html, "html.parser")
        except Exception:
            if return_details:
                return reasons, indicators, extra_penalty, force_fraud, details
            return reasons, indicators, extra_penalty, force_fraud

    page_netloc = url_info.get("netloc", "").lower().split(":")[0]
    page_scheme = url_info.get("scheme", "https")

    # ── 1. Password form / credential-harvesting check ────────────────────────
    all_forms = soup.find_all("form")
    details["forms_count"] = len(all_forms)

    pwd_inputs = soup.find_all("input", {"type": re.compile(r"^password$", re.I)})
    details["password_inputs_count"] = len(pwd_inputs)

    if pwd_inputs:
        # Find the nearest enclosing <form> for each password field
        for pwd in pwd_inputs:
            form = pwd.find_parent("form")
            if form is None:
                continue

            action = (form.get("action") or "").strip()

            # Resolve relative actions against the page origin
            if action == "" or action.startswith("#"):
                # Posts back to same page – not suspicious on its own
                continue

            # Detect absolute URLs submitting to a *different* host
            if re.match(r"^https?://", action, re.I):
                try:
                    from urllib.parse import urlparse as _up
                    action_host = _up(action).netloc.lower().split(":")[0]
                    if action_host and action_host != page_netloc:
                        reasons.append(
                            f"Password form submits credentials to external domain '{action_host}'"
                        )
                        indicators.append("credential_harvesting")
                        extra_penalty += 0.50
                        force_fraud = True
                except Exception:
                    pass
            else:
                # Relative action – check if the page itself is not HTTPS
                if page_scheme != "https":
                    reasons.append(
                        "Password form on non-HTTPS page (credentials sent in plaintext)"
                    )
                    indicators.append("credential_harvesting")
                    extra_penalty += 0.30
                    force_fraud = True

    # ── 2. Hidden / zero-size iframe detection ────────────────────────────────
    all_iframes = soup.find_all("iframe")
    details["iframes_count"] = len(all_iframes)
    hidden_iframes_found = 0

    for iframe in all_iframes:
        style = (iframe.get("style") or "").lower().replace(" ", "")
        width = (iframe.get("width") or "").strip()
        height = (iframe.get("height") or "").strip()

        is_hidden_style = (
            "display:none" in style
            or "visibility:hidden" in style
            or "width:0" in style
            or "height:0" in style
            or "opacity:0" in style
        )
        is_zero_size = (width in ("0", "0px", "1", "1px") or height in ("0", "0px", "1", "1px"))

        if is_hidden_style or is_zero_size:
            hidden_iframes_found += 1
            if hidden_iframes_found == 1:
                src = iframe.get("src") or ""
                reasons.append(
                    f"Hidden/zero-size iframe detected{(' (src: ' + src[:80] + ')') if src else ''}"
                )
                indicators.append("hidden_iframe")
                extra_penalty += 0.25

    details["hidden_iframes_count"] = hidden_iframes_found

    # ── 3. Brand/title mismatch detection ────────────────────────────────────
    title_tag = soup.find("title")
    page_title = (title_tag.get_text(strip=True).lower() if title_tag else "")
    details["title"] = page_title

    if page_title:
        for brand in _BRAND_KEYWORDS:
            if brand in page_title and brand not in page_netloc:
                reasons.append(
                    f"Page title mentions brand '{brand}' but domain does not match"
                )
                indicators.append("brand_title_mismatch")
                extra_penalty += 0.30
                break  # Report only the most prominent mismatch

    # ── 4. Drive-by download link detection ───────────────────────────────────
    all_anchors = soup.find_all("a", href=True)
    details["links_checked_count"] = len(all_anchors)

    drive_by_found: list[str] = []
    for anchor in all_anchors:
        href = (anchor.get("href") or "").strip().lower()
        # Strip query/fragment for extension check
        href_path = href.split("?")[0].split("#")[0]
        for ext in _EXECUTABLE_EXTS:
            if href_path.endswith(ext):
                drive_by_found.append(href[:120])
                break

    details["executable_links_count"] = len(drive_by_found)

    if drive_by_found:
        sample = drive_by_found[0]
        reasons.append(
            f"Drive-by download link detected on page (e.g. '{sample}')"
        )
        indicators.append("drive_by_download_risk")
        extra_penalty += 0.35
        force_fraud = True

    # Deduplicate
    indicators = list(dict.fromkeys(indicators))
    if return_details:
        return reasons, indicators, min(extra_penalty, 1.0), force_fraud, details
    return reasons, indicators, min(extra_penalty, 1.0), force_fraud


