import re
import unicodedata
from difflib import SequenceMatcher
from urllib.parse import urlparse

# A small set of well-known brands for lookalike checks
KNOWN_BRANDS = [
    "microsoft.com",
    "google.com",
    "apple.com",
    "paypal.com",
    "amazon.com",
    "facebook.com",
    "bankofamerica.com",
    "hsbc.com",
    "slsp.sk",
    "tatrabanka.sk",
]

URL_REGEX = re.compile(r"https?://[^\s]+", re.IGNORECASE)

URGENCY_KEYWORDS = [
    "urgent", "immediately", "act now", "24 hours", "final notice",
    "your account will be", "suspended", "last warning", "overdue",
]
THREAT_KEYWORDS = [
    "legal action", "police", "lawsuit", "prosecution", "fine",
]
PAYMENT_KEYWORDS = [
    "gift card", "itunes card", "bitcoin", "crypto", "wire transfer",
    "western union", "moneygram", "voucher",
]
CREDENTIAL_KEYWORDS = [
    "password", "otp", "2fa", "verification code", "PIN", "passcode",
]


def extract_urls(text: str):
    return URL_REGEX.findall(text or "")


def contains_non_ascii(s: str) -> bool:
    try:
        s.encode("ascii")
        return False
    except UnicodeEncodeError:
        return True


def has_confusable_chars(s: str) -> bool:
    # Flag if characters are from mixed scripts (e.g., Cyrillic + Latin) or have suspicious categories
    scripts = set()
    for ch in s:
        try:
            name = unicodedata.name(ch)
        except ValueError:
            continue
        if "CYRILLIC" in name:
            scripts.add("CYRILLIC")
        elif "GREEK" in name:
            scripts.add("GREEK")
        elif "LATIN" in name:
            scripts.add("LATIN")
    return len(scripts) > 1


def domain_from_url(url: str) -> str:
    try:
        netloc = urlparse(url).netloc.lower()
        # strip port if present
        return netloc.split(":")[0]
    except Exception:
        return ""


def similar(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()


def analyze_text(text: str):
    text_lower = (text or "").lower()
    urls = extract_urls(text)

    flags = []
    score = 0

    # Urgency
    if any(k in text_lower for k in URGENCY_KEYWORDS):
        flags.append({
            "id": "urgency",
            "title": "Urgency or pressure",
            "severity": 2,
            "explanation": "The message uses urgency/pressure (e.g., 'act now', 'suspended')."
        })
        score += 15

    # Threats
    if any(k in text_lower for k in THREAT_KEYWORDS):
        flags.append({
            "id": "threat",
            "title": "Threatening language",
            "severity": 2,
            "explanation": "Mentions threats or legal action to force quick decisions."
        })
        score += 10

    # Payment requests
    if any(k in text_lower for k in PAYMENT_KEYWORDS):
        flags.append({
            "id": "payment",
            "title": "Unusual payment request",
            "severity": 3,
            "explanation": "Asks for gift cards, crypto, or non‑reversible transfers."
        })
        score += 25

    # Credential requests
    if any(k in text_lower for k in CREDENTIAL_KEYWORDS):
        flags.append({
            "id": "credentials",
            "title": "Requests codes or passwords",
            "severity": 3,
            "explanation": "Legitimate support will not ask for your OTP, 2FA, or password."
        })
        score += 25

    # Excessive punctuation / all caps (naive)
    if text.count("!") >= 3 or (len(text) > 0 and sum(1 for c in text if c.isupper()) > (0.4 * len(text))):
        flags.append({
            "id": "style",
            "title": "Shouting or excessive punctuation",
            "severity": 1,
            "explanation": "Unusual formatting can be a social‑engineering tactic."
        })
        score += 5

    # URL checks
    suspicious_domains = []
    for u in urls:
        d = domain_from_url(u)
        if not d:
            continue
        # unicode/punycode suspicion
        if contains_non_ascii(d) or has_confusable_chars(d):
            flags.append({
                "id": "unicode",
                "title": "Non‑ASCII or mixed‑script domain",
                "severity": 3,
                "explanation": f"Domain '{d}' contains non‑ASCII or mixed scripts that can hide lookalikes."
            })
            score += 20
        # lookalike based on similarity
        for kb in KNOWN_BRANDS:
            if d != kb and similar(d, kb) > 0.75:
                suspicious_domains.append((d, kb))
                break
        # uncommon TLD heuristic
        if d.split(".")[-1] in {"zip", "top", "cam", "info", "biz", "ru", "cn"}:
            flags.append({
                "id": "tld",
                "title": "Unfamiliar or high‑risk TLD",
                "severity": 1,
                "explanation": f"Domain '{d}' uses a TLD often seen in spam."
            })
            score += 5

    if suspicious_domains:
        pretty = ", ".join([f"{d}≈{kb}" for d, kb in suspicious_domains])
        flags.append({
            "id": "lookalike",
            "title": "Brand lookalike domain",
            "severity": 3,
            "explanation": f"These domains resemble well‑known brands: {pretty}."
        })
        score += 25

    # Cap score 0..100 and derive verdict
    score = max(0, min(100, score))
    if score >= 70:
        verdict = "High Risk"
        color = "red"
    elif score >= 35:
        verdict = "Caution"
        color = "orange"
    else:
        verdict = "Likely Safe"
        color = "green"

    return {
        "score": score,
        "verdict": verdict,
        "color": color,
        "flags": flags,
        "urls": urls,
    }
