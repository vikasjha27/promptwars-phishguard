"""Deterministic phishing and scam triage engine.

No outbound network requests are made. Optional AI enrichment is only used when
an API key is configured and the local analysis is always returned as baseline.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Iterable
from urllib.parse import urlparse

MAX_TEXT_LENGTH = 5000
MAX_URL_LENGTH = 2048
MAX_SENDER_LENGTH = 120

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "rb.gy", "tiny.cc", "shorturl.at", "t.ly",
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "tk", "ml", "ga", "cf", "gq", "zip", "mov",
    "country", "stream", "download", "gives", "loan", "work", "support",
    "fit", "rest", "cam",
}

FREE_HOSTING_DOMAINS = {
    "pages.dev", "vercel.app", "netlify.app", "github.io", "web.app",
    "firebaseapp.com", "blogspot.com", "weebly.com", "wixsite.com",
    "godaddysites.com", "duckdns.org", "no-ip.org",
}

BRAND_KEYWORDS = {
    "google": ["google", "g00gle", "go0gle", "goog1e"],
    "microsoft": ["microsoft", "micros0ft", "rnicrosoft", "micr0soft"],
    "paypal": ["paypal", "paypa1", "paypai", "paypall"],
    "amazon": ["amazon", "amaz0n", "arnazon", "amazonn"],
    "apple": ["apple", "app1e", "appl3"],
    "sbi": ["sbi", "sb1"],
    "hdfc": ["hdfc", "hdfcbank", "hdfc-bank"],
    "icici": ["icici", "icicibank", "icici-bank"],
    "axis": ["axisbank", "axis-bank"],
    "paytm": ["paytm", "paytmm"],
    "whatsapp": ["whatsapp", "whatsap", "vvhatsapp"],
    "instagram": ["instagram", "lnstagram"],
    "facebook": ["facebook", "faceb00k"],
    "netflix": ["netflix", "netf1ix"],
    "dhl": ["dhl"],
    "fedex": ["fedex", "fedx"],
    "irs": ["irs"],
    "gov": ["government", "govt"],
}

OFFICIAL_BRAND_DOMAINS = {
    "google": {"google.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com"},
    "paypal": {"paypal.com"},
    "amazon": {"amazon.com", "amazon.in"},
    "apple": {"apple.com", "icloud.com"},
    "sbi": {"sbi.co.in", "onlinesbi.sbi"},
    "hdfc": {"hdfcbank.com"},
    "icici": {"icicibank.com"},
    "axis": {"axisbank.com"},
    "paytm": {"paytm.com"},
    "whatsapp": {"whatsapp.com"},
    "instagram": {"instagram.com"},
    "facebook": {"facebook.com"},
    "netflix": {"netflix.com"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
}

URGENCY_PATTERNS = [
    (r"\b(urgent|immediately|right now|within \d+\s*(?:minutes?|hours?|days?)|act now|final warning|last chance)\b", "Urgency or pressure language"),
    (r"\b(account (?:will be|has been)?\s*(?:suspended|blocked|locked|deactivated|limited)|suspend your account)\b", "Account suspension threat"),
    (r"\b(kyc|know your customer).{0,30}\b(expir|updat|verif|fail|incomplete|pending)\b", "KYC/update pressure"),
    (r"\b(verify|confirm).{0,30}\b(account|identity|details|information|login)\b", "Verification request"),
]

CREDENTIAL_PATTERNS = [
    (r"\b(otp|one[- ]time password|pin|cvv|password|passcode|security code)\b", "Credential or OTP request"),
    (r"\b(bank details|card number|debit card|credit card|net banking|login credentials)\b", "Sensitive financial information request"),
]

SCAM_PATTERNS = [
    (r"\b(won|winner|lottery|prize|reward|gift card|congratulations).{0,40}\b(claim|click|link|pay|fee)\b", "Prize/lottery lure"),
    (r"\b(registration fee|processing fee|training fee|security deposit|pay.{0,20}fee|refundable fee)\b", "Upfront fee request"),
    (r"\b(internship|job offer|work from home).{0,60}\b(fee|deposit|pay|registration)\b", "Job/internship fee scam cue"),
    (r"\b(scan.{0,20}qr|qr code).{0,30}\b(pay|payment|receive|refund)\b", "QR/payment scam cue"),
    (r"\b(send money|wire transfer|crypto|bitcoin|gift cards?)\b", "Unusual payment method request"),
]

URL_RE = re.compile(
    r"(?:(?:https?|hxxps?)://|www\.)[^\s<>'\"]+",
    re.IGNORECASE,
)
DEFANGED_DOT_RE = re.compile(r"\[\.\]|\(\.\)|\{\.\}")
DEFANGED_SCHEME_RE = re.compile(r"\bhxxps?://", re.IGNORECASE)

ZERO_WIDTH_CHARS = {
    "​": "U+200B ZERO WIDTH SPACE",
    "‌": "U+200C ZERO WIDTH NON-JOINER",
    "‍": "U+200D ZERO WIDTH JOINER",
    "﻿": "U+FEFF ZERO WIDTH NO-BREAK SPACE",
}
DANGEROUS_EXT_RE = re.compile(r"\b[\w.-]+\.(apk|exe|bat|scr|iso|js|vbs|cmd|ps1|msi)\b", re.IGNORECASE)
ARCHIVE_EXT_RE = re.compile(r"\b[\w.-]+\.(zip|rar|7z|gz)\b", re.IGNORECASE)
UPI_SCAM_RE = re.compile(
    r"\b(upi\s+(?:collect|request|refund)|collect\s+request|approve\s+(?:the\s+)?collect|enter\s+(?:your\s+)?upi\s+pin\s+to\s+(?:receive|refund|get)|receive\s+(?:money|refund).{0,30}upi\s+pin|send\s+money\s+via\s+upi)\b",
    re.IGNORECASE,
)
HEADER_FROM_RE = re.compile(r"^From:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
HEADER_REPLY_RE = re.compile(r"^Reply-To:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
HEADER_RETURN_RE = re.compile(r"^Return-Path:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
AUTH_FAIL_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*fail\b", re.IGNORECASE)
EMAIL_ADDR_RE = re.compile(r"[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})", re.IGNORECASE)


@dataclass
class Signal:
    points: int
    reason: str
    tactic: str | None = None
    indicator: str | None = None
    snippet: str | None = None


@dataclass
class AnalysisResult:
    risk_score: int
    verdict: str
    confidence: str
    extracted_indicators: list[str]
    reasons: list[str]
    recommended_actions: list[str]
    safe_reply_template: str | None
    signals: list[Signal] = field(default_factory=list)


def _clamp_text(value: str | None, limit: int) -> str:
    if not value:
        return ""
    value = value.strip()
    if len(value) > limit:
        return value[:limit]
    return value


def refang_url(url: str) -> str:
    """Convert defanged URL to parseable form for analysis only."""
    u = url.strip().rstrip(").,;!?\"'")
    u = DEFANGED_SCHEME_RE.sub(lambda m: "https://" if "s" in m.group(0).lower() else "http://", u)
    u = DEFANGED_DOT_RE.sub(".", u)
    u = re.sub(r"\[:\]", ":", u)
    if u.lower().startswith("www."):
        u = "http://" + u
    return u


def defang_url(url: str) -> str:
    u = url.strip().rstrip(").,;!?\"'")
    u = re.sub(r"^http://", "hxxp://", u, flags=re.IGNORECASE)
    u = re.sub(r"^https://", "hxxps://", u, flags=re.IGNORECASE)
    u = u.replace(".", "[.]")
    return u


def defang_domain(domain: str) -> str:
    return domain.replace(".", "[.]")


def extract_urls(text: str, standalone_url: str = "") -> list[str]:
    candidates: list[str] = []
    for match in URL_RE.finditer(text or ""):
        candidates.append(match.group(0))
    if standalone_url:
        candidates.append(standalone_url.strip())
    # Also catch defanged forms that might not start with scheme after normalization misses
    for match in re.finditer(r"\b(?:[a-z0-9-]+\[\.\])+[a-z]{2,}(?:/[^\s<>'\"]*)?", text or "", re.IGNORECASE):
        candidates.append(match.group(0))

    seen: set[str] = set()
    urls: list[str] = []
    for raw in candidates:
        cleaned = raw.strip().rstrip(").,;!?\"'")
        if not cleaned:
            continue
        norm = refang_url(cleaned)
        key = norm.lower()
        if key in seen:
            continue
        # basic sanity: must have a dot/host
        parsed = urlparse(norm)
        host = (parsed.hostname or "").lower()
        if not host or "." not in host:
            continue
        seen.add(key)
        urls.append(norm)
    return urls


def get_domain(url: str) -> str:
    parsed = urlparse(refang_url(url))
    return (parsed.hostname or "").lower().strip(".")


def is_ip_literal(domain: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", domain))


def registered_like_domain(domain: str) -> str:
    parts = [p for p in domain.split(".") if p]
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def domain_is_brand_official(domain: str, brand: str) -> bool:
    official = OFFICIAL_BRAND_DOMAINS.get(brand, set())
    return any(domain == d or domain.endswith("." + d) for d in official)


def detect_lookalike(domain: str) -> list[str]:
    hits: list[str] = []
    compact = domain.replace("-", "")
    labels = domain.split(".")
    left = ".".join(labels[:-1]) if len(labels) > 1 else domain
    left_compact = re.sub(r"[^a-z0-9]", "", left.lower())
    for brand, variants in BRAND_KEYWORDS.items():
        if domain_is_brand_official(domain, brand):
            continue
        brand_hit = False
        for variant in variants:
            v = variant.lower()
            if v in left.lower() or v in compact.lower():
                if v == brand.lower():
                    hits.append(f"Brand name '{brand}' appears in non-official domain")
                else:
                    hits.append(f"Lookalike pattern for '{brand}' ({variant})")
                brand_hit = True
                break
        if brand_hit:
            continue
        # simple homoglyph/typo heuristic for brand in domain label
        if any(_looks_similar(left_compact, v.lower()) for v in variants):
            hits.append(f"Possible typosquatting targeting '{brand}'")
    return list(dict.fromkeys(hits))


def _looks_similar(host_left: str, variant: str) -> bool:
    # Cheap similarity: same length and few char diffs, or variant present as token-ish.
    if variant in host_left:
        return True
    token = re.sub(r"[^a-z0-9]", "", host_left)
    if not token or abs(len(token) - len(variant)) > 2:
        return False
    # common substitutions
    norm = token.replace("0", "o").replace("1", "l").replace("3", "e").replace("@", "a").replace("5", "s")
    varnorm = variant.replace("0", "o").replace("1", "l").replace("3", "e")
    if norm == varnorm:
        return True
    if len(token) == len(variant):
        diffs = sum(a != b for a, b in zip(token, variant))
        return diffs <= 1
    return False


def extract_indicators(text: str, urls: list[str]) -> list[str]:
    indicators: list[str] = []
    for u in urls:
        indicators.append(f"URL: {defang_url(u)}")
        d = get_domain(u)
        if d:
            indicators.append(f"Domain: {defang_domain(d)}")
    # de-dupe preserving order
    seen = set()
    out = []
    for i in indicators:
        if i.lower() in seen:
            continue
        seen.add(i.lower())
        out.append(i)
    return out




def _domain_from_header_value(value: str) -> str:
    m = EMAIL_ADDR_RE.search(value or "")
    if m:
        return m.group(1).lower().strip(".")
    # fallback: try to grab domain-like token
    m2 = re.search(r"\b([a-z0-9.-]+\.[a-z]{2,})\b", (value or "").lower())
    return m2.group(1).strip(".") if m2 else ""


def detect_email_header_spoofing(text: str) -> list[Signal]:
    signals: list[Signal] = []
    from_m = HEADER_FROM_RE.search(text or "")
    reply_m = HEADER_REPLY_RE.search(text or "")
    return_m = HEADER_RETURN_RE.search(text or "")
    from_d = _domain_from_header_value(from_m.group(1)) if from_m else ""
    reply_d = _domain_from_header_value(reply_m.group(1)) if reply_m else ""
    return_d = _domain_from_header_value(return_m.group(1)) if return_m else ""

    if from_d and reply_d and registered_like_domain(from_d) != registered_like_domain(reply_d):
        signals.append(Signal(25, f"From/Reply-To domain mismatch: {defang_domain(from_d)} vs {defang_domain(reply_d)}.", "Email header spoofing", defang_domain(reply_d), f"From/Reply-To mismatch: {from_d} vs {reply_d}"))
    if from_d and return_d and registered_like_domain(from_d) != registered_like_domain(return_d):
        signals.append(Signal(20, f"From/Return-Path domain mismatch: {defang_domain(from_d)} vs {defang_domain(return_d)}.", "Email header spoofing", defang_domain(return_d), f"From/Return-Path mismatch: {from_d} vs {return_d}"))

    for m in AUTH_FAIL_RE.finditer(text or ""):
        mech = m.group(1).lower()
        signals.append(Signal(20, f"Email authentication failure indicator detected: {mech}=fail.", "Email auth failure", f"{mech}=fail", m.group(0)))
    return signals


def detect_obfuscation(text: str, urls: list[str]) -> list[Signal]:
    signals: list[Signal] = []
    for ch, name in ZERO_WIDTH_CHARS.items():
        # ch may be literal "\u200b" or actual unicode char
        if ch.startswith("\\u") and len(ch) == 6:
            actual = chr(int(ch[2:], 16))
        elif len(ch) == 1:
            actual = ch
        else:
            m = re.search(r"[0-9a-fA-F]{4}", ch)
            actual = chr(int(m.group(0), 16)) if m else ""
        if actual and (actual in (text or "") or ch in (text or "")):
            signals.append(Signal(20, f"Hidden zero-width character detected ({name}).", "Text obfuscation", name, name))

    for u in urls:
        raw_host = urlparse(u).hostname or ""
        domain = get_domain(u)
        check_vals = [raw_host, domain, u]
        non_ascii = None
        for val in check_vals:
            for c in val:
                if ord(c) > 127:
                    non_ascii = c
                    break
            if non_ascii:
                break
        if non_ascii:
            disp = defang_domain(domain) if domain else defang_url(u)
            signals.append(Signal(30, f"Mixed-script/non-ASCII lookalike characters detected in domain: {disp}.", "Unicode homograph", disp, raw_host or domain))
            continue
        if "xn--" in domain:
            pass
    # Catch non-ASCII domain-like tokens in raw text
    for m in re.finditer(r"(?:^|(?<=\s))([\w\-\.]*[^\x00-\x7F][\w\-\.]*\.[a-z]{2,})(?=[\s/]|$)", text or ""):
        tok = m.group(1)
        disp = defang_domain(tok.lower())
        if not any(disp.lower() in (s.indicator or "").lower() for s in signals):
            signals.append(Signal(30, f"Mixed-script/non-ASCII lookalike characters detected in domain: {disp}.", "Unicode homograph", disp, tok))
    return signals


def detect_attachments_and_upi(text: str) -> list[Signal]:
    signals: list[Signal] = []
    lowered = (text or "").lower()
    has_urgency = bool(re.search(r"\b(urgent|immediately|invoice|payment|due|suspend|verify|action required|attach|document)\b", lowered))
    for m in DANGEROUS_EXT_RE.finditer(text or ""):
        ext = m.group(1).lower()
        pts = 25 if has_urgency or ext in {"apk", "exe", "bat", "scr", "js", "vbs", "cmd", "ps1", "msi"} else 15
        signals.append(Signal(pts, f"Dangerous attachment/file extension detected: .{ext}.", "Malicious attachment", m.group(0), m.group(0)))
    for m in ARCHIVE_EXT_RE.finditer(text or ""):
        if has_urgency or "invoice" in lowered or "payment" in lowered:
            signals.append(Signal(15, f"Archive attachment combined with urgency/invoice cue: {m.group(0)}.", "Malicious attachment", m.group(0), m.group(0)))
    for m in UPI_SCAM_RE.finditer(text or ""):
        signals.append(Signal(25, "UPI refund/collect payment trap pattern detected.", "UPI/payment scam", "UPI scam", m.group(0)))
    return signals
def analyze_input(text: str | None, url: str | None, sender: str | None = None) -> dict:
    text = _clamp_text(text, MAX_TEXT_LENGTH)
    url = _clamp_text(url, MAX_URL_LENGTH)
    sender = _clamp_text(sender, MAX_SENDER_LENGTH)
    combined = "\n".join([p for p in [text, url] if p]).strip()

    if not combined:
        return {
            "risk_score": 0,
            "verdict": "Safe",
            "confidence": "High",
            "extracted_indicators": [],
            "reasons": ["No content provided for analysis."],
            "recommended_actions": ["Paste a suspicious message or URL to triage."],
            "safe_reply_template": None,
            "matched_snippets": [],
        }

    urls = extract_urls(text, url)
    signals: list[Signal] = []
    tactics: list[str] = []

    # URL-based signals
    for u in urls:
        parsed = urlparse(u)
        domain = get_domain(u)
        scheme = (parsed.scheme or "").lower()
        host_labels = [p for p in domain.split(".") if p]
        tld = host_labels[-1] if host_labels else ""
        registered = registered_like_domain(domain)

        if scheme == "http":
            signals.append(Signal(10, f"Insecure HTTP link detected: {defang_url(u)}", "Insecure transport", defang_url(u)))
        if is_ip_literal(domain):
            signals.append(Signal(25, f"IP-literal URL used instead of a domain: {defang_url(u)}", "IP-literal URL", defang_domain(domain)))
        if registered in SHORTENER_DOMAINS or domain in SHORTENER_DOMAINS:
            signals.append(Signal(20, f"URL shortener can hide the real destination: {defang_domain(domain)}", "URL shortener", defang_domain(domain)))
        if tld in SUSPICIOUS_TLDS:
            signals.append(Signal(15, f"Suspicious top-level domain '.{tld}' detected: {defang_domain(domain)}", "Suspicious TLD", defang_domain(domain)))
        if "xn--" in domain:
            signals.append(Signal(20, f"Punycode domain detected, which can be used for lookalikes: {defang_domain(domain)}", "Punycode/homograph", defang_domain(domain)))
        if len(host_labels) >= 4:
            signals.append(Signal(10, f"Excessive subdomains observed: {defang_domain(domain)}", "Excessive subdomains", defang_domain(domain)))
        if "@" in u:
            signals.append(Signal(15, f"URL contains '@', which can obscure the true destination: {defang_url(u)}", "Obfuscated URL", defang_url(u)))

        lookalikes = detect_lookalike(domain)
        for lk in lookalikes:
            signals.append(Signal(25, f"{lk} in domain {defang_domain(domain)}", "Typosquatting/lookalike", defang_domain(domain)))

        domain_left = ".".join(host_labels[:-1]) if len(host_labels) > 1 else domain
        if re.search(r"\b(kyc|verify|verification|secure|update|login|signin|password|account|unlock|support)\b", domain_left, re.IGNORECASE) and not any(domain_is_brand_official(domain, b) for b in OFFICIAL_BRAND_DOMAINS):
            signals.append(Signal(10, f"Domain contains credential/verification bait keywords: {defang_domain(domain)}", "Phishing domain keywords", defang_domain(domain)))

        path_q = (parsed.path or "") + "?" + (parsed.query or "")
        if re.search(r"\b(login|signin|verify|verification|secure|update|kyc|password|account|unlock)\b", path_q, re.IGNORECASE):
            signals.append(Signal(5, f"Sensitive path keywords in URL: {defang_url(u)}", "Credential-harvesting path", defang_url(u)))

        if registered in FREE_HOSTING_DOMAINS or domain in FREE_HOSTING_DOMAINS:
            signals.append(Signal(10, f"URL hosted on free/shared hosting: {defang_domain(domain)}", "Free hosting abuse", defang_domain(domain)))

    # Text-based signals
    lowered = combined.lower()
    for pattern, reason in URGENCY_PATTERNS:
        m = re.search(pattern, combined, re.IGNORECASE | re.DOTALL)
        if m:
            tactic = "Urgency/social pressure"
            if "kyc" in reason.lower():
                tactic = "KYC/verification pressure"
            elif "suspension" in reason.lower():
                tactic = "Account threat"
            signals.append(Signal(15, reason + ".", tactic, snippet=m.group(0)[:80]))

    for pattern, reason in CREDENTIAL_PATTERNS:
        m = re.search(pattern, combined, re.IGNORECASE)
        if m:
            signals.append(Signal(30, reason + ".", "Credential harvesting", snippet=m.group(0)[:80]))

    for pattern, reason in SCAM_PATTERNS:
        m = re.search(pattern, combined, re.IGNORECASE | re.DOTALL)
        if m:
            points = 20 if "fee" in reason.lower() or "Job" in reason else 15
            tactic = "Financial scam"
            if "Job" in reason:
                tactic = "Job/internship scam"
            elif "QR" in reason:
                tactic = "QR/payment scam"
            elif "Prize" in reason:
                tactic = "Prize/lottery scam"
            signals.append(Signal(points, reason + ".", tactic, snippet=m.group(0)[:80]))

    # Generic urgency markers
    exclamations = combined.count("!")
    caps_words = re.findall(r"\b[A-Z]{4,}\b", combined)
    if exclamations >= 3 or len(caps_words) >= 4:
        signals.append(Signal(5, "Message uses aggressive formatting (excessive punctuation/capitalization).", "Pressure formatting"))

    # Context mismatch
    sender_l = sender.lower()
    if sender_l and sender_l != "unknown" and urls:
        sender_kind = None
        if any(k in sender_l for k in ["bank", "sbi", "hdfc", "icici", "axis", "paytm"]):
            sender_kind = "bank"
        elif any(k in sender_l for k in ["gov", "government", "tax", "irs", "police"]):
            sender_kind = "government"
        elif any(k in sender_l for k in ["employer", "hr", "company", "recruit", "intern"]):
            sender_kind = "employer"
        elif any(k in sender_l for k in ["delivery", "courier", "dhl", "fedex", "usps"]):
            sender_kind = "delivery"

        if sender_kind:
            for u in urls:
                domain = get_domain(u)
                registered = registered_like_domain(domain)
                brand_match = None
                for brand in OFFICIAL_BRAND_DOMAINS:
                    if brand in sender_l or brand in lowered:
                        brand_match = brand
                        break
                if brand_match:
                    if not domain_is_brand_official(domain, brand_match):
                        signals.append(Signal(20, f"Sender/context claims '{brand_match}' but link domain {defang_domain(domain)} is not an official domain.", "Context mismatch", defang_domain(domain)))
                elif registered in FREE_HOSTING_DOMAINS or tld_of(domain) in SUSPICIOUS_TLDS or is_ip_literal(domain):
                    signals.append(Signal(15, f"Sender claims to be {sender_kind} but uses untrusted domain {defang_domain(domain)}.", "Context mismatch", defang_domain(domain)))

    # Additional deep detections
    signals.extend(detect_obfuscation(combined, urls))
    signals.extend(detect_email_header_spoofing(text))
    signals.extend(detect_attachments_and_upi(combined))

    # Deduplicate signals by (reason, indicator)
    deduped: list[Signal] = []
    seen_sig = set()
    for s in signals:
        key = (s.reason.lower(), (s.indicator or "").lower(), s.points)
        if key in seen_sig:
            continue
        seen_sig.add(key)
        deduped.append(s)
    signals = deduped

    # Score calculation
    raw_score = sum(s.points for s in signals)
    # Diminish stacking of same tactic slightly
    tactic_counts: dict[str, int] = {}
    for s in signals:
        if s.tactic:
            tactic_counts[s.tactic] = tactic_counts.get(s.tactic, 0) + 1
    penalty = 0
    for t, c in tactic_counts.items():
        if c > 2:
            penalty += (c - 2) * 3
    score = max(0, min(100, raw_score - penalty))

    # Benign mitigation: no signals and no URLs -> very safe
    if not signals:
        score = min(score, 5)

    verdict = "Safe" if score <= 29 else "Suspicious" if score <= 64 else "High Risk"
    strong = [s for s in signals if s.points >= 20]
    confidence = "High" if (len(strong) >= 2 or score >= 75 or score <= 5) else "Medium"

    for s in signals:
        if s.tactic and s.tactic not in tactics:
            tactics.append(s.tactic)

    indicators = extract_indicators(combined, urls)
    for s in signals:
        if s.indicator and all(s.indicator.lower() not in i.lower() for i in indicators):
            indicators.append(s.indicator)
    for t in tactics:
        label = f"Tactic: {t}"
        if label not in indicators:
            indicators.append(label)

    reasons = [s.reason for s in signals]
    if not reasons:
        reasons = ["No strong phishing or scam indicators were detected in the provided content."]

    recommended_actions = build_recommendations(verdict, tactics, sender)
    safe_reply = build_safe_reply(verdict, sender)

    matched_snippets: list[str] = []
    for s in signals:
        snip = (s.snippet or "").strip()
        if not snip:
            # derive short snippet from indicator/reason for evidence
            snip = (s.indicator or "")[:80]
        snip = re.sub(r"\s+", " ", snip).strip()
        if snip and snip.lower() not in {m.lower() for m in matched_snippets}:
            matched_snippets.append(snip[:120])

    result = {
        "risk_score": int(score),
        "verdict": verdict,
        "confidence": confidence,
        "extracted_indicators": indicators[:20],
        "reasons": reasons[:12],
        "recommended_actions": recommended_actions,
        "safe_reply_template": safe_reply,
        "matched_snippets": matched_snippets[:12],
    }

    result = maybe_enrich_with_ai(result, combined, sender)
    return result


def tld_of(domain: str) -> str:
    parts = [p for p in domain.split(".") if p]
    return parts[-1] if parts else ""


def build_recommendations(verdict: str, tactics: list[str], sender: str) -> list[str]:
    sender_l = (sender or "").lower()
    common = [
        "Do not click unknown links or download unexpected attachments.",
        "Verify the message through an official app, website, or trusted contact channel.",
    ]
    if verdict == "High Risk":
        actions = [
            "Do not reply, click links, scan QR codes, or share OTPs, passwords, or personal details.",
            "Verify the claim using the organization's official website or helpline, not the message link.",
            "Report the message as phishing/scam to your security team, carrier, or platform.",
        ]
        if "Credential harvesting" in tactics:
            actions.append("If you already entered credentials, change the password immediately and enable MFA from the official site.")
        if "QR/payment scam" in tactics or "Financial scam" in tactics:
            actions.append("Do not send money or approve payments; confirm payment requests through a separate trusted channel.")
        return actions
    if verdict == "Suspicious":
        actions = [
            "Treat the message with caution and avoid clicking links until independently verified.",
            "Contact the sender through a known official channel to confirm legitimacy.",
            "If the message asks for money, credentials, or urgency, report it to your security/helpdesk team.",
        ]
        if any(k in sender_l for k in ["bank", "gov", "delivery", "employer"]):
            actions.append("Use the official app or bookmarked website instead of any link provided in the message.")
        return actions
    return [
        "No immediate phishing indicators were detected, but remain cautious with unexpected requests.",
        "Verify sensitive requests through official channels if context changes.",
    ]


def build_safe_reply(verdict: str, sender: str) -> str | None:
    if verdict == "Safe":
        return None
    sender_name = sender.strip() if sender and sender.strip().lower() != "unknown" else "the sender"
    return (
        f"I can't take action using the link or details in this message. "
        f"I will verify this request through an official channel before responding. "
        f"If you are legitimate, please share a reference I can confirm via the official {sender_name} contact method."
    )


def maybe_enrich_with_ai(result: dict, content: str, sender: str) -> dict:
    """Optionally enrich explanation with configured AI provider.

    This is best-effort and never required. Any failure returns the original
    deterministic result unchanged.
    """
    openai_key = os.getenv("OPENAI_API_KEY", "").strip()
    gemini_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not openai_key and not gemini_key:
        return result

    prompt = (
        "You are a security assistant. In 1-2 short sentences, explain why this message may be risky. "
        "Do not include markdown. Be cautious and factual.\n\n"
        f"Sender: {sender or 'Unknown'}\n"
        f"Verdict: {result['verdict']} (score {result['risk_score']}/100)\n"
        f"Signals: {'; '.join(result['reasons'][:6])}\n"
        f"Content: {content[:1000]}"
    )

    try:
        import json
        import urllib.request

        if openai_key:
            body = json.dumps({
                "model": os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.2,
                "max_tokens": 80,
            }).encode("utf-8")
            req = urllib.request.Request(
                "https://api.openai.com/v1/chat/completions",
                data=body,
                headers={"Authorization": f"Bearer {openai_key}", "Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            text = data["choices"][0]["message"]["content"].strip()
        else:
            model = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")
            endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={gemini_key}"
            body = json.dumps({
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"temperature": 0.2, "maxOutputTokens": 80},
            }).encode("utf-8")
            req = urllib.request.Request(endpoint, data=body, headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            text = data["candidates"][0]["content"]["parts"][0]["text"].strip()

        if text:
            text = re.sub(r"\s+", " ", text).strip()
            reasons = list(result.get("reasons", []))
            note = f"AI summary: {text[:240]}"
            if note not in reasons:
                reasons.insert(0, note)
            result["reasons"] = reasons[:12]
    except Exception:
        return result
    return result
