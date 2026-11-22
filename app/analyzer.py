"""Deterministic phishing and scam triage engine.

No outbound network requests are made to user-submitted URLs. Optional AI
enrichment runs only when an API key is configured; deterministic analysis is
always the baseline and fallback.
"""

from __future__ import annotations

import copy
import functools
import os
import re
from dataclasses import dataclass
from typing import Literal, TypedDict
from urllib.parse import urlparse

MAX_TEXT_LENGTH = 5000
MAX_URL_LENGTH = 2048
MAX_SENDER_LENGTH = 120

Verdict = Literal["Safe", "Suspicious", "High Risk"]
Confidence = Literal["High", "Medium"]


class AnalysisResultDict(TypedDict):
    """Structured triage response returned by the analyzer."""

    risk_score: int
    verdict: Verdict
    confidence: Confidence
    extracted_indicators: list[str]
    reasons: list[str]
    recommended_actions: list[str]
    safe_reply_template: str | None
    matched_snippets: list[str]


@dataclass(slots=True)
class Signal:
    """A single scored detection signal."""

    points: int
    reason: str
    tactic: str | None = None
    indicator: str | None = None
    snippet: str | None = None


# --- Precompiled patterns ---
URL_RE = re.compile(r"(?:(?:https?|hxxps?)://|www\.)[^\s<>'\"]+", re.IGNORECASE)
DEFANGED_URL_RE = re.compile(r"\b(?:[a-z0-9-]+\[\.\])+[a-z]{2,}(?:/[^\s<>'\"]*)?", re.IGNORECASE)
DEFANGED_DOT_RE = re.compile(r"\[\.\]|\(\.\)|\{\.\}")
DEFANGED_SCHEME_RE = re.compile(r"\bhxxps?://", re.IGNORECASE)
COLON_BRACKET_RE = re.compile(r"\[:\]")
TRAILING_PUNCT_RE = re.compile(r"[).,;!?\"']+$")
WHITESPACE_RE = re.compile(r"\s+")
NON_ALNUM_RE = re.compile(r"[^a-z0-9]")
IP_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
DOMAIN_TOKEN_RE = re.compile(r"\b([a-z0-9.-]+\.[a-z]{2,})\b", re.IGNORECASE)
HEX4_RE = re.compile(r"[0-9a-fA-F]{4}")
CAPS_WORD_RE = re.compile(r"\b[A-Z]{4,}\b")
DANGEROUS_EXT_RE = re.compile(r"\b[\w.-]+\.(apk|exe|bat|scr|iso|js|vbs|cmd|ps1|msi)\b", re.IGNORECASE)
ARCHIVE_EXT_RE = re.compile(r"\b[\w.-]+\.(zip|rar|7z|gz)\b", re.IGNORECASE)
UPI_SCAM_RE = re.compile(
    r"\b(upi\s+(?:collect|request|refund)|collect\s+request|approve\s+(?:the\s+)?collect|"
    r"enter\s+(?:your\s+)?upi\s+pin\s+to\s+(?:receive|refund|get)|receive\s+(?:money|refund).{0,30}upi\s+pin|send\s+money\s+via\s+upi)\b",
    re.IGNORECASE,
)
HEADER_FROM_RE = re.compile(r"^From:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
HEADER_REPLY_RE = re.compile(r"^Reply-To:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
HEADER_RETURN_RE = re.compile(r"^Return-Path:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
AUTH_FAIL_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*fail\b", re.IGNORECASE)
EMAIL_ADDR_RE = re.compile(r"[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})", re.IGNORECASE)
SENSITIVE_PATH_RE = re.compile(r"\b(login|signin|verify|verification|secure|update|kyc|password|account|unlock)\b", re.IGNORECASE)
DOMAIN_BAIT_RE = re.compile(r"\b(kyc|verify|verification|secure|update|login|signin|password|account|unlock|support)\b", re.IGNORECASE)
URGENT_ATTACH_RE = re.compile(r"\b(urgent|immediately|invoice|payment|due|suspend|verify|action required|attach|document)\b", re.IGNORECASE)
NON_ASCII_DOMAIN_RE = re.compile(r"(?:^|(?<=\s))([\w\-.]*[^\x00-\x7F][\w\-.]*\.[a-z]{2,})(?=[\s/]|$)")
HTTP_RE = re.compile(r"^http://", re.IGNORECASE)
HTTPS_RE = re.compile(r"^https://", re.IGNORECASE)

# --- Lookup tables (O(1)) ---
SHORTENER_DOMAINS: frozenset[str] = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "rb.gy", "tiny.cc", "shorturl.at", "t.ly",
})
SUSPICIOUS_TLDS: frozenset[str] = frozenset({
    "xyz", "top", "click", "tk", "ml", "ga", "cf", "gq", "zip", "mov",
    "country", "stream", "download", "gives", "loan", "work", "support", "fit", "rest", "cam",
})
FREE_HOSTING_DOMAINS: frozenset[str] = frozenset({
    "pages.dev", "vercel.app", "netlify.app", "github.io", "web.app", "firebaseapp.com",
    "blogspot.com", "weebly.com", "wixsite.com", "godaddysites.com", "duckdns.org", "no-ip.org",
})
DANGEROUS_EXTS: frozenset[str] = frozenset({"apk", "exe", "bat", "scr", "js", "vbs", "cmd", "ps1", "msi"})
BANK_HINTS: frozenset[str] = frozenset({"bank", "sbi", "hdfc", "icici", "axis", "paytm"})
GOV_HINTS: frozenset[str] = frozenset({"gov", "government", "tax", "irs", "police"})
EMPLOYER_HINTS: frozenset[str] = frozenset({"employer", "hr", "company", "recruit", "intern"})
DELIVERY_HINTS: frozenset[str] = frozenset({"delivery", "courier", "dhl", "fedex", "usps"})
ZERO_WIDTH_CHARS: dict[str, str] = {"\u200b": "U+200B ZERO WIDTH SPACE", "\u200c": "U+200C ZERO WIDTH NON-JOINER", "\u200d": "U+200D ZERO WIDTH JOINER", "\ufeff": "U+FEFF ZERO WIDTH NO-BREAK SPACE"}

BRAND_KEYWORDS: dict[str, tuple[str, ...]] = {
    "google": ("google", "g00gle", "go0gle", "goog1e"), "microsoft": ("microsoft", "micros0ft", "rnicrosoft", "micr0soft"),
    "paypal": ("paypal", "paypa1", "paypai", "paypall"), "amazon": ("amazon", "amaz0n", "arnazon", "amazonn"),
    "apple": ("apple", "app1e", "appl3"), "sbi": ("sbi", "sb1"), "hdfc": ("hdfc", "hdfcbank", "hdfc-bank"),
    "icici": ("icici", "icicibank", "icici-bank"), "axis": ("axisbank", "axis-bank"), "paytm": ("paytm", "paytmm"),
    "whatsapp": ("whatsapp", "whatsap", "vvhatsapp"), "instagram": ("instagram", "lnstagram"), "facebook": ("facebook", "faceb00k"),
    "netflix": ("netflix", "netf1ix"), "dhl": ("dhl",), "fedex": ("fedex", "fedx"), "irs": ("irs",), "gov": ("government", "govt"),
}
OFFICIAL_BRAND_DOMAINS: dict[str, frozenset[str]] = {
    "google": frozenset({"google.com"}), "microsoft": frozenset({"microsoft.com", "live.com", "office.com"}),
    "paypal": frozenset({"paypal.com"}), "amazon": frozenset({"amazon.com", "amazon.in"}),
    "apple": frozenset({"apple.com", "icloud.com"}), "sbi": frozenset({"sbi.co.in", "onlinesbi.sbi"}),
    "hdfc": frozenset({"hdfcbank.com"}), "icici": frozenset({"icicibank.com"}), "axis": frozenset({"axisbank.com"}),
    "paytm": frozenset({"paytm.com"}), "whatsapp": frozenset({"whatsapp.com"}), "instagram": frozenset({"instagram.com"}),
    "facebook": frozenset({"facebook.com"}), "netflix": frozenset({"netflix.com"}), "dhl": frozenset({"dhl.com"}), "fedex": frozenset({"fedex.com"}),
}

URGENCY_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\b(urgent|immediately|right now|within \d+\s*(?:minutes?|hours?|days?)|act now|final warning|last chance)\b", re.I), "Urgency or pressure language"),
    (re.compile(r"\b(account (?:will be|has been)?\s*(?:suspended|blocked|locked|deactivated|limited)|suspend your account)\b", re.I), "Account suspension threat"),
    (re.compile(r"\b(kyc|know your customer).{0,30}\b(expir|updat|verif|fail|incomplete|pending)\b", re.I | re.S), "KYC/update pressure"),
    (re.compile(r"\b(verify|confirm).{0,30}\b(account|identity|details|information|login)\b", re.I | re.S), "Verification request"),
)
CREDENTIAL_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\b(otp|one[- ]time password|pin|cvv|password|passcode|security code)\b", re.I), "Credential or OTP request"),
    (re.compile(r"\b(bank details|card number|debit card|credit card|net banking|login credentials)\b", re.I), "Sensitive financial information request"),
)
SCAM_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\b(won|winner|lottery|prize|reward|gift card|congratulations).{0,40}\b(claim|click|link|pay|fee)\b", re.I | re.S), "Prize/lottery lure"),
    (re.compile(r"\b(registration fee|processing fee|training fee|security deposit|pay.{0,20}fee|refundable fee)\b", re.I), "Upfront fee request"),
    (re.compile(r"\b(internship|job offer|work from home).{0,60}\b(fee|deposit|pay|registration)\b", re.I | re.S), "Job/internship fee scam cue"),
    (re.compile(r"\b(scan.{0,20}qr|qr code).{0,30}\b(pay|payment|receive|refund)\b", re.I | re.S), "QR/payment scam cue"),
    (re.compile(r"\b(send money|wire transfer|crypto|bitcoin|gift cards?)\b", re.I), "Unusual payment method request"),
)


def _clamp_text(value: str | None, limit: int) -> str:
    """Trim and clamp input text to a safe maximum length."""
    if not value:
        return ""
    value = value.strip()
    return value[:limit] if len(value) > limit else value


def refang_url(url: str) -> str:
    """Convert a defanged URL into a parseable form for local analysis only."""
    u = TRAILING_PUNCT_RE.sub("", url.strip())
    u = DEFANGED_SCHEME_RE.sub(lambda m: "https://" if "s" in m.group(0).lower() else "http://", u)
    u = DEFANGED_DOT_RE.sub(".", u)
    u = COLON_BRACKET_RE.sub(":", u)
    if u.lower().startswith("www."):
        u = "http://" + u
    return u


def defang_url(url: str) -> str:
    """Defang a URL for safe display (no clickable/live link)."""
    u = TRAILING_PUNCT_RE.sub("", url.strip())
    u = HTTP_RE.sub("hxxp://", u)
    u = HTTPS_RE.sub("hxxps://", u)
    return u.replace(".", "[.]")


def defang_domain(domain: str) -> str:
    """Defang a domain for safe display."""
    return domain.replace(".", "[.]")


def get_domain(url: str) -> str:
    """Extract and normalize the hostname from a URL."""
    parsed = urlparse(refang_url(url))
    return (parsed.hostname or "").lower().strip(".")


def registered_like_domain(domain: str) -> str:
    """Return a naive registered-domain approximation (last two labels)."""
    parts = [p for p in domain.split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def is_ip_literal(domain: str) -> bool:
    """Return True when the domain is an IPv4 literal."""
    return bool(IP_RE.fullmatch(domain))


def domain_is_brand_official(domain: str, brand: str) -> bool:
    """Check whether a domain belongs to an official brand domain."""
    official = OFFICIAL_BRAND_DOMAINS.get(brand, frozenset())
    return any(domain == d or domain.endswith("." + d) for d in official)


def _looks_similar(host_left: str, variant: str) -> bool:
    """Cheap similarity heuristic for typosquatting detection."""
    if variant in host_left:
        return True
    token = NON_ALNUM_RE.sub("", host_left)
    if not token or abs(len(token) - len(variant)) > 2:
        return False
    norm = token.replace("0", "o").replace("1", "l").replace("3", "e").replace("@", "a").replace("5", "s")
    varnorm = variant.replace("0", "o").replace("1", "l").replace("3", "e")
    if norm == varnorm:
        return True
    return len(token) == len(variant) and sum(a != b for a, b in zip(token, variant)) <= 1


def detect_lookalike(domain: str) -> list[str]:
    """Detect brand impersonation/lookalike patterns in a domain."""
    hits: list[str] = []
    compact = domain.replace("-", "").lower()
    labels = domain.split(".")
    left = ".".join(labels[:-1]) if len(labels) > 1 else domain
    left_lower = left.lower()
    left_compact = NON_ALNUM_RE.sub("", left_lower)
    for brand, variants in BRAND_KEYWORDS.items():
        if domain_is_brand_official(domain, brand):
            continue
        brand_hit = False
        for variant in variants:
            v = variant.lower()
            if v in left_lower or v in compact:
                hits.append(f"Brand name '{brand}' appears in non-official domain" if v == brand.lower() else f"Lookalike pattern for '{brand}' ({variant})")
                brand_hit = True
                break
        if not brand_hit and any(_looks_similar(left_compact, v.lower()) for v in variants):
            hits.append(f"Possible typosquatting targeting '{brand}'")
    return list(dict.fromkeys(hits))


def _extract_urls(text: str, standalone_url: str = "") -> list[str]:
    """Extract and normalize URLs from text and standalone input."""
    candidates: list[str] = [m.group(0) for m in URL_RE.finditer(text or "")]
    if standalone_url:
        candidates.append(standalone_url.strip())
    candidates.extend(m.group(0) for m in DEFANGED_URL_RE.finditer(text or ""))
    seen: set[str] = set()
    urls: list[str] = []
    for raw in candidates:
        cleaned = TRAILING_PUNCT_RE.sub("", raw.strip())
        if not cleaned:
            continue
        norm = refang_url(cleaned)
        key = norm.lower()
        if key in seen:
            continue
        host = (urlparse(norm).hostname or "").lower()
        if not host or "." not in host:
            continue
        seen.add(key)
        urls.append(norm)
    return urls


# Backward-compatible alias
extract_urls = _extract_urls


def _domain_from_header_value(value: str) -> str:
    """Extract domain from an email header value."""
    m = EMAIL_ADDR_RE.search(value or "")
    if m:
        return m.group(1).lower().strip(".")
    m2 = DOMAIN_TOKEN_RE.search((value or "").lower())
    return m2.group(1).strip(".") if m2 else ""


def detect_email_header_spoofing(text: str) -> list[Signal]:
    """Detect From/Reply-To/Return-Path mismatches and auth failures."""
    signals: list[Signal] = []
    from_d = _domain_from_header_value(HEADER_FROM_RE.search(text or "").group(1)) if HEADER_FROM_RE.search(text or "") else ""
    reply_d = _domain_from_header_value(HEADER_REPLY_RE.search(text or "").group(1)) if HEADER_REPLY_RE.search(text or "") else ""
    return_d = _domain_from_header_value(HEADER_RETURN_RE.search(text or "").group(1)) if HEADER_RETURN_RE.search(text or "") else ""
    if from_d and reply_d and registered_like_domain(from_d) != registered_like_domain(reply_d):
        signals.append(Signal(25, f"From/Reply-To domain mismatch: {defang_domain(from_d)} vs {defang_domain(reply_d)}.", "Email header spoofing", defang_domain(reply_d), f"From/Reply-To mismatch: {from_d} vs {reply_d}"))
    if from_d and return_d and registered_like_domain(from_d) != registered_like_domain(return_d):
        signals.append(Signal(20, f"From/Return-Path domain mismatch: {defang_domain(from_d)} vs {defang_domain(return_d)}.", "Email header spoofing", defang_domain(return_d), f"From/Return-Path mismatch: {from_d} vs {return_d}"))
    for m in AUTH_FAIL_RE.finditer(text or ""):
        mech = m.group(1).lower()
        signals.append(Signal(20, f"Email authentication failure indicator detected: {mech}=fail.", "Email auth failure", f"{mech}=fail", m.group(0)))
    return signals


def detect_obfuscation(text: str, urls: list[str]) -> list[Signal]:
    """Detect zero-width chars and non-ASCII/homograph domain obfuscation."""
    signals: list[Signal] = []
    raw_text = text or ""
    for ch, name in ZERO_WIDTH_CHARS.items():
        actual = ch if len(ch) == 1 else (chr(int(ch[2:], 16)) if ch.startswith("\\u") and len(ch) == 6 else "")
        if actual and actual in raw_text:
            signals.append(Signal(20, f"Hidden zero-width character detected ({name}).", "Text obfuscation", name, name))
    for u in urls:
        raw_host = urlparse(u).hostname or ""
        domain = get_domain(u)
        non_ascii = next((c for val in (raw_host, domain, u) for c in val if ord(c) > 127), None)
        if non_ascii:
            disp = defang_domain(domain) if domain else defang_url(u)
            signals.append(Signal(30, f"Mixed-script/non-ASCII lookalike characters detected in domain: {disp}.", "Unicode homograph", disp, raw_host or domain))
    for m in NON_ASCII_DOMAIN_RE.finditer(raw_text):
        tok = m.group(1)
        disp = defang_domain(tok.lower())
        if not any(disp.lower() in (s.indicator or "").lower() for s in signals):
            signals.append(Signal(30, f"Mixed-script/non-ASCII lookalike characters detected in domain: {disp}.", "Unicode homograph", disp, tok))
    return signals


def detect_attachments_and_upi(text: str) -> list[Signal]:
    """Detect dangerous attachment extensions and UPI payment traps."""
    signals: list[Signal] = []
    raw = text or ""
    lowered = raw.lower()
    has_urgency = bool(URGENT_ATTACH_RE.search(lowered))
    for m in DANGEROUS_EXT_RE.finditer(raw):
        ext = m.group(1).lower()
        pts = 25 if has_urgency or ext in DANGEROUS_EXTS else 15
        signals.append(Signal(pts, f"Dangerous attachment/file extension detected: .{ext}.", "Malicious attachment", m.group(0), m.group(0)))
    for m in ARCHIVE_EXT_RE.finditer(raw):
        if has_urgency or "invoice" in lowered or "payment" in lowered:
            signals.append(Signal(15, f"Archive attachment combined with urgency/invoice cue: {m.group(0)}.", "Malicious attachment", m.group(0), m.group(0)))
    for m in UPI_SCAM_RE.finditer(raw):
        signals.append(Signal(25, "UPI refund/collect payment trap pattern detected.", "UPI/payment scam", "UPI scam", m.group(0)))
    return signals


def _score_urls(urls: list[str]) -> list[Signal]:
    """Score URL/domain-based phishing indicators."""
    signals: list[Signal] = []
    for u in urls:
        parsed = urlparse(u)
        domain = get_domain(u)
        scheme = (parsed.scheme or "").lower()
        labels = [p for p in domain.split(".") if p]
        tld = labels[-1] if labels else ""
        registered = registered_like_domain(domain)
        ddisp, udisp = defang_domain(domain), defang_url(u)
        if scheme == "http":
            signals.append(Signal(10, f"Insecure HTTP link detected: {udisp}", "Insecure transport", udisp, udisp))
        if is_ip_literal(domain):
            signals.append(Signal(25, f"IP-literal URL used instead of a domain: {udisp}", "IP-literal URL", ddisp, ddisp))
        if registered in SHORTENER_DOMAINS or domain in SHORTENER_DOMAINS:
            signals.append(Signal(20, f"URL shortener can hide the real destination: {ddisp}", "URL shortener", ddisp, ddisp))
        if tld in SUSPICIOUS_TLDS:
            signals.append(Signal(15, f"Suspicious top-level domain '.{tld}' detected: {ddisp}", "Suspicious TLD", ddisp, ddisp))
        if "xn--" in domain:
            signals.append(Signal(20, f"Punycode domain detected, which can be used for lookalikes: {ddisp}", "Punycode/homograph", ddisp, ddisp))
        if len(labels) >= 4:
            signals.append(Signal(10, f"Excessive subdomains observed: {ddisp}", "Excessive subdomains", ddisp, ddisp))
        if "@" in u:
            signals.append(Signal(15, f"URL contains '@', which can obscure the true destination: {udisp}", "Obfuscated URL", udisp, udisp))
        for lk in detect_lookalike(domain):
            signals.append(Signal(25, f"{lk} in domain {ddisp}", "Typosquatting/lookalike", ddisp, ddisp))
        domain_left = ".".join(labels[:-1]) if len(labels) > 1 else domain
        if DOMAIN_BAIT_RE.search(domain_left) and not any(domain_is_brand_official(domain, b) for b in OFFICIAL_BRAND_DOMAINS):
            signals.append(Signal(10, f"Domain contains credential/verification bait keywords: {ddisp}", "Phishing domain keywords", ddisp, ddisp))
        path_q = (parsed.path or "") + "?" + (parsed.query or "")
        if SENSITIVE_PATH_RE.search(path_q):
            signals.append(Signal(5, f"Sensitive path keywords in URL: {udisp}", "Credential-harvesting path", udisp, udisp))
        if registered in FREE_HOSTING_DOMAINS or domain in FREE_HOSTING_DOMAINS:
            signals.append(Signal(10, f"URL hosted on free/shared hosting: {ddisp}", "Free hosting abuse", ddisp, ddisp))
    return signals


def _score_text(combined: str) -> list[Signal]:
    """Score message text for social-engineering and scam patterns."""
    signals: list[Signal] = []
    for pattern, reason in URGENCY_PATTERNS:
        m = pattern.search(combined)
        if m:
            tactic = "KYC/verification pressure" if "kyc" in reason.lower() else "Account threat" if "suspension" in reason.lower() else "Urgency/social pressure"
            signals.append(Signal(15, reason + ".", tactic, snippet=m.group(0)[:80]))
    for pattern, reason in CREDENTIAL_PATTERNS:
        m = pattern.search(combined)
        if m:
            signals.append(Signal(30, reason + ".", "Credential harvesting", snippet=m.group(0)[:80]))
    for pattern, reason in SCAM_PATTERNS:
        m = pattern.search(combined)
        if m:
            points = 20 if "fee" in reason.lower() or "Job" in reason else 15
            tactic = "Job/internship scam" if "Job" in reason else "QR/payment scam" if "QR" in reason else "Prize/lottery scam" if "Prize" in reason else "Financial scam"
            signals.append(Signal(points, reason + ".", tactic, snippet=m.group(0)[:80]))
    if combined.count("!") >= 3 or len(CAPS_WORD_RE.findall(combined)) >= 4:
        signals.append(Signal(5, "Message uses aggressive formatting (excessive punctuation/capitalization).", "Pressure formatting"))
    return signals


def _sender_kind(sender_l: str) -> str | None:
    """Classify sender context into a coarse risk category."""
    if any(k in sender_l for k in BANK_HINTS):
        return "bank"
    if any(k in sender_l for k in GOV_HINTS):
        return "government"
    if any(k in sender_l for k in EMPLOYER_HINTS):
        return "employer"
    if any(k in sender_l for k in DELIVERY_HINTS):
        return "delivery"
    return None


def _score_context(sender: str, urls: list[str], combined_lower: str) -> list[Signal]:
    """Score sender/context mismatch signals."""
    sender_l = sender.lower()
    signals: list[Signal] = []
    if not sender_l or sender_l == "unknown" or not urls:
        return signals
    kind = _sender_kind(sender_l)
    if not kind:
        return signals
    for u in urls:
        domain = get_domain(u)
        registered = registered_like_domain(domain)
        brand_match = next((b for b in OFFICIAL_BRAND_DOMAINS if b in sender_l or b in combined_lower), None)
        if brand_match and not domain_is_brand_official(domain, brand_match):
            signals.append(Signal(20, f"Sender/context claims '{brand_match}' but link domain {defang_domain(domain)} is not an official domain.", "Context mismatch", defang_domain(domain), defang_domain(domain)))
        elif not brand_match and (registered in FREE_HOSTING_DOMAINS or domain in FREE_HOSTING_DOMAINS or (domain.split(".")[-1] if "." in domain else "") in SUSPICIOUS_TLDS or is_ip_literal(domain)):
            signals.append(Signal(15, f"Sender claims to be {kind} but uses untrusted domain {defang_domain(domain)}.", "Context mismatch", defang_domain(domain), defang_domain(domain)))
    return signals


def _dedupe_signals(signals: list[Signal]) -> list[Signal]:
    """Deduplicate signals by reason, indicator, and points."""
    seen: set[tuple[str, str, int]] = set()
    out: list[Signal] = []
    for s in signals:
        key = (s.reason.lower(), (s.indicator or "").lower(), s.points)
        if key not in seen:
            seen.add(key)
            out.append(s)
    return out


def extract_indicators(text: str, urls: list[str]) -> list[str]:
    """Build a de-duplicated indicator list from URLs and domains."""
    indicators: list[str] = []
    for u in urls:
        indicators.append(f"URL: {defang_url(u)}")
        d = get_domain(u)
        if d:
            indicators.append(f"Domain: {defang_domain(d)}")
    seen: set[str] = set()
    out: list[str] = []
    for i in indicators:
        k = i.lower()
        if k not in seen:
            seen.add(k)
            out.append(i)
    return out


def _build_recommendations(verdict: Verdict, tactics: list[str], sender: str) -> list[str]:
    """Return verdict-specific recommended actions."""
    sender_l = (sender or "").lower()
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
        if any(k in sender_l for k in ("bank", "gov", "delivery", "employer")):
            actions.append("Use the official app or bookmarked website instead of any link provided in the message.")
        return actions
    return [
        "No immediate phishing indicators were detected, but remain cautious with unexpected requests.",
        "Verify sensitive requests through official channels if context changes.",
    ]


build_recommendations = _build_recommendations


def _build_safe_reply(verdict: Verdict, sender: str) -> str | None:
    """Build a non-engaging safe reply template for risky messages."""
    if verdict == "Safe":
        return None
    sender_name = sender.strip() if sender and sender.strip().lower() != "unknown" else "the sender"
    return (
        f"I can't take action using the link or details in this message. "
        f"I will verify this request through an official channel before responding. "
        f"If you are legitimate, please share a reference I can confirm via the official {sender_name} contact method."
    )


build_safe_reply = _build_safe_reply


def _finalize_result(signals: list[Signal], combined: str, urls: list[str], sender: str) -> AnalysisResultDict:
    """Convert scored signals into the API response schema."""
    raw_score = sum(s.points for s in signals)
    tactic_counts: dict[str, int] = {}
    for s in signals:
        if s.tactic:
            tactic_counts[s.tactic] = tactic_counts.get(s.tactic, 0) + 1
    penalty = sum((c - 2) * 3 for c in tactic_counts.values() if c > 2)
    score = max(0, min(100, raw_score - penalty))
    if not signals:
        score = min(score, 5)
    verdict: Verdict = "Safe" if score <= 29 else "Suspicious" if score <= 64 else "High Risk"
    strong = [s for s in signals if s.points >= 20]
    confidence: Confidence = "High" if (len(strong) >= 2 or score >= 75 or score <= 5) else "Medium"
    tactics: list[str] = []
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
    reasons = [s.reason for s in signals] or ["No strong phishing or scam indicators were detected in the provided content."]
    snippets: list[str] = []
    for s in signals:
        snip = WHITESPACE_RE.sub(" ", (s.snippet or s.indicator or "")).strip()[:120]
        if snip and snip.lower() not in {x.lower() for x in snippets}:
            snippets.append(snip)
    return {
        "risk_score": int(score),
        "verdict": verdict,
        "confidence": confidence,
        "extracted_indicators": indicators[:20],
        "reasons": reasons[:12],
        "recommended_actions": _build_recommendations(verdict, tactics, sender),
        "safe_reply_template": _build_safe_reply(verdict, sender),
        "matched_snippets": snippets[:12],
    }


@functools.lru_cache(maxsize=256)
def _analyze_deterministic(text: str, url: str, sender: str) -> AnalysisResultDict:
    """Cached deterministic triage for repeated/preset inputs."""
    text, url, sender = _clamp_text(text, MAX_TEXT_LENGTH), _clamp_text(url, MAX_URL_LENGTH), _clamp_text(sender, MAX_SENDER_LENGTH)
    combined = "\n".join(p for p in (text, url) if p).strip()
    if not combined:
        return {
            "risk_score": 0, "verdict": "Safe", "confidence": "High", "extracted_indicators": [],
            "reasons": ["No content provided for analysis."],
            "recommended_actions": ["Paste a suspicious message or URL to triage."],
            "safe_reply_template": None, "matched_snippets": [],
        }
    urls = _extract_urls(text, url)
    signals: list[Signal] = []
    signals.extend(_score_urls(urls))
    signals.extend(_score_text(combined))
    signals.extend(_score_context(sender, urls, combined.lower()))
    signals.extend(detect_obfuscation(combined, urls))
    signals.extend(detect_email_header_spoofing(text))
    signals.extend(detect_attachments_and_upi(combined))
    return _finalize_result(_dedupe_signals(signals), combined, urls, sender)


def maybe_enrich_with_ai(result: AnalysisResultDict, content: str, sender: str) -> AnalysisResultDict:
    """Optionally enrich reasons with an AI summary when API keys are configured.

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
        f"Sender: {sender or 'Unknown'}\nVerdict: {result['verdict']} (score {result['risk_score']}/100)\n"
        f"Signals: {'; '.join(result['reasons'][:6])}\nContent: {content[:1000]}"
    )
    try:
        import json
        import urllib.request

        if openai_key:
            body = json.dumps({"model": os.getenv("OPENAI_MODEL", "gpt-4o-mini"), "messages": [{"role": "user", "content": prompt}], "temperature": 0.2, "max_tokens": 80}).encode("utf-8")
            req = urllib.request.Request("https://api.openai.com/v1/chat/completions", data=body, headers={"Authorization": f"Bearer {openai_key}", "Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            text = data["choices"][0]["message"]["content"].strip()
        else:
            model = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")
            endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={gemini_key}"
            body = json.dumps({"contents": [{"parts": [{"text": prompt}]}], "generationConfig": {"temperature": 0.2, "maxOutputTokens": 80}}).encode("utf-8")
            req = urllib.request.Request(endpoint, data=body, headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            text = data["candidates"][0]["content"]["parts"][0]["text"].strip()
        if text:
            note = f"AI summary: {WHITESPACE_RE.sub(' ', text).strip()[:240]}"
            reasons = list(result.get("reasons", []))
            if note not in reasons:
                reasons.insert(0, note)
            result["reasons"] = reasons[:12]
    except Exception:
        return result
    return result


def analyze_input(text: str | None, url: str | None, sender: str | None = None) -> dict:
    """Analyze suspicious content and return a structured triage result.

    The deterministic core is memoized for repeated inputs; optional AI
    enrichment is applied only on the returned copy.
    """
    safe_text = _clamp_text(text, MAX_TEXT_LENGTH)
    safe_url = _clamp_text(url, MAX_URL_LENGTH)
    safe_sender = _clamp_text(sender, MAX_SENDER_LENGTH) or "Unknown"
    result = copy.deepcopy(_analyze_deterministic(safe_text, safe_url, safe_sender))
    combined = "\n".join(p for p in (safe_text, safe_url) if p).strip()
    return maybe_enrich_with_ai(result, combined, safe_sender)
