import os
import sys

# Ensure project root is importable when running tests from different cwd.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.analyzer import analyze_input, defang_url


def test_high_risk_bank_kyc_otp_scam():
    result = analyze_input(
        text=(
            "URGENT: Your account will be suspended in 24 hours due to incomplete KYC. "
            "Verify now and share your OTP and PIN immediately at http://bank-secure-verify.xyz/login"
        ),
        url="",
        sender="Bank",
    )
    assert result["verdict"] == "High Risk"
    assert result["risk_score"] >= 65
    assert any("OTP" in r or "Credential" in r for r in result["reasons"])
    assert result["safe_reply_template"]


def test_lookalike_domain_detected_as_high_risk():
    result = analyze_input(
        text="Please login to your account",
        url="hxxp://sbi-kyc-verify[.]xyz/login",
        sender="Bank",
    )
    assert result["verdict"] == "High Risk"
    assert result["risk_score"] >= 65
    indicators = " ".join(result["extracted_indicators"]).lower()
    reasons = " ".join(result["reasons"]).lower()
    assert "sbi" in indicators or "sbi" in reasons
    assert "hxxp://" in " ".join(result["extracted_indicators"]).lower() or "[.]" in " ".join(result["extracted_indicators"])


def test_credential_otp_request_is_flagged():
    result = analyze_input(
        text="Your package is on hold. Confirm delivery by sharing the OTP sent to your phone.",
        url="",
        sender="Delivery",
    )
    assert result["risk_score"] >= 30
    assert any("otp" in r.lower() or "credential" in r.lower() for r in result["reasons"])


def test_suspicious_urgency_and_fee_scam():
    result = analyze_input(
        text=(
            "Congratulations! You are selected for a remote internship. "
            "Pay a refundable registration fee within 2 hours to secure your slot. Act now!"
        ),
        url="",
        sender="Employer",
    )
    assert result["verdict"] in {"Suspicious", "High Risk"}
    assert result["risk_score"] >= 30
    joined = " ".join(result["reasons"]).lower()
    assert "fee" in joined or "urgency" in joined or "pressure" in joined


def test_safe_benign_input():
    result = analyze_input(
        text="Hi team, reminder that our college project meeting is tomorrow at 10:00 AM in Lab 3. Please bring your slides.",
        url="",
        sender="Colleague",
    )
    assert result["verdict"] == "Safe"
    assert result["risk_score"] <= 29
    assert result["safe_reply_template"] is None


def test_defang_url():
    assert defang_url("https://example.com/path") == "hxxps://example[.]com/path"
    assert defang_url("http://evil.xyz") == "hxxp://evil[.]xyz"


def test_no_empty_submission_defaults():
    result = analyze_input(text="", url="", sender="Unknown")
    assert result["verdict"] == "Safe"
    assert result["risk_score"] == 0


def test_unicode_homograph_domain_detected():
    # Cyrillic 'а' (U+0430) in paypal
    result = analyze_input(text="Login now", url="https://p\u0430ypal.com/login", sender="Unknown")
    assert result["risk_score"] >= 30
    joined = " ".join(result["reasons"]).lower() + " " + " ".join(result["extracted_indicators"]).lower()
    assert "homograph" in joined or "non-ascii" in joined or "mixed-script" in joined
    assert "matched_snippets" in result


def test_zero_width_obfuscation_detected():
    text = "Please verify your account\u200b immediately and share OTP"
    result = analyze_input(text=text, url="", sender="Bank")
    joined = " ".join(result["reasons"]).lower()
    assert "zero-width" in joined or "obfuscation" in joined
    assert any("zero width" in s.lower() or "u+200b" in s.lower() for s in result.get("matched_snippets", []))


def test_email_header_spoofing_from_reply_to():
    raw = """From: support@trustedbank.com
Reply-To: attacker@evil.xyz
Subject: Urgent account verification

Please verify your account immediately."""
    result = analyze_input(text=raw, url="", sender="Bank")
    joined = " ".join(result["reasons"]).lower()
    assert "reply-to" in joined or "mismatch" in joined or "spoof" in joined
    assert result["risk_score"] >= 30


def test_email_auth_failure_detected():
    raw = """From: alerts@bank.com
Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail
Subject: Verify now"""
    result = analyze_input(text=raw, url="", sender="Bank")
    joined = " ".join(result["reasons"]).lower()
    assert "spf=fail" in joined or "dkim=fail" in joined or "dmarc=fail" in joined


def test_apk_attachment_and_upi_scam_detected():
    result = analyze_input(
        text="Your invoice is attached as invoice.apk. To receive refund approve the UPI collect request and enter your UPI PIN to receive money.",
        url="",
        sender="Unknown",
    )
    joined = " ".join(result["reasons"]).lower()
    assert "apk" in joined or "attachment" in joined
    assert "upi" in joined
    assert result["risk_score"] >= 50
    assert any("apk" in s.lower() or "upi" in s.lower() for s in result.get("matched_snippets", []))
