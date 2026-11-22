# PhishGuard AI — Personal Cybersecurity Dashboard

**Vertical:** Defence and Security  
A lightweight, stateless FastAPI + vanilla JS dashboard for phishing/scam triage, QR payload checks, password hygiene, cyber awareness, and local scan history. Designed for fast Vercel/Cloud Run deployment.

## Modules
1. **Phishing & Scam Triage** — Paste suspicious text/URL/sender context, use presets, get risk score (0-100), verdict (Safe/Suspicious/High Risk), matched evidence, indicators, reasons, recommendations, safe reply, Copy Report, Download JSON. `Ctrl+Enter` analyzes.
2. **QR Scam Scanner** — Upload QR image (client-side `BarcodeDetector` when supported) or paste decoded QR text/URL; 1-click suspicious demo; decoded payload analyzed via `/api/analyze`. URLs are never auto-opened; safety warning shown.
3. **Password Checker** — 100% client-side strength analysis (length, variety, repeats, sequences, common weak passwords). Weak/Medium/Strong meter + tips. Passwords never transmitted or stored.
4. **Cyber Academy** — 4-question interactive quiz (phishing, OTP, UPI, password safety) with instant explanations and score badge.
5. **Security History** — Opt-in consent toggle; scan summaries stored in browser `localStorage` (stateless hosting friendly). Risk filter + Clear History.

## Multilingual UI
Language selector in header: **English, हिंदी, ಕನ್ನಡ**. Translates navigation labels, headings, verdict labels, and safety recommendations.

## Security Safeguards
- **SSRF prevention:** submitted URLs are parsed/defanged only; never fetched by backend.
- **XSS prevention:** frontend renders dynamic data with DOM APIs (`textContent`/`createElement`), not raw HTML injection.
- **Zero password transmission:** Password Checker runs entirely in browser JS; no network/storage.
- **Local-only QR decoding:** QR images decoded in browser via `BarcodeDetector`; fallback is manual paste. No remote QR decode service.
- **Stateless history:** scan summaries stored only in `localStorage` after explicit opt-in.

## API
- `GET /health` → `{"status":"ok"}`
- `POST /api/analyze` body: `{"text":"","url":"","sender":"Unknown"}`  
  returns: `risk_score`, `verdict`, `confidence`, `extracted_indicators`, `reasons`, `recommended_actions`, `safe_reply_template`, `matched_snippets`.

## Local Run
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload
# http://localhost:8080
```

## Tests
```bash
pip install -r requirements.txt pytest
pytest -v
```

## Vercel Deployment
- Python pinned by `.python-version` (`3.12`).
- Static files resolved in `app/main.py` via `Path(__file__).resolve().parent.parent / "static"`.
- `.vercelignore` excludes `.venv/`, `__pycache__/`, `.pytest_cache/`, `tests/`.
- `vercel.json` routes requests to FastAPI app.

```bash
npm i -g vercel
vercel login
vercel        # preview
vercel --prod # production
```

## Cloud Run
```bash
docker build -t phishguard-ai .
docker run --rm -p 8080:8080 -e PORT=8080 phishguard-ai
```

## Repo Constraints
Minimal deps: `fastapi`, `uvicorn`, `pydantic`. No heavy image/DB dependencies. Keep repo < 500 KB.
