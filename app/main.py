"""FastAPI application for PhishGuard AI."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from .analyzer import MAX_SENDER_LENGTH, MAX_TEXT_LENGTH, MAX_URL_LENGTH, AnalysisResultDict, analyze_input

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(title="PhishGuard AI", version="1.0.0", docs_url="/docs", redoc_url=None)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_cache_headers(request: Request, call_next: Any) -> Response:
    """Add cache headers for static assets; keep API responses uncached."""
    response: Response = await call_next(request)
    path = request.url.path
    if path.startswith("/static/"):
        response.headers["Cache-Control"] = "public, max-age=3600, immutable"
    elif path == "/api/analyze":
        response.headers["Cache-Control"] = "no-store"
    return response


class AnalyzeRequest(BaseModel):
    """Request payload for phishing/scam triage."""

    text: str | None = Field(default="", max_length=MAX_TEXT_LENGTH, description="Suspicious message text")
    url: str | None = Field(default="", max_length=MAX_URL_LENGTH, description="Standalone suspicious URL")
    sender: str | None = Field(default="Unknown", max_length=MAX_SENDER_LENGTH, description="Sender context")

    @field_validator("text", "url", "sender", mode="before")
    @classmethod
    def coerce_str(cls, v: Any) -> str:
        """Coerce null values to empty strings and reject non-strings."""
        if v is None:
            return ""
        if isinstance(v, str):
            return v
        raise ValueError("must be a string")


class AnalyzeResponse(BaseModel):
    """Structured triage response."""

    risk_score: int = Field(ge=0, le=100)
    verdict: str
    confidence: str
    extracted_indicators: list[str]
    reasons: list[str]
    recommended_actions: list[str]
    safe_reply_template: str | None = None
    matched_snippets: list[str] = Field(default_factory=list)


@app.get("/health")
def health() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "ok"}


def _fallback_response() -> dict[str, Any]:
    """Safe fallback response when analysis unexpectedly fails."""
    return {
        "risk_score": 50, "verdict": "Suspicious", "confidence": "Medium",
        "extracted_indicators": [], "reasons": ["Analysis encountered an unexpected error; treat content cautiously."],
        "recommended_actions": ["Do not click links or share sensitive information.", "Verify the message through an official channel."],
        "safe_reply_template": "I will verify this request through an official channel before responding.",
        "matched_snippets": [],
    }


@app.post("/api/analyze", response_model=AnalyzeResponse)
def analyze(payload: AnalyzeRequest) -> AnalysisResultDict | JSONResponse:
    """Analyze suspicious text/URL and return structured triage."""
    text = (payload.text or "").strip()
    url = (payload.url or "").strip()
    sender = (payload.sender or "Unknown").strip() or "Unknown"
    if not text and not url:
        raise HTTPException(status_code=400, detail="Provide at least a message text or a URL to analyze.")
    if len(text) > MAX_TEXT_LENGTH or len(url) > MAX_URL_LENGTH or len(sender) > MAX_SENDER_LENGTH:
        raise HTTPException(status_code=400, detail="Input exceeds maximum allowed length.")
    try:
        return analyze_input(text=text, url=url, sender=sender)
    except Exception:
        return JSONResponse(status_code=200, content=_fallback_response())


if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
def index() -> FileResponse:
    """Serve the frontend SPA."""
    index_path = STATIC_DIR / "index.html"
    if not index_path.exists():
        raise HTTPException(status_code=404, detail="Frontend not found")
    return FileResponse(str(index_path))
