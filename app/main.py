"""FastAPI app for PhishGuard AI."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from .analyzer import MAX_SENDER_LENGTH, MAX_TEXT_LENGTH, MAX_URL_LENGTH, analyze_input

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


class AnalyzeRequest(BaseModel):
    text: Optional[str] = Field(default="", max_length=MAX_TEXT_LENGTH, description="Suspicious message text")
    url: Optional[str] = Field(default="", max_length=MAX_URL_LENGTH, description="Standalone suspicious URL")
    sender: Optional[str] = Field(default="Unknown", max_length=MAX_SENDER_LENGTH, description="Sender context")

    @field_validator("text", "url", "sender", mode="before")
    @classmethod
    def coerce_str(cls, v):
        if v is None:
            return ""
        if isinstance(v, str):
            return v
        raise ValueError("must be a string")


class AnalyzeResponse(BaseModel):
    risk_score: int = Field(ge=0, le=100)
    verdict: str
    confidence: str
    extracted_indicators: list[str]
    reasons: list[str]
    recommended_actions: list[str]
    safe_reply_template: Optional[str] = None
    matched_snippets: list[str] = Field(default_factory=list)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/analyze", response_model=AnalyzeResponse)
def analyze(payload: AnalyzeRequest):
    text = (payload.text or "").strip()
    url = (payload.url or "").strip()
    sender = (payload.sender or "Unknown").strip() or "Unknown"

    if not text and not url:
        raise HTTPException(status_code=400, detail="Provide at least a message text or a URL to analyze.")

    if len(text) > MAX_TEXT_LENGTH or len(url) > MAX_URL_LENGTH or len(sender) > MAX_SENDER_LENGTH:
        raise HTTPException(status_code=400, detail="Input exceeds maximum allowed length.")

    try:
        result = analyze_input(text=text, url=url, sender=sender)
    except Exception as exc:
        # Deterministic engine should not fail; return safe fallback.
        return JSONResponse(
            status_code=200,
            content={
                "risk_score": 50,
                "verdict": "Suspicious",
                "confidence": "Medium",
                "extracted_indicators": [],
                "reasons": ["Analysis encountered an unexpected error; treat content cautiously."],
                "recommended_actions": [
                    "Do not click links or share sensitive information.",
                    "Verify the message through an official channel.",
                ],
                "safe_reply_template": "I will verify this request through an official channel before responding.",
                "matched_snippets": [],
            },
        )

    return result


if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
def index():
    index_path = STATIC_DIR / "index.html"
    if not index_path.exists():
        raise HTTPException(status_code=404, detail="Frontend not found")
    return FileResponse(str(index_path))
