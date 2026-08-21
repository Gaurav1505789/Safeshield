from datetime import datetime, timezone
from pathlib import Path
import sys
from uuid import uuid4

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, ConfigDict

from analyzer.message_analyzer import analyze_message
from analyzer.url_analyzer import analyze_url
from risk_engine import evaluate_message_risk, message_hash
from database import analyses_collection


# cool
class MessageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message: str = Field(
        ...,
        min_length=1,
        max_length=5000,
        description="User-selected message content to review.",
    )


class MessageAnalysisResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    analysis_id: str
    risk_score: int
    risk_level: str
    category: str
    confidence: int
    confidence_level: str
    reasons: list[str]
    detected_indicators: list[str]
    recommendation: str
    model_prediction: str
    model_confidence: int
    rule_confidence: int


class URLRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str = Field(..., min_length=1, max_length=2048)


class URLAnalysisResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    analysis_id: str
    original_url: str
    normalized_url: str
    risk_score: int
    risk_level: str
    category: str
    verdict: str
    confidence: int
    reasons: list[str]
    detected_indicators: list[str]
    recommendation: str
    model_prediction: str
    model_confidence: int
    rule_confidence: int
    domain_valid: bool


app = FastAPI(
    title="SafeShield Backend",
    version="1.0.0",
    description="User-initiated, explainable message risk analysis for SafeShield.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_origin_regex=r"^chrome-extension://.*$",
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.get("/")
def root() -> dict[str, str]:
    return {
        "service": "SafeShield Backend",
        "status": "ok",
        "health_url": "/health",
        "docs_url": "/docs",
    }


@app.get("/health")
def health_check() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "SafeShield Backend",
        "version": "1.0.0",
    }


@app.post("/analyze/message", response_model=MessageAnalysisResponse)
def analyze_message_endpoint(
    payload: MessageRequest,
) -> MessageAnalysisResponse:

    if not payload.message or not payload.message.strip():
        raise HTTPException(
            status_code=400,
            detail="Message cannot be empty.",
        )

    if len(payload.message.strip()) > 5000:
        raise HTTPException(
            status_code=413,
            detail="Message is too long for analysis.",
        )

    indicator_matches = analyze_message(payload.message)

    analysis = evaluate_message_risk(indicator_matches, payload.message)

    analysis_id = f"SS-{uuid4().hex[:10].upper()}"

    analysis_document = {
        "analysis_id": analysis_id,
        "type": "message",
        "message_hash": message_hash(payload.message),
        "timestamp": datetime.now(timezone.utc),
        "risk_score": analysis.risk_score,
        "risk_level": analysis.risk_level,
        "category": analysis.category,
        "confidence": analysis.confidence,
        "reasons": analysis.reasons,
        "detected_indicators": analysis.detected_indicators,
        "recommendation": analysis.recommendation,
        "model_prediction": analysis.model_prediction,
    }

    try:
        if analyses_collection is not None:
            analyses_collection.insert_one(analysis_document)
    except Exception as error:
        raise HTTPException(
            status_code=503,
            detail="Analysis completed, but the result could not be saved.",
        ) from error

    return MessageAnalysisResponse(
        analysis_id=analysis_id,
        risk_score=analysis.risk_score,
        risk_level=analysis.risk_level,
        category=analysis.category,
        confidence=analysis.confidence,
        confidence_level=analysis.confidence_level,
        reasons=analysis.reasons,
        detected_indicators=analysis.detected_indicators,
        recommendation=analysis.recommendation,
        model_prediction=analysis.model_prediction,
        model_confidence=analysis.model_confidence,
        rule_confidence=analysis.rule_confidence,
    )


@app.post("/analyze/url", response_model=URLAnalysisResponse)
def analyze_url_endpoint(payload: URLRequest) -> URLAnalysisResponse:
    url = payload.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty.")

    analysis = analyze_url(url)
    analysis_id = f"SS-{uuid4().hex[:10].upper()}"
    analysis_document = {
        "analysis_id": analysis_id,
        "type": "url",
        "original_url": url,
        "normalized_url": analysis.normalized_url,
        "timestamp": datetime.now(timezone.utc),
        "risk_score": analysis.risk_score,
        "risk_level": analysis.risk_level,
        "category": analysis.category,
        "verdict": analysis.verdict,
        "confidence": analysis.confidence,
        "reasons": analysis.reasons,
        "detected_indicators": analysis.detected_indicators,
        "recommendation": analysis.recommendation,
        "model_prediction": analysis.model_prediction,
    }
    try:
        if analyses_collection is not None:
            analyses_collection.insert_one(analysis_document)
    except Exception as error:
        raise HTTPException(
            status_code=503,
            detail="Analysis completed, but the result could not be saved.",
        ) from error

    return URLAnalysisResponse(
        analysis_id=analysis_id,
        original_url=url,
        normalized_url=analysis.normalized_url,
        risk_score=analysis.risk_score,
        risk_level=analysis.risk_level,
        category=analysis.category,
        verdict=analysis.verdict,
        confidence=analysis.confidence,
        reasons=analysis.reasons,
        detected_indicators=analysis.detected_indicators,
        recommendation=analysis.recommendation,
        model_prediction=analysis.model_prediction,
        model_confidence=analysis.model_confidence,
        rule_confidence=analysis.rule_confidence,
        domain_valid=analysis.domain_valid,
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8000,
    )