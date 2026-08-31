from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dataclasses import asdict
import json
import sys
import os

# Allow Python to find files inside the models folder
sys.path.append(
    os.path.join(os.path.dirname(__file__), "..", "models")
)

from predict import predict_url
from security_analysis import analyze_url
from database.operations import (
    save_scan,
    get_recent_scans,
    get_scan,
    get_statistics,
)
from database.utils import scan_to_dict
from threat_intelligence.checker import check_threat_intelligence


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:5174",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class URLRequest(BaseModel):
    url: str


class AnalyzeRequest(BaseModel):
    input: str
    type: str


@app.get("/")
def home():
    return {
        "message": "AI Cyber Threat Platform API is running"
    }
@app.get("/api/history")
def history(limit: int = 10):
    scans = get_recent_scans(limit)
    return {
        "scans": [scan_to_dict(scan) for scan in scans]
    }
@app.get("/api/statistics")
def statistics():
    return get_statistics()
@app.get("/api/history/{scan_id}")
def scan_details(scan_id: int):
    scan = get_scan(scan_id)

    if scan is None:
        return {
            "error": "Scan not found"
        }

    return scan_to_dict(scan)


@app.post("/predict")
def predict(request: URLRequest):

    result = predict_url(request.url)

    confidence = max(
        result["phishing_probability"],
        result["legitimate_probability"]
    )

    save_scan(
        url=request.url,
        prediction=result["prediction"],
        confidence=confidence,
    )

    return {
        "url": result["url"],
        "prediction": result["prediction"],
        "confidence": confidence,
        "phishing_probability": result["phishing_probability"],
        "legitimate_probability": result["legitimate_probability"]
    }


@app.post("/api/analyze")
def analyze(request: AnalyzeRequest):

    if request.type == "url":

        # ---------------------------------------------
        # 1. ML MODEL ANALYSIS
        # ---------------------------------------------

        ml_result = predict_url(request.input)

        # ---------------------------------------------
        # 2. SECURITY HEURISTIC ANALYSIS
        # ---------------------------------------------

        security_result = analyze_url(request.input)

        # ---------------------------------------------
        # 3. THREAT INTELLIGENCE ANALYSIS
        # ---------------------------------------------

        threat_intel_result = check_threat_intelligence(
            request.input
        )

        # Convert dataclass result into dictionary
        threat_intel_dict = asdict(threat_intel_result)

        # ---------------------------------------------
        # 4. ML RESULT
        # ---------------------------------------------

        if ml_result["prediction"] == "PHISHING":
            threat = "malicious"
            category = "Phishing URL"
        else:
            threat = "safe"
            category = "Legitimate URL"

        confidence = round(
            max(
                ml_result["phishing_probability"],
                ml_result["legitimate_probability"]
            ) * 100,
            2
        )

        # ---------------------------------------------
        # 5. SAVE COMPLETE SCAN TO DATABASE
        # ---------------------------------------------

        save_scan(
            url=request.input,
            prediction=ml_result["prediction"],
            confidence=max(
                ml_result["phishing_probability"],
                ml_result["legitimate_probability"]
            ),
            security_analysis=json.dumps(
                security_result
            ),
            threat_intelligence=json.dumps(
                threat_intel_dict
            ),
        )

        # ---------------------------------------------
        # 6. RETURN COMBINED ANALYSIS
        # ---------------------------------------------

        return {
            "url": request.input,

            # ML result
            "threat": threat,
            "prediction": ml_result["prediction"],
            "confidence": confidence,
            "phishing_probability": ml_result[
                "phishing_probability"
            ],
            "legitimate_probability": ml_result[
                "legitimate_probability"
            ],

            # Security analysis
            "risk_score": security_result["risk_score"],
            "findings": security_result["findings"],

            # Threat intelligence
            "threat_intelligence": {
                "reputation": threat_intel_dict["reputation"],
                "blacklisted": threat_intel_dict["blacklisted"],
                "sources_checked": threat_intel_dict[
                    "sources_checked"
                ],
                "details": threat_intel_dict["details"],
            },

            # General category/message
            "category": category,
            "message": (
                f"The URL was classified as "
                f"{ml_result['prediction']}."
            )
        }

    return {
        "threat": "unknown",
        "risk_score": 0,
        "confidence": 0,
        "category": "unsupported",
        "message": "This input type is not supported yet."
    }