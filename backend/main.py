from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dataclasses import asdict
from datetime import datetime
from typing import Optional
import json
import sys
import os

# Allow Python to find files inside the models folder
sys.path.append(
    os.path.join(os.path.dirname(__file__), "..", "models")
)

from predict import predict_url
from security_analysis import analyze_url
from attack_prediction import predict_attack
from backend.trusted_domains import is_trusted_domain

from database.operations import (
    save_scan,
    get_recent_scans,
    get_scan,
    get_statistics,
    get_threat_history,
    get_repeated_urls,
    get_threat_trends,
    get_increased_risk_urls,
    get_attack_category_distribution,
)
from database.utils import scan_to_dict
from threat_intelligence.checker import check_threat_intelligence
from backend.alerts import generate_alert


app = FastAPI()


# --------------------------------------------------
# CORS CONFIGURATION
# --------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:5174",
        "http://localhost:5175",
        "http://localhost:5176",
        "http://localhost:5177",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174",
        "http://127.0.0.1:5175",
        "http://127.0.0.1:5176",
        "http://127.0.0.1:5177",
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


@app.get("/api/threat-history")
def threat_history():
    return {
        "history": get_threat_history()
    }
@app.get("/api/threat-trends")
def threat_trends(
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
):
    return {
        "trends": get_threat_trends(
            start_time=start_time,
            end_time=end_time,
        )
    }


@app.get("/api/attack-category-distribution")
def attack_category_distribution():
    return get_attack_category_distribution()
@app.get("/api/repeated-urls")
def repeated_urls():
    return {
        "repeated_urls": get_repeated_urls()
    }
@app.get("/api/increased-risk-urls")
def increased_risk_urls():
    return {
        "increased_risk_urls": get_increased_risk_urls()
    }
@app.get("/api/alerts")
def alerts():
    scans = get_recent_scans(limit=100)

    results = []

    for scan in scans:
        security_analysis = scan.security_analysis

        if not security_analysis:
            continue

        try:
            data = json.loads(security_analysis)
        except (TypeError, json.JSONDecodeError):
            continue

        alert = data.get("alert")

        if alert and alert.get("alert"):
            results.append({
                "scan_id": scan.id,
                "url": scan.url,
                "timestamp": scan.timestamp,
                "severity": alert.get("severity"),
                "risk_score": alert.get("risk_score"),
                "prediction": alert.get("prediction"),
                "message": alert.get("message"),
            })

    return {"alerts": results}


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

        if is_trusted_domain(request.input):
            ml_result["prediction"] = "LEGITIMATE"
            ml_result["phishing_probability"] = 0.0
            ml_result["legitimate_probability"] = 1.0
            ml_result["confidence"] = 100.0

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
        # 4. ATTACK PREDICTION / THREAT INFERENCE
        # ---------------------------------------------

        attack_prediction_result = predict_attack(
            ml_result,
            security_result,
            threat_intel_dict
        )
        # ---------------------------------------------
        # 4.1 ALERT GENERATION
        # ---------------------------------------------

        alert_result = generate_alert({
    "risk_score": security_result["risk_score"],
    "prediction": ml_result["prediction"],
    "findings": security_result["findings"]
})

        # ---------------------------------------------
        # 5. GENERAL THREAT STATUS
        # ---------------------------------------------

        if (
             ml_result["prediction"] == "PHISHING"
          or any(
                 "impersonate" in finding.lower()
            for finding in security_result["findings"]
          )
          ):
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
        # 6. SAVE COMPLETE SCAN TO DATABASE
        # ---------------------------------------------

        # Keep existing database structure intact.
        # Add attack prediction information to the
        # existing security analysis JSON.
        security_analysis_to_save = {
            **security_result,
            "attack_prediction": attack_prediction_result,
            "alert": alert_result
        }

        save_scan(
            url=request.input,
            prediction=ml_result["prediction"],
            confidence=max(
                ml_result["phishing_probability"],
                ml_result["legitimate_probability"]
            ),
            security_analysis=json.dumps(
                security_analysis_to_save
            ),
            threat_intelligence=json.dumps(
                threat_intel_dict
            ),
        )

        # ---------------------------------------------
        # 7. RETURN COMPLETE COMBINED ANALYSIS
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

            # NEW: Attack prediction
            "attack_prediction": {
                "attack_category": attack_prediction_result[
                    "attack_category"
                ],
                "attack_likelihood": attack_prediction_result[
                    "attack_likelihood"
                ],
                "severity": attack_prediction_result[
                    "severity"
                ],
                "evidence": attack_prediction_result[
                    "evidence"
                ],
            },
            # Alert status
            "alert": alert_result,

            # General category/message
            "category": category,
            "message": (
                  "The URL was classified as PHISHING."
                  if threat == "malicious"
                  else "The URL was classified as LEGITIMATE."
                 )
        }

    return {
        "threat": "unknown",
        "risk_score": 0,
        "confidence": 0,
        "category": "unsupported",
        "message": "This input type is not supported yet."
    }