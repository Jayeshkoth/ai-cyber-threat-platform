from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import sys
import os

# Allow Python to find files inside the models folder
sys.path.append(
    os.path.join(os.path.dirname(__file__), "..", "models")
)

from predict import predict_url
from security_analysis import analyze_url
from database.operations import save_scan


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
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


@app.post("/predict")
def predict(request: URLRequest):

    result = predict_url(request.url)

    save_scan(
        url=request.url,
        prediction=result["prediction"],
        confidence=max(
            result["phishing_probability"],
            result["legitimate_probability"]
        ),
    )

    return {
        "url": result["url"],
        "prediction": result["prediction"],
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
        # 3. ML RESULT
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
        # 4. RETURN COMBINED ANALYSIS
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