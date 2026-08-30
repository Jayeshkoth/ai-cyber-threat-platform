from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import sys
import os

# Allow Python to find files inside the models folder
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "models"))

from predict import predict_url


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


@app.get("/")
def home():
    return {"message": "AI Cyber Threat Platform API is running"}


@app.post("/predict")
def predict(request: URLRequest):
    result, confidence = predict_url(request.url)

    return {
        "url": request.url,
        "prediction": result,
        "confidence": round(confidence * 100, 2)
    }

class AnalyzeRequest(BaseModel):
    input: str
    type: str


@app.post("/api/analyze")
def analyze(request: AnalyzeRequest):

    if request.type == "url":

        result, confidence = predict_url(request.input)

        if result == "PHISHING":
            threat = "malicious"
            risk_score = round(confidence * 100, 2)
            category = "Phishing URL"
        else:
            threat = "safe"
            risk_score = round((1 - confidence) * 100, 2)
            category = "Legitimate URL"

        return {
            "threat": threat,
            "risk_score": risk_score,
            "confidence": round(confidence * 100, 2),
            "category": category,
            "message": f"The URL was classified as {result}."
        }

    return {
        "threat": "unknown",
        "risk_score": 0,
        "confidence": 0,
        "category": "unsupported",
        "message": "This input type is not supported yet."
    }