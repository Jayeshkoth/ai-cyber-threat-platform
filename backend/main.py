from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import sys
import os

# Allow Python to find files inside the models folder
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "models"))

from predict import predict_url
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


@app.get("/")
def home():
    return {"message": "AI Cyber Threat Platform API is running"}


@app.post("/predict")
def predict(request: URLRequest):
    result, confidence = predict_url(request.url)

    save_scan(
        url=request.url,
        prediction=result,
        confidence=confidence,
    )

    return {
        "url": request.url,
        "prediction": result,
        "confidence": round(confidence * 100, 2)
    }