from fastapi import FastAPI

app = FastAPI()


@app.get("/")
def home():
    return {"message": "AI Cyber Threat Platform API is running"}