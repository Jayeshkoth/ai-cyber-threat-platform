import joblib

MODEL_PATH = "phishing_model.pkl"

model = joblib.load(MODEL_PATH)

print("Model loaded successfully!")