import joblib
import pandas as pd
import os
from url_features import extract_url_features

MODEL_PATH = os.path.join(
    os.path.dirname(__file__),
    "phishing_model.pkl"
)

model_data = joblib.load(MODEL_PATH)

model = model_data["model"]
FEATURES = model_data["features"]

print("Model loaded successfully!")


def predict_url(url):

    extracted = extract_url_features(url)

    X = pd.DataFrame(
        [[extracted[feature] for feature in FEATURES]],
        columns=FEATURES
    )

    prediction = model.predict(X)[0]

    probabilities = model.predict_proba(X)[0]
    confidence = max(probabilities)

    # PhiUSIIL:
    # 1 = LEGITIMATE
    # 0 = PHISHING

    if prediction == 1:
        result = "LEGITIMATE"
    else:
        result = "PHISHING"

    return result, confidence


if __name__ == "__main__":

    test_url = "http://192.168.1.1/login"

    result, confidence = predict_url(test_url)

    print("\nURL:", test_url)
    print("Prediction:", result)
    print("Confidence:", round(confidence * 100, 2), "%")