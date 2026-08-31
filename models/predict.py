import joblib
import pandas as pd
import os

from models.url_features import extract_url_features


# --------------------------------------------------
# MODEL PATH
# --------------------------------------------------

MODEL_PATH = os.path.join(
    os.path.dirname(__file__),
    "phishing_model.pkl"
)


# --------------------------------------------------
# LOAD MODEL
# --------------------------------------------------

model_data = joblib.load(MODEL_PATH)

model = model_data["model"]
FEATURES = model_data["features"]

print("Model loaded successfully!")


# --------------------------------------------------
# PREDICT URL
# --------------------------------------------------

def predict_url(url):

    # Extract URL features
    extracted = extract_url_features(url)

    # Create DataFrame in exact training order
    X = pd.DataFrame(
        [[extracted[feature] for feature in FEATURES]],
        columns=FEATURES
    )

    # Prediction
    prediction = model.predict(X)[0]

    # Probabilities
    probabilities = model.predict_proba(X)[0]

    # PhiUSIIL:
    # 0 = PHISHING
    # 1 = LEGITIMATE

    phishing_probability = probabilities[
        list(model.classes_).index(0)
    ]

    legitimate_probability = probabilities[
        list(model.classes_).index(1)
    ]

    # Final result
    if prediction == 1:
        result = "LEGITIMATE"
    else:
        result = "PHISHING"

    return {
        "url": url,
        "prediction": result,
        "phishing_probability": float(phishing_probability),
        "legitimate_probability": float(legitimate_probability)
    }


# --------------------------------------------------
# TEST
# --------------------------------------------------

if __name__ == "__main__":

    test_urls = [
        "https://www.google.com",
        "https://github.com",
        "http://192.168.1.1/login",
        "http://www.shprakserf.gq"
    ]

    for url in test_urls:

        result = predict_url(url)

        print("\n" + "=" * 60)
        print("URL:", result["url"])
        print("Prediction:", result["prediction"])
        print(
            "Phishing probability:",
            round(result["phishing_probability"] * 100, 2),
            "%"
        )
        print(
            "Legitimate probability:",
            round(result["legitimate_probability"] * 100, 2),
            "%"
        )