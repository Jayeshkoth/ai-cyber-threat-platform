import pandas as pd
import joblib
import os

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

from url_features import extract_url_features


# --------------------------------------------------
# 1. LOAD DATASET
# --------------------------------------------------

data_path = os.path.join(
    os.path.dirname(__file__),
    "..",
    "data",
    "PhiUSIIL_Phishing_URL_Dataset.csv"
)

df = pd.read_csv(data_path)

print("Dataset loaded.")
print("Shape:", df.shape)


# --------------------------------------------------
# 2. FEATURES
# --------------------------------------------------

FEATURES = [
    "URLLength",
    "DomainLength",
    "IsDomainIP",
    "NoOfSubDomain",
    "HasObfuscation",
    "NoOfObfuscatedChar",
    "ObfuscationRatio",
    "NoOfLettersInURL",
    "LetterRatioInURL",
    "NoOfDegitsInURL",
    "DegitRatioInURL",
    "NoOfEqualsInURL",
    "NoOfQMarkInURL",
    "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL",
    "SpacialCharRatioInURL",
    "IsHTTPS"
]

print("Number of features:", len(FEATURES))


# --------------------------------------------------
# 3. EXTRACT FEATURES FROM URL
# --------------------------------------------------

print("\nExtracting features from URLs...")

feature_rows = []

total = len(df)

for i, url in enumerate(df["URL"]):

    feature_rows.append(
        extract_url_features(str(url))
    )

    # Progress every 10,000 URLs
    if (i + 1) % 10000 == 0:
        print(f"Processed {i + 1}/{total}")


X = pd.DataFrame(feature_rows)

# Make sure feature order is exactly correct
X = X[FEATURES]

y = df["label"]


print("\nFeature extraction complete.")

print("X shape:", X.shape)
print("y shape:", y.shape)


# --------------------------------------------------
# 4. SPLIT DATASET
# --------------------------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

print("\nTraining samples:", len(X_train))
print("Testing samples:", len(X_test))


# --------------------------------------------------
# 5. CREATE MODEL
# --------------------------------------------------

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1
)


# --------------------------------------------------
# 6. TRAIN
# --------------------------------------------------

print("\nTraining model...")

model.fit(X_train, y_train)

print("Training complete.")


# --------------------------------------------------
# 7. PREDICT
# --------------------------------------------------

y_pred = model.predict(X_test)


# --------------------------------------------------
# 8. EVALUATE
# --------------------------------------------------

accuracy = accuracy_score(
    y_test,
    y_pred
)

print("\nAccuracy:", accuracy)

print("\nClassification Report:")

print(
    classification_report(
        y_test,
        y_pred
    )
)


# --------------------------------------------------
# 9. SAVE MODEL
# --------------------------------------------------

joblib.dump(
    {
        "model": model,
        "features": FEATURES
    },
    "phishing_model.pkl"
)

print("\nModel saved as phishing_model.pkl")