import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score


# 1. Load dataset
data_path = "../data/PhiUSIIL_Phishing_URL_Dataset.csv"
df = pd.read_csv(data_path)

print("Dataset loaded.")
print("Shape:", df.shape)


# 2. Features that can be extracted directly from a URL
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

X = df[FEATURES]
y = df["label"]

print("Number of features:", X.shape[1])


# 3. Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

print("Training samples:", len(X_train))
print("Testing samples:", len(X_test))


# 4. Create model
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1
)


# 5. Train
print("\nTraining model...")
model.fit(X_train, y_train)

print("Training complete.")


# 6. Predict
y_pred = model.predict(X_test)


# 7. Evaluate
accuracy = accuracy_score(y_test, y_pred)

print("\nAccuracy:", accuracy)

print("\nClassification Report:")
print(classification_report(y_test, y_pred))


# 8. Save model + feature list
joblib.dump(
    {
        "model": model,
        "features": FEATURES
    },
    "phishing_model.pkl"
)

print("\nModel saved as phishing_model.pkl")