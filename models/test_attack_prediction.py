from attack_prediction import predict_attack


def test_legitimate_url():
    result = predict_attack(
        {
            "phishing_probability": 0.02,
            "legitimate_probability": 0.98,
        },
        {
            "risk_score": 0,
            "findings": [],
        },
        {
            "reputation": "clean",
        },
    )

    assert result["attack_category"] == "Benign"
    assert result["attack_likelihood"] == 80
    assert result["severity"] == "Low"


def test_credential_theft():
    result = predict_attack(
        {
            "phishing_probability": 0.98,
            "legitimate_probability": 0.02,
        },
        {
            "risk_score": 65,
            "findings": [
                "URL contains security-sensitive keywords: login, password"
            ],
        },
        {
            "reputation": "malicious",
        },
    )

    assert result["attack_category"] == "Credential Theft"
    assert result["attack_likelihood"] == 75
    assert result["severity"] == "High"


def test_suspicious_infrastructure():
    result = predict_attack(
        {
            "phishing_probability": 0.90,
            "legitimate_probability": 0.10,
        },
        {
            "risk_score": 50,
            "findings": [
                "URL uses an IP address instead of a domain"
            ],
        },
        {
            "reputation": "malicious",
        },
    )

    assert result["attack_category"] == "Suspicious Infrastructure"
    assert result["attack_likelihood"] == 75
    assert result["severity"] == "High"


def test_banking_phishing():
    result = predict_attack(
        {
            "phishing_probability": 0.94,
            "legitimate_probability": 0.06,
        },
        {
            "risk_score": 70,
            "findings": [
                "URL contains security-sensitive keywords: payment, billing, account"
            ],
        },
        {
            "reputation": "malicious",
        },
    )

    assert result["attack_category"] == "Banking Phishing"
    assert result["attack_likelihood"] == 80
    assert result["severity"] == "High"


def test_cryptocurrency_scam():
    result = predict_attack(
        {
            "phishing_probability": 0.91,
            "legitimate_probability": 0.09,
        },
        {
            "risk_score": 60,
            "findings": [
                "URL contains security-sensitive keywords: wallet"
            ],
        },
        {
            "reputation": "malicious",
        },
    )

    assert result["attack_category"] == "Cryptocurrency Scam"
    assert result["attack_likelihood"] == 75
    assert result["severity"] == "High"


def test_malicious_redirect():
    result = predict_attack(
        {
            "phishing_probability": 0.88,
            "legitimate_probability": 0.12,
        },
        {
            "risk_score": 55,
            "findings": [
                "URL contains a redirect-related parameter"
            ],
        },
        {
            "reputation": "malicious",
        },
    )

    assert result["attack_category"] == "Malicious Redirect"
    assert result["attack_likelihood"] == 75
    assert result["severity"] == "High"


def test_generic_phishing():
    result = predict_attack(
        {
            "phishing_probability": 0.93,
            "legitimate_probability": 0.07,
        },
        {
            "risk_score": 45,
            "findings": [],
        },
        {
            "reputation": "malicious",
        },
    )

    assert result["attack_category"] == "Generic Phishing"
    assert result["attack_likelihood"] == 45
    assert result["severity"] == "Medium"