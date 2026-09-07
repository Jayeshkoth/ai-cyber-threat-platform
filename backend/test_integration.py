from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.main import app
from database.operations import get_recent_scans
from threat_intelligence.schemas import ThreatIntelResult


client = TestClient(app)


def test_scan_is_saved_to_database():
    test_url = "https://integration-test-unique.example.com"

    response = client.post(
        "/predict",
        json={"url": test_url},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["url"] == test_url
    assert "prediction" in data
    assert "confidence" in data

    scans = get_recent_scans()

    saved_scan = next(
        (scan for scan in scans if scan.url == test_url),
        None,
    )

    assert saved_scan is not None
    assert saved_scan.prediction == data["prediction"]


def test_analyze_endpoint_returns_threat_intelligence():
    fake_ml_result = {
        "url": "https://example.com",
        "prediction": "LEGITIMATE",
        "phishing_probability": 0.10,
        "legitimate_probability": 0.90,
    }

    fake_security_result = {
        "risk_score": 10,
        "findings": [],
    }

    fake_threat_intelligence = ThreatIntelResult(
        url="https://example.com",
        reputation="clean",
        blacklisted=False,
        sources_checked=[
            "VirusTotal",
            "PhishTank",
        ],
        details=[],
    )

    with patch(
        "backend.main.predict_url",
        return_value=fake_ml_result,
    ), patch(
        "backend.main.analyze_url",
        return_value=fake_security_result,
    ), patch(
        "backend.main.check_threat_intelligence",
        return_value=fake_threat_intelligence,
    ), patch(
        "backend.main.save_scan",
    ):

        response = client.post(
            "/api/analyze",
            json={
                "input": "https://example.com",
                "type": "url",
            },
        )

    assert response.status_code == 200

    data = response.json()

    assert data["url"] == "https://example.com"
    assert data["threat"] == "safe"
    assert data["prediction"] == "LEGITIMATE"

    assert "threat_intelligence" in data

    threat_intel = data["threat_intelligence"]

    assert threat_intel["reputation"] == "clean"
    assert threat_intel["blacklisted"] is False

    assert "VirusTotal" in threat_intel["sources_checked"]
    assert "PhishTank" in threat_intel["sources_checked"]


def test_analyze_endpoint_survives_threat_intelligence_provider_failure():
    fake_ml_result = {
        "url": "https://example.com",
        "prediction": "LEGITIMATE",
        "phishing_probability": 0.10,
        "legitimate_probability": 0.90,
    }

    fake_security_result = {
        "risk_score": 10,
        "findings": [],
    }

    fake_threat_intelligence = ThreatIntelResult(
        url="https://example.com",
        reputation="unknown",
        blacklisted=False,
        sources_checked=[
            "VirusTotal",
            "PhishTank",
        ],
        details=[
            {
                "source": "VirusTotal",
                "status": "error",
                "malicious": None,
                "details": "VirusTotal unavailable",
            },
            {
                "source": "PhishTank",
                "status": "error",
                "malicious": None,
                "details": "PhishTank unavailable",
            },
        ],
    )

    with patch(
        "backend.main.predict_url",
        return_value=fake_ml_result,
    ), patch(
        "backend.main.analyze_url",
        return_value=fake_security_result,
    ), patch(
        "backend.main.check_threat_intelligence",
        return_value=fake_threat_intelligence,
    ), patch(
        "backend.main.save_scan",
    ):

        response = client.post(
            "/api/analyze",
            json={
                "input": "https://example.com",
                "type": "url",
            },
        )

    assert response.status_code == 200

    data = response.json()

    assert data["url"] == "https://example.com"
    assert data["threat"] == "safe"

    threat_intel = data["threat_intelligence"]

    assert threat_intel["reputation"] == "unknown"
    assert threat_intel["blacklisted"] is False

    assert "VirusTotal" in threat_intel["sources_checked"]
    assert "PhishTank" in threat_intel["sources_checked"]

    assert len(threat_intel["details"]) == 2

    assert threat_intel["details"][0]["status"] == "error"
    assert threat_intel["details"][1]["status"] == "error"