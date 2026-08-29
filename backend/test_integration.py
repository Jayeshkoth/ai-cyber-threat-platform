from fastapi.testclient import TestClient

from backend.main import app
from database.operations import get_recent_scans


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