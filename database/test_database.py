import pytest

from database.operations import (
    save_scan,
    get_recent_scans,
    get_scan,
    get_statistics,
)


def test_save_scan():
    scan = save_scan(
        url="https://example.com",
        prediction="LEGITIMATE",
        confidence=0.95,
    )

    assert scan.id is not None
    assert scan.url == "https://example.com"
    assert scan.prediction == "LEGITIMATE"
    assert scan.confidence == 0.95
    assert scan.timestamp is not None


def test_get_recent_scans():
    save_scan(
        url="https://example.com",
        prediction="LEGITIMATE",
        confidence=0.95,
    )

    scans = get_recent_scans()

    assert len(scans) > 0
    assert all(scan.id is not None for scan in scans)


def test_get_scan():
    scan = save_scan(
        url="https://example.com",
        prediction="LEGITIMATE",
        confidence=0.95,
    )

    found_scan = get_scan(scan.id)

    assert found_scan is not None
    assert found_scan.id == scan.id
    assert found_scan.url == "https://example.com"


def test_get_scan_returns_none_for_invalid_id():
    scan = get_scan(999999999)

    assert scan is None


def test_get_statistics():
    save_scan(
        url="https://example.com",
        prediction="LEGITIMATE",
        confidence=0.95,
    )

    save_scan(
        url="http://suspicious-test-site.com",
        prediction="PHISHING",
        confidence=0.91,
    )

    statistics = get_statistics()

    assert "total_scans" in statistics
    assert "phishing_count" in statistics
    assert "legitimate_count" in statistics

    assert statistics["total_scans"] >= 2
    assert statistics["phishing_count"] >= 1
    assert statistics["legitimate_count"] >= 1


def test_save_scan_with_optional_results():
    scan = save_scan(
        url="https://example.com",
        prediction="LEGITIMATE",
        confidence=0.95,
        security_analysis="No security issues detected.",
        threat_intelligence="No known threats found.",
    )

    assert scan.security_analysis == "No security issues detected."
    assert scan.threat_intelligence == "No known threats found."


def test_save_scan_rejects_invalid_confidence():
    with pytest.raises(ValueError):
        save_scan(
            url="https://example.com",
            prediction="LEGITIMATE",
            confidence=1.5,
        )


def test_save_scan_rejects_empty_url():
    with pytest.raises(ValueError):
        save_scan(
            url="",
            prediction="LEGITIMATE",
            confidence=0.95,
        )


def test_save_scan_rejects_invalid_prediction():
    with pytest.raises(ValueError):
        save_scan(
            url="https://example.com",
            prediction="UNKNOWN",
            confidence=0.95,
        )


def test_get_recent_scans_rejects_invalid_limit():
    with pytest.raises(ValueError):
        get_recent_scans(limit=0)