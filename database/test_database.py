import json
from datetime import datetime, timedelta, timezone

import pytest

from database.operations import (
    save_scan,
    get_recent_scans,
    get_scan,
    get_statistics,
    get_threat_history,
    get_repeated_urls,
    get_prediction_distribution,
    get_threat_trends,
    get_increased_risk_urls,
    get_threat_statistics,
    get_attack_category_distribution,
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


def test_get_threat_history_empty():
    history = get_threat_history(
        start_time=datetime(2030, 1, 1, tzinfo=timezone.utc),
        end_time=datetime(2030, 1, 2, tzinfo=timezone.utc),
    )

    assert history == []


def test_get_threat_history_filters_by_time():
    old_scan = save_scan(
        url="https://old-example.com",
        prediction="LEGITIMATE",
        confidence=0.95,
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    new_scan = save_scan(
        url="https://new-example.com",
        prediction="PHISHING",
        confidence=0.90,
        timestamp=datetime(2026, 2, 1, tzinfo=timezone.utc),
    )

    history = get_threat_history(
        start_time=datetime(2026, 1, 15, tzinfo=timezone.utc),
        end_time=datetime(2026, 2, 15, tzinfo=timezone.utc),
    )

    assert new_scan.id in [scan.id for scan in history]
    assert old_scan.id not in [scan.id for scan in history]


def test_get_repeated_urls():
    url = "https://repeated-example.com"

    save_scan(
        url=url,
        prediction="PHISHING",
        confidence=0.80,
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    save_scan(
        url=url,
        prediction="PHISHING",
        confidence=0.90,
        timestamp=datetime(2026, 1, 2, tzinfo=timezone.utc),
    )

    repeated = get_repeated_urls()

    result = next(item for item in repeated if item["url"] == url)

    assert result["scan_count"] == 2
    assert result["first_seen"] is not None
    assert result["last_seen"] is not None


def test_get_prediction_distribution():
    save_scan(
        url="https://phishing-example.com",
        prediction="PHISHING",
        confidence=0.90,
    )

    save_scan(
        url="https://legitimate-example.com",
        prediction="LEGITIMATE",
        confidence=0.95,
    )

    distribution = get_prediction_distribution()

    assert distribution["PHISHING"] >= 1
    assert distribution["LEGITIMATE"] >= 1


def test_get_threat_trends():
    save_scan(
        url="https://trend-phishing.com",
        prediction="PHISHING",
        confidence=0.90,
        timestamp=datetime(2026, 3, 1, tzinfo=timezone.utc),
    )

    save_scan(
        url="https://trend-legitimate.com",
        prediction="LEGITIMATE",
        confidence=0.95,
        timestamp=datetime(2026, 3, 1, tzinfo=timezone.utc),
    )

    trends = get_threat_trends(
        start_time=datetime(2026, 3, 1, tzinfo=timezone.utc),
        end_time=datetime(2026, 3, 2, tzinfo=timezone.utc),
    )

    assert len(trends) == 1
    assert trends[0]["PHISHING"] == 1
    assert trends[0]["LEGITIMATE"] == 1


def test_get_increased_risk_urls():
    url = "https://increasing-risk.com"

    save_scan(
        url=url,
        prediction="PHISHING",
        confidence=0.60,
        timestamp=datetime(2026, 4, 1, tzinfo=timezone.utc),
    )

    save_scan(
        url=url,
        prediction="PHISHING",
        confidence=0.90,
        timestamp=datetime(2026, 4, 2, tzinfo=timezone.utc),
    )

    increased = get_increased_risk_urls()

    result = next(item for item in increased if item["url"] == url)

    assert result["first_risk"] == 0.60
    assert result["latest_risk"] == 0.90
    assert result["risk_increase"] == pytest.approx(0.30)


def test_get_threat_statistics_with_time_filter():
    save_scan(
        url="https://period-phishing.com",
        prediction="PHISHING",
        confidence=0.90,
        timestamp=datetime(2026, 5, 1, tzinfo=timezone.utc),
    )

    save_scan(
        url="https://period-legitimate.com",
        prediction="LEGITIMATE",
        confidence=0.95,
        timestamp=datetime(2026, 5, 1, tzinfo=timezone.utc),
    )

    save_scan(
        url="https://outside-period.com",
        prediction="PHISHING",
        confidence=0.80,
        timestamp=datetime(2026, 6, 1, tzinfo=timezone.utc),
    )

    statistics = get_threat_statistics(
        start_time=datetime(2026, 5, 1, tzinfo=timezone.utc),
        end_time=datetime(2026, 5, 2, tzinfo=timezone.utc),
    )

    assert statistics["total_scans"] == 2
    assert statistics["phishing_count"] == 1
    assert statistics["legitimate_count"] == 1


def test_get_attack_category_distribution_multiple_categories():
    start_time = datetime.now(timezone.utc) + timedelta(hours=1)
    end_time = start_time + timedelta(seconds=10)

    save_scan(
        url="https://attack-category-1.example",
        prediction="PHISHING",
        confidence=0.90,
        timestamp=start_time + timedelta(seconds=1),
        security_analysis=json.dumps({
            "attack_prediction": {
                "attack_category": "Credential Theft Test"
            }
        }),
    )

    save_scan(
        url="https://attack-category-2.example",
        prediction="PHISHING",
        confidence=0.85,
        timestamp=start_time + timedelta(seconds=2),
        security_analysis=json.dumps({
            "attack_prediction": {
                "attack_category": "Credential Theft Test"
            }
        }),
    )

    save_scan(
        url="https://attack-category-3.example",
        prediction="PHISHING",
        confidence=0.80,
        timestamp=start_time + timedelta(seconds=3),
        security_analysis=json.dumps({
            "attack_prediction": {
                "attack_category": "Malware Test"
            }
        }),
    )

    distribution = get_attack_category_distribution(
        start_time=start_time,
        end_time=end_time,
    )

    assert distribution == {
        "Credential Theft Test": 2,
        "Malware Test": 1,
    }


def test_get_attack_category_distribution_without_attack_prediction():
    start_time = datetime.now(timezone.utc) + timedelta(hours=3)
    end_time = start_time + timedelta(seconds=10)

    save_scan(
        url="https://without-attack-prediction.example",
        prediction="PHISHING",
        confidence=0.90,
        timestamp=start_time + timedelta(seconds=1),
        security_analysis=json.dumps({
            "security_score": 0.8
        }),
    )

    save_scan(
        url="https://with-attack-prediction.example",
        prediction="PHISHING",
        confidence=0.85,
        timestamp=start_time + timedelta(seconds=2),
        security_analysis=json.dumps({
            "attack_prediction": {
                "attack_category": "Phishing Test"
            }
        }),
    )

    distribution = get_attack_category_distribution(
        start_time=start_time,
        end_time=end_time,
    )

    assert distribution == {
        "Phishing Test": 1,
    }


def test_get_attack_category_distribution_empty_history():
    start_time = datetime(2030, 1, 1, tzinfo=timezone.utc)
    end_time = start_time + timedelta(days=1)

    distribution = get_attack_category_distribution(
        start_time=start_time,
        end_time=end_time,
    )

    assert distribution == {}


def test_get_attack_category_distribution_time_filter():
    start_time = datetime.now(timezone.utc) + timedelta(hours=5)

    save_scan(
        url="https://inside-category-1.example",
        prediction="PHISHING",
        confidence=0.90,
        timestamp=start_time + timedelta(seconds=1),
        security_analysis=json.dumps({
            "attack_prediction": {
                "attack_category": "Inside Range Test"
            }
        }),
    )

    save_scan(
        url="https://inside-category-2.example",
        prediction="PHISHING",
        confidence=0.85,
        timestamp=start_time + timedelta(seconds=2),
        security_analysis=json.dumps({
            "attack_prediction": {
                "attack_category": "Inside Range Test"
            }
        }),
    )

    save_scan(
        url="https://outside-category.example",
        prediction="PHISHING",
        confidence=0.80,
        timestamp=start_time + timedelta(seconds=20),
        security_analysis=json.dumps({
            "attack_prediction": {
                "attack_category": "Outside Range Test"
            }
        }),
    )

    distribution = get_attack_category_distribution(
        start_time=start_time,
        end_time=start_time + timedelta(seconds=10),
    )

    assert distribution == {
        "Inside Range Test": 2,
    }
