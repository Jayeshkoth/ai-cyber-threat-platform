from unittest.mock import patch

from threat_intelligence.checker import check_threat_intelligence


def test_legitimate_url():
    fake_virustotal = {
        "source": "VirusTotal",
        "status": "success",
        "malicious": False,
        "details": {
            "malicious": 0,
            "suspicious": 0
        }
    }

    fake_phishtank = {
        "source": "PhishTank",
        "status": "success",
        "malicious": False,
        "details": {
            "in_database": False,
            "verified": False,
            "valid": False,
            "phish_id": None
        }
    }

    with patch(
        "threat_intelligence.checker.virustotal.check_url",
        return_value=fake_virustotal
    ), patch(
        "threat_intelligence.checker.phishtank.check_url",
        return_value=fake_phishtank
    ):

        result = check_threat_intelligence("https://example.com")

    assert result.url == "https://example.com"
    assert result.reputation == "clean"
    assert result.blacklisted is False
    assert "VirusTotal" in result.sources_checked
    assert "PhishTank" in result.sources_checked


def test_result_structure():
    fake_virustotal = {
        "source": "VirusTotal",
        "status": "success",
        "malicious": False,
        "details": {}
    }

    fake_phishtank = {
        "source": "PhishTank",
        "status": "success",
        "malicious": False,
        "details": {}
    }

    with patch(
        "threat_intelligence.checker.virustotal.check_url",
        return_value=fake_virustotal
    ), patch(
        "threat_intelligence.checker.phishtank.check_url",
        return_value=fake_phishtank
    ):

        result = check_threat_intelligence("https://example.com")

    assert isinstance(result.url, str)
    assert isinstance(result.reputation, str)
    assert isinstance(result.blacklisted, bool)
    assert isinstance(result.sources_checked, list)
    assert isinstance(result.details, list)


def test_virustotal_failure_does_not_mark_url_malicious():
    fake_virustotal = {
        "source": "VirusTotal",
        "status": "error",
        "malicious": None,
        "details": "Request timed out"
    }

    fake_phishtank = {
        "source": "PhishTank",
        "status": "success",
        "malicious": False,
        "details": {
            "in_database": False
        }
    }

    with patch(
        "threat_intelligence.checker.virustotal.check_url",
        return_value=fake_virustotal
    ), patch(
        "threat_intelligence.checker.phishtank.check_url",
        return_value=fake_phishtank
    ):

        result = check_threat_intelligence("https://example.com")

    assert result.reputation == "clean"
    assert result.blacklisted is False


def test_phishtank_failure_does_not_crash_checker():
    fake_virustotal = {
        "source": "VirusTotal",
        "status": "success",
        "malicious": False,
        "details": {}
    }

    fake_phishtank = {
        "source": "PhishTank",
        "status": "error",
        "malicious": None,
        "details": "403 Forbidden"
    }

    with patch(
        "threat_intelligence.checker.virustotal.check_url",
        return_value=fake_virustotal
    ), patch(
        "threat_intelligence.checker.phishtank.check_url",
        return_value=fake_phishtank
    ):

        result = check_threat_intelligence("https://example.com")

    assert result.reputation == "clean"
    assert result.blacklisted is False


def test_malicious_provider_marks_url_malicious():
    fake_virustotal = {
        "source": "VirusTotal",
        "status": "success",
        "malicious": True,
        "details": {
            "malicious": 5,
            "suspicious": 2
        }
    }

    fake_phishtank = {
        "source": "PhishTank",
        "status": "success",
        "malicious": False,
        "details": {}
    }

    with patch(
        "threat_intelligence.checker.virustotal.check_url",
        return_value=fake_virustotal
    ), patch(
        "threat_intelligence.checker.phishtank.check_url",
        return_value=fake_phishtank
    ):

        result = check_threat_intelligence("https://example.com")

    assert result.reputation == "malicious"
    assert result.blacklisted is True


def test_all_providers_unknown_results_in_unknown_reputation():
    fake_virustotal = {
        "source": "VirusTotal",
        "status": "not_configured",
        "malicious": None,
        "details": "API key missing"
    }

    fake_phishtank = {
        "source": "PhishTank",
        "status": "error",
        "malicious": None,
        "details": "403 Forbidden"
    }

    with patch(
        "threat_intelligence.checker.virustotal.check_url",
        return_value=fake_virustotal
    ), patch(
        "threat_intelligence.checker.phishtank.check_url",
        return_value=fake_phishtank
    ):

        result = check_threat_intelligence("https://example.com")

    assert result.reputation == "unknown"
    assert result.blacklisted is False


def test_provider_exception_does_not_crash_checker():
    fake_phishtank = {
        "source": "PhishTank",
        "status": "success",
        "malicious": False,
        "details": {
            "in_database": False
        }
    }

    with patch(
        "threat_intelligence.checker.virustotal.check_url",
        side_effect=Exception("VirusTotal connection failed")
    ), patch(
        "threat_intelligence.checker.phishtank.check_url",
        return_value=fake_phishtank
    ):

        result = check_threat_intelligence("https://example.com")

    assert result.url == "https://example.com"
    assert result.reputation == "clean"
    assert result.blacklisted is False