from attack_indicators import analyze_attack_indicators


def get_indicator_names(url):
    result = analyze_attack_indicators(url)
    return {
        indicator["indicator_name"]
        for indicator in result["indicators"]
    }


def test_credential_theft_indicator():
    url = "https://secure-login-example.xyz/verify/account"

    indicators = get_indicator_names(url)

    assert "Credential Theft / Login Phishing" in indicators


def test_banking_phishing_indicator():
    url = "https://secure-banking-example.xyz/login/payment"

    indicators = get_indicator_names(url)

    assert "Banking / Financial Phishing" in indicators


def test_cryptocurrency_scam_indicator():
    url = "https://crypto-wallet-example.xyz/verify"

    indicators = get_indicator_names(url)

    assert "Cryptocurrency Scam" in indicators


def test_malicious_redirect_indicator():
    url = "https://example.xyz/redirect=https%3A%2F%2Fevil.example"

    indicators = get_indicator_names(url)

    assert "Malicious Redirect" in indicators


def test_suspicious_infrastructure_indicator():
    url = "http://192.168.1.1/login"

    indicators = get_indicator_names(url)

    assert "Suspicious Infrastructure" in indicators


def test_combined_attack_indicators():
    url = "https://secure-wallet-login-example.xyz/verify?redirect=https%3A%2F%2Fevil.example"

    indicators = get_indicator_names(url)

    assert "Credential Theft / Login Phishing" in indicators
    assert "Cryptocurrency Scam" in indicators
    assert "Malicious Redirect" in indicators
    assert "Suspicious Infrastructure" in indicators


def test_legitimate_url_has_no_attack_indicators():
    url = "https://www.google.com"

    indicators = get_indicator_names(url)

    assert indicators == set()


def test_empty_url_has_no_attack_indicators():
    indicators = get_indicator_names("")

    assert indicators == set()