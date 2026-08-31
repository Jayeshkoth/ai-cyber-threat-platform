import pytest

from security_analysis import analyze_url


def test_legitimate_url():
    result = analyze_url("https://www.google.com")

    assert result["risk_score"] == 0
    assert result["findings"] == []


def test_ip_based_url():
    result = analyze_url("http://192.168.1.1")

    assert result["risk_score"] >= 30
    assert any("IP address" in finding for finding in result["findings"])


def test_suspicious_tld():
    result = analyze_url("https://example.xyz")

    assert result["risk_score"] >= 15
    assert any("suspicious TLD" in finding for finding in result["findings"])


def test_excessive_subdomains():
    result = analyze_url(
        "https://a.b.c.example.com"
    )

    assert result["risk_score"] >= 10
    assert any(
        "subdomains" in finding
        for finding in result["findings"]
    )


def test_long_url():
    long_url = "https://example.com/" + ("a" * 101)

    result = analyze_url(long_url)

    assert result["risk_score"] >= 15
    assert any(
        "unusually long" in finding
        for finding in result["findings"]
    )


def test_at_symbol_obfuscation():
    result = analyze_url(
        "https://google.com@example.com"
    )

    assert result["risk_score"] >= 20
    assert any(
        "obfuscation" in finding
        for finding in result["findings"]
    )


def test_encoded_character_obfuscation():
    result = analyze_url(
        "https://example.com/%41/%42"
    )

    assert result["risk_score"] >= 10
    assert any(
        "encoded characters" in finding
        for finding in result["findings"]
    )


def test_redirect_parameter():
    result = analyze_url(
        "https://example.com/login?redirect=https://other.com"
    )

    assert result["risk_score"] >= 10
    assert any(
        "redirect-related" in finding
        for finding in result["findings"]
    )


@pytest.mark.parametrize(
    "keyword",
    [
        "login",
        "payment",
        "verify",
        "account",
    ],
)
def test_security_sensitive_keywords(keyword):
    result = analyze_url(
        f"https://example.com/{keyword}"
    )

    assert result["risk_score"] >= 10
    assert any(
        "security-sensitive keywords" in finding
        for finding in result["findings"]
    )


@pytest.mark.parametrize(
    "url",
    [
        "",
        "   ",
        None,
    ],
)
def test_invalid_or_empty_url(url):
    result = analyze_url(url)

    assert result["risk_score"] == 0
    assert "Invalid or empty URL" in result["findings"]


def test_multiple_findings():
    url = (
        "http://192.168.1.1/"
        + "login/"
        + ("a" * 101)
        + "?redirect=https://example.xyz"
    )

    result = analyze_url(url)

    assert len(result["findings"]) >= 3
    assert result["risk_score"] > 0


def test_risk_score_is_between_0_and_100():
    test_urls = [
        "https://www.google.com",
        "http://192.168.1.1/login",
        "https://example.xyz",
        "https://a.b.c.example.com",
        "https://example.com/" + ("a" * 200),
        "https://google.com@example.com/%41/%42",
    ]

    for url in test_urls:
        result = analyze_url(url)

        assert 0 <= result["risk_score"] <= 100


def test_analysis_is_deterministic():
    url = (
        "https://secure-login.example.xyz/"
        "verify/account?redirect=https://example.com"
    )

    first_result = analyze_url(url)
    second_result = analyze_url(url)

    assert first_result == second_result
