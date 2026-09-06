from urllib.parse import urlparse

from models.security_analysis import analyze_url


CREDENTIAL_KEYWORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "password",
    "confirm",
}

FINANCIAL_KEYWORDS = {
    "payment",
    "billing",
    "bank",
    "banking",
    "card",
    "transaction",
    "finance",
}

CRYPTO_KEYWORDS = {
    "crypto",
    "bitcoin",
    "ethereum",
    "usdt",
    "wallet",
    "airdrop",
}

REDIRECT_KEYWORDS = {
    "redirect=",
    "url=",
    "next=",
    "return=",
    "redirect_uri=",
    "continue=",
}


def _get_hostname(url):
    """Return the hostname from a URL."""
    parsed = urlparse(
        url if "://" in url else "http://" + url
    )
    return parsed.hostname or ""


def _matched_keywords(url, keywords):
    """Return keywords found in the URL."""
    url_lower = url.lower()
    return sorted(
        keyword
        for keyword in keywords
        if keyword in url_lower
    )


def analyze_attack_indicators(url):
    """
    Identify deterministic attack indicators from a URL.

    Returns:
        {
            "indicators": [
                {
                    "indicator_name": str,
                    "attack_category": str,
                    "severity": str,
                    "explanation": str
                }
            ]
        }
    """

    if not isinstance(url, str) or not url.strip():
        return {"indicators": []}

    url = url.strip()
    analysis = analyze_url(url)
    findings = analysis["findings"]
    hostname = _get_hostname(url)

    indicators = []

    credential_matches = _matched_keywords(
        url,
        CREDENTIAL_KEYWORDS
    )

    financial_matches = _matched_keywords(
        url,
        FINANCIAL_KEYWORDS
    )

    crypto_matches = _matched_keywords(
        url,
        CRYPTO_KEYWORDS
    )

    redirect_matches = _matched_keywords(
        url,
        REDIRECT_KEYWORDS
    )

    suspicious_infrastructure = any(
        phrase in finding
        for finding in findings
        for phrase in [
            "IP address",
            "suspicious TLD",
            "high number of subdomains",
        ]
    )

    obfuscation = any(
    phrase in finding
    for finding in findings
    for phrase in [
        "obfuscation",
        "encoded characters",
        "special characters",
    ]
)

    # Credential Theft / Login Phishing
    if credential_matches and (
        suspicious_infrastructure or obfuscation
    ):
        indicators.append({
            "indicator_name": "Credential Theft / Login Phishing",
            "attack_category": "Credential Theft",
            "severity": "high",
            "explanation": (
                "Credential-related keywords were combined "
                "with suspicious URL infrastructure or "
                "obfuscation."
            ),
        })

    # Banking / Financial Phishing
    if financial_matches and (
        credential_matches
        or suspicious_infrastructure
        or obfuscation
    ):
        indicators.append({
            "indicator_name": "Banking / Financial Phishing",
            "attack_category": "Financial Phishing",
            "severity": "high",
            "explanation": (
                "Financial or payment-related terms were "
                "combined with credential-related or "
                "suspicious URL characteristics."
            ),
        })

    # Cryptocurrency Scam
    if crypto_matches and (
        suspicious_infrastructure
        or obfuscation
        or credential_matches
    ):
        indicators.append({
            "indicator_name": "Cryptocurrency Scam",
            "attack_category": "Cryptocurrency Scam",
            "severity": "high",
            "explanation": (
                "Cryptocurrency-related terms were combined "
                "with suspicious infrastructure, obfuscation, "
                "or credential-related patterns."
            ),
        })

    # Malicious Redirect
    if redirect_matches and (
        suspicious_infrastructure or obfuscation
    ):
        indicators.append({
            "indicator_name": "Malicious Redirect",
            "attack_category": "Redirect Attack",
            "severity": "high",
            "explanation": (
                "A redirect-related URL parameter was detected "
                "together with suspicious infrastructure or "
                "URL obfuscation."
            ),
        })

    # Suspicious Infrastructure
    infrastructure_count = sum([
        any("IP address" in finding for finding in findings),
        any("suspicious TLD" in finding for finding in findings),
        any("high number of subdomains" in finding for finding in findings),
    ])

    if infrastructure_count >= 1:
        severity = "high" if infrastructure_count >= 2 else "medium"

        indicators.append({
            "indicator_name": "Suspicious Infrastructure",
            "attack_category": "Suspicious Infrastructure",
            "severity": severity,
            "explanation": (
                "The URL uses infrastructure characteristics "
                "commonly associated with suspicious or "
                "untrusted websites."
            ),
        })

    # Generic Phishing
    if (
        not indicators
        and len(findings) >= 2
    ):
        indicators.append({
            "indicator_name": "Generic Phishing",
            "attack_category": "Phishing",
            "severity": "medium",
            "explanation": (
                "Multiple suspicious URL characteristics were "
                "detected, but they did not match a more "
                "specific attack pattern."
            ),
        })

    return {
        "indicators": indicators
    }