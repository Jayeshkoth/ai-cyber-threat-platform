from urllib.parse import urlparse
import ipaddress
import re


SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "zip"
}

SUSPICIOUS_KEYWORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "update",
    "secure",
    "password",
    "payment",
    "billing",
    "wallet",
    "confirm",
}


def _is_ip_address(hostname):
    """Return True if the hostname is an IPv4 or IPv6 address."""
    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def analyze_url(url):
    """
    Analyze a URL using security heuristics.

    Returns:
        {
            "risk_score": int,
            "findings": list[str]
        }
    """

    if not isinstance(url, str) or not url.strip():
        return {
            "risk_score": 0,
            "findings": ["Invalid or empty URL"]
        }

    url = url.strip()

    # Add a scheme so urlparse can correctly identify the hostname.
    parsed = urlparse(
        url if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url)
        else "http://" + url
    )

    hostname = parsed.hostname or ""
    full_url = parsed.geturl()

    risk_score = 0
    findings = []

    # --------------------------------------------------
    # 1. IP-BASED URL
    # --------------------------------------------------

    if _is_ip_address(hostname):
        risk_score += 30
        findings.append(
            "URL uses an IP address instead of a domain"
        )

    # --------------------------------------------------
    # 2. URL LENGTH
    # --------------------------------------------------

    if len(full_url) > 100:
        risk_score += 15
        findings.append(
            "URL is unusually long"
        )

    # --------------------------------------------------
    # 3. SUBDOMAINS
    # --------------------------------------------------

    if not _is_ip_address(hostname):
        domain_parts = hostname.split(".")
        subdomain_count = max(len(domain_parts) - 2, 0)

        if subdomain_count >= 3:
            risk_score += 10
            findings.append(
                "URL contains an unusually high number of subdomains"
            )

    # --------------------------------------------------
    # 4. URL OBFUSCATION
    # --------------------------------------------------

    if "@" in full_url:
        risk_score += 20
        findings.append(
            "URL contains '@', which can be used for URL obfuscation"
        )

    encoded_matches = re.findall(
        r"%[0-9a-fA-F]{2}",
        full_url
    )

    if len(encoded_matches) >= 2:
        risk_score += 10
        findings.append(
            "URL contains multiple encoded characters"
        )

    # --------------------------------------------------
    # 5. SUSPICIOUS CHARACTERS
    # --------------------------------------------------

    suspicious_character_count = sum(
        full_url.count(char)
        for char in ["@", "$", "^", "`", "{", "}", "[", "]"]
    )

    if suspicious_character_count >= 2:
        risk_score += 10
        findings.append(
            "URL contains multiple suspicious special characters"
        )

    # --------------------------------------------------
    # 6. SUSPICIOUS TLD
    # --------------------------------------------------

    if not _is_ip_address(hostname) and "." in hostname:
        tld = hostname.rsplit(".", 1)[-1].lower()

        if tld in SUSPICIOUS_TLDS:
            risk_score += 15
            findings.append(
                f"URL uses a potentially suspicious TLD: .{tld}"
            )

    # --------------------------------------------------
    # 7. REDIRECT-RELATED INDICATORS
    # --------------------------------------------------

    redirect_keywords = [
        "redirect=",
        "url=",
        "next=",
        "return=",
        "redirect_uri=",
        "continue=",
    ]

    if any(
        keyword in full_url.lower()
        for keyword in redirect_keywords
    ):
        risk_score += 10
        findings.append(
            "URL contains a redirect-related parameter"
        )

    # --------------------------------------------------
    # 8. LOGIN / PAYMENT / VERIFICATION PATTERNS
    # --------------------------------------------------

    url_lower = full_url.lower()

    matched_keywords = [
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword in url_lower
    ]

    if matched_keywords:
        risk_score += 10
        findings.append(
            "URL contains security-sensitive keywords: "
            + ", ".join(sorted(matched_keywords))
        )

    # --------------------------------------------------
    # FINAL SCORE
    # --------------------------------------------------

    risk_score = min(risk_score, 100)

    return {
        "risk_score": risk_score,
        "findings": findings,
    }


if __name__ == "__main__":
    test_urls = [
        "https://www.google.com",
        "http://192.168.1.1/login",
        "https://secure-login-example.xyz/verify/account",
        "https://example.com",
    ]

    for test_url in test_urls:
        print("\n" + "=" * 60)
        print("URL:", test_url)

        result = analyze_url(test_url)

        print("Risk Score:", result["risk_score"])
        print("Findings:")

        for finding in result["findings"]:
            print("-", finding)
