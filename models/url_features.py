from urllib.parse import urlparse
import re


def extract_url_features(url):
    # Make sure URL has a scheme
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)

    domain = parsed.netloc
    path = parsed.path
    query = parsed.query

    features = {}

    # Basic URL features
    features["URLLength"] = len(url)
    features["DomainLength"] = len(domain)

    # Check if domain is an IP address
    features["IsDomainIP"] = int(
        bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", domain))
    )

    # Number of subdomains
    domain_parts = domain.split(".")
    features["NoOfSubDomain"] = max(len(domain_parts) - 2, 0)

    # Obfuscation
    suspicious_chars = ["@", "%", "//"]
    features["HasObfuscation"] = int(
        any(char in url for char in suspicious_chars)
    )

    features["NoOfObfuscatedChar"] = (
        url.count("@")
        + url.count("%")
    )

    features["ObfuscationRatio"] = (
        features["NoOfObfuscatedChar"] / len(url)
        if len(url) > 0 else 0
    )

    # Character statistics
    features["NoOfLettersInURL"] = sum(c.isalpha() for c in url)
    features["LetterRatioInURL"] = (
        features["NoOfLettersInURL"] / len(url)
        if len(url) > 0 else 0
    )

    features["NoOfDegitsInURL"] = sum(c.isdigit() for c in url)
    features["DegitRatioInURL"] = (
        features["NoOfDegitsInURL"] / len(url)
        if len(url) > 0 else 0
    )

    # Special characters
    features["NoOfEqualsInURL"] = url.count("=")
    features["NoOfQMarkInURL"] = url.count("?")
    features["NoOfAmpersandInURL"] = url.count("&")

    special_chars = set("!#$%&'()*+,-./:;=?@[]^_`{|}~")

    features["NoOfOtherSpecialCharsInURL"] = sum(
        c in special_chars
        for c in url
    )

    features["SpacialCharRatioInURL"] = (
        features["NoOfOtherSpecialCharsInURL"] / len(url)
        if len(url) > 0 else 0
    )

    # HTTPS
    features["IsHTTPS"] = int(parsed.scheme == "https")

    return features


if __name__ == "__main__":
    test_url = "https://www.google.com"

    result = extract_url_features(test_url)

    print("URL:", test_url)
    print("\nExtracted features:")

    for key, value in result.items():
        print(f"{key}: {value}")