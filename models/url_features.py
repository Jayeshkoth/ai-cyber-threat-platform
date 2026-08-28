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

    # --------------------------------------------------
    # BASIC URL FEATURES
    # --------------------------------------------------

    features["URLLength"] = len(url)

    features["DomainLength"] = len(domain)

    # --------------------------------------------------
    # IP ADDRESS
    # --------------------------------------------------

    # Remove port if present
    domain_without_port = domain.split(":")[0]

    features["IsDomainIP"] = int(
        bool(
            re.fullmatch(
                r"\d{1,3}(\.\d{1,3}){3}",
                domain_without_port
            )
        )
    )

    # --------------------------------------------------
    # SUBDOMAINS
    # --------------------------------------------------

    domain_parts = domain_without_port.split(".")

    if len(domain_parts) >= 3:
        features["NoOfSubDomain"] = len(domain_parts) - 2
    else:
        features["NoOfSubDomain"] = 0

    # --------------------------------------------------
    # OBFUSCATION
    # --------------------------------------------------

    # IMPORTANT:
    # We do NOT count "://" as obfuscation.
    #
    # @       -> suspicious
    # %       -> URL encoding
    # encoded characters -> suspicious
    #
    # A normal https:// URL should NOT automatically
    # become obfuscated.

    at_count = url.count("@")
    percent_count = url.count("%")

    features["HasObfuscation"] = int(
        at_count > 0 or percent_count > 0
    )

    features["NoOfObfuscatedChar"] = (
        at_count + percent_count
    )

    features["ObfuscationRatio"] = (
        features["NoOfObfuscatedChar"] / len(url)
        if len(url) > 0 else 0
    )

    # --------------------------------------------------
    # CHARACTER STATISTICS
    # --------------------------------------------------

    features["NoOfLettersInURL"] = sum(
        c.isalpha() for c in url
    )

    features["LetterRatioInURL"] = (
        features["NoOfLettersInURL"] / len(url)
        if len(url) > 0 else 0
    )

    features["NoOfDegitsInURL"] = sum(
        c.isdigit() for c in url
    )

    features["DegitRatioInURL"] = (
        features["NoOfDegitsInURL"] / len(url)
        if len(url) > 0 else 0
    )

    # --------------------------------------------------
    # QUERY PARAMETERS
    # --------------------------------------------------

    features["NoOfEqualsInURL"] = url.count("=")

    features["NoOfQMarkInURL"] = url.count("?")

    features["NoOfAmpersandInURL"] = url.count("&")

    # --------------------------------------------------
    # SPECIAL CHARACTERS
    # --------------------------------------------------

    special_chars = set(
        "!#$%&'()*+,-./:;=?@[]^_`{|}~"
    )

    features["NoOfOtherSpecialCharsInURL"] = sum(
        c in special_chars
        for c in url
    )

    features["SpacialCharRatioInURL"] = (
        features["NoOfOtherSpecialCharsInURL"] / len(url)
        if len(url) > 0 else 0
    )

    # --------------------------------------------------
    # HTTPS
    # --------------------------------------------------

    features["IsHTTPS"] = int(
        parsed.scheme.lower() == "https"
    )

    return features


# ------------------------------------------------------
# TEST
# ------------------------------------------------------

if __name__ == "__main__":

    test_urls = [
        "https://www.google.com",
        "https://www.microsoft.com",
        "http://secure-login-example.com/verify/account",
        "http://192.168.1.1/login",
        "https://example.com/login?user=test"
    ]

    for test_url in test_urls:

        print("\n" + "=" * 60)
        print("URL:", test_url)

        result = extract_url_features(test_url)

        for key, value in result.items():
            print(f"{key}: {value}")