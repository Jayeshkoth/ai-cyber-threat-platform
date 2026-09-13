def predict_attack(
    ml_result: dict,
    security_result: dict,
    threat_intel_result: dict
) -> dict:
    """
    Infer the most likely attack category by combining
    ML prediction, security indicators, risk score,
    and threat-intelligence evidence.

    This is a hybrid evidence-fusion engine.
    It does not claim to predict a specific future attack.
    """

    findings = security_result.get("findings", [])
    risk_score = security_result.get("risk_score", 0)

    phishing_probability = ml_result.get(
        "phishing_probability",
        0
    )

    reputation = threat_intel_result.get(
        "reputation",
        "unknown"
    )

    # --------------------------------------------------
    # Attack categories
    # --------------------------------------------------

    scores = {
        "Credential Theft": 0,
        "Banking Phishing": 0,
        "Cryptocurrency Scam": 0,
        "Malicious Redirect": 0,
        "Suspicious Infrastructure": 0,
        "Generic Phishing": 0,
        "Benign": 0
    }

    evidence = []

    # Convert findings into one lowercase string
    # so indicator matching is consistent.
    finding_texts = [
        str(finding).lower()
        for finding in findings
    ]

    combined_findings = " ".join(finding_texts)

    # --------------------------------------------------
    # 1. OVERALL THREAT SIGNAL
    # --------------------------------------------------

    is_likely_phishing = phishing_probability >= 0.50
    is_high_confidence_phishing = phishing_probability >= 0.80

    # --------------------------------------------------
    # 2. ML EVIDENCE
    # --------------------------------------------------

    if is_high_confidence_phishing:
        scores["Generic Phishing"] += 25

        evidence.append(
            "ML model detected a high phishing probability."
        )

    elif is_likely_phishing:
        scores["Generic Phishing"] += 12

        evidence.append(
            "ML model detected a moderate phishing probability."
        )

    # --------------------------------------------------
    # 3. CREDENTIAL THEFT
    # --------------------------------------------------

    credential_keywords = [
        "login",
        "signin",
        "sign-in",
        "password",
        "verify",
        "verification",
        "confirm"
    ]

    credential_matches = [
        keyword
        for keyword in credential_keywords
        if keyword in combined_findings
    ]

    if credential_matches:
        scores["Credential Theft"] += 35

        evidence.append(
            "Credential-related URL indicators were detected: "
            + ", ".join(credential_matches)
            + "."
        )

    # --------------------------------------------------
    # 4. BANKING / FINANCIAL PHISHING
    # --------------------------------------------------

    banking_keywords = [
        "bank",
        "banking",
        "payment",
        "billing",
        "card",
        "account"
    ]

    banking_matches = [
        keyword
        for keyword in banking_keywords
        if keyword in combined_findings
    ]

    if banking_matches:
        scores["Banking Phishing"] += 35

        evidence.append(
            "Financial or banking-related indicators were detected: "
            + ", ".join(banking_matches)
            + "."
        )

    # --------------------------------------------------
    # 5. CRYPTOCURRENCY SCAM
    # --------------------------------------------------

    crypto_keywords = [
        "crypto",
        "cryptocurrency",
        "bitcoin",
        "ethereum",
        "wallet",
        "token"
    ]

    crypto_matches = [
        keyword
        for keyword in crypto_keywords
        if keyword in combined_findings
    ]

    if crypto_matches:
        scores["Cryptocurrency Scam"] += 35

        evidence.append(
            "Cryptocurrency-related indicators were detected: "
            + ", ".join(crypto_matches)
            + "."
        )

    # --------------------------------------------------
    # 6. MALICIOUS REDIRECT
    # --------------------------------------------------

    redirect_indicators = [
        "redirect-related parameter",
        "redirect=",
        "redirect_uri",
        "return=",
        "next=",
        "continue=",
        "url="
    ]

    redirect_matches = [
        indicator
        for indicator in redirect_indicators
        if indicator in combined_findings
    ]

    if redirect_matches:
        scores["Malicious Redirect"] += 35

        evidence.append(
            "Redirect-related URL indicators were detected."
        )

    # --------------------------------------------------
    # 7. SUSPICIOUS INFRASTRUCTURE
    # --------------------------------------------------

    infrastructure_indicators = [
        "ip address",
        "ip-based",
        "suspicious tld",
        "unusually high number of subdomains",
        "unusually long"
    ]

    infrastructure_matches = [
        indicator
        for indicator in infrastructure_indicators
        if indicator in combined_findings
    ]

    if infrastructure_matches:
        scores["Suspicious Infrastructure"] += 35

        evidence.append(
            "Suspicious infrastructure characteristics were detected."
        )

        # --------------------------------------------------
    # 7.5 BRAND IMPERSONATION
    # --------------------------------------------------

    if "impersonate" in combined_findings:
        scores["Generic Phishing"] += 50

        evidence.append(
            "The hostname appears to impersonate a trusted brand."
        )
    # --------------------------------------------------
    # 8. COMBINATION EVIDENCE
    # --------------------------------------------------

    if (
        is_likely_phishing
        and scores["Credential Theft"] > 0
    ):
        scores["Credential Theft"] += 20

        evidence.append(
            "Phishing probability combined with credential-related "
            "indicators strengthens the credential-theft assessment."
        )

    if (
        is_likely_phishing
        and scores["Banking Phishing"] > 0
    ):
        scores["Banking Phishing"] += 20

        evidence.append(
            "Phishing probability combined with financial indicators "
            "strengthens the banking-phishing assessment."
        )

    if (
        is_likely_phishing
        and scores["Cryptocurrency Scam"] > 0
    ):
        scores["Cryptocurrency Scam"] += 20

        evidence.append(
            "Phishing probability combined with cryptocurrency "
            "indicators strengthens the crypto-scam assessment."
        )

    if (
        is_likely_phishing
        and scores["Malicious Redirect"] > 0
    ):
        scores["Malicious Redirect"] += 20

        evidence.append(
            "Phishing probability combined with redirect indicators "
            "strengthens the malicious-redirect assessment."
        )

    if (
        is_likely_phishing
        and scores["Suspicious Infrastructure"] > 0
    ):
        scores["Suspicious Infrastructure"] += 20

        evidence.append(
            "Phishing probability combined with suspicious infrastructure "
            "indicators strengthens the suspicious-infrastructure assessment."
          )

    # --------------------------------------------------
    # 9. RISK SCORE
    # --------------------------------------------------

    if risk_score >= 70:
        evidence.append(
            "Security analysis indicates high risk."
        )

        for category in scores:
            if category != "Benign":
                scores[category] += 10

    elif risk_score >= 40:
        evidence.append(
            "Security analysis indicates elevated risk."
        )

        for category in scores:
            if category != "Benign":
                scores[category] += 5

    # --------------------------------------------------
    # 10. THREAT INTELLIGENCE
    # --------------------------------------------------

    if reputation == "malicious":
        evidence.append(
            "Threat intelligence sources classified "
            "the URL as malicious."
        )

        for category in scores:
            if category != "Benign":
                scores[category] += 15

    elif reputation == "clean":
        evidence.append(
            "Threat intelligence sources did not "
            "identify the URL as malicious."
        )

    elif reputation == "unknown":
        evidence.append(
            "Threat intelligence could not establish "
            "a definitive reputation."
        )

    # --------------------------------------------------
    # 11. BENIGN ASSESSMENT
    # --------------------------------------------------

    if (
    phishing_probability < 0.50
    and risk_score < 40
    and reputation != "malicious"
    and not any(
        "impersonate" in finding.lower()
        for finding in findings
    )
):
     scores["Benign"] = 80

    # --------------------------------------------------
    # 12. FINAL CATEGORY
    # --------------------------------------------------

    attack_category = max(
        scores,
        key=scores.get
    )

    attack_likelihood = min(
        max(scores[attack_category], 0),
        100
    )

    # --------------------------------------------------
    # 13. SEVERITY
    # --------------------------------------------------

    if attack_category == "Benign":
        severity = "Low"

    elif attack_likelihood >= 70:
        severity = "High"

    elif attack_likelihood >= 40:
        severity = "Medium"

    else:
        severity = "Low"

    # --------------------------------------------------
    # 14. FINAL RESULT
    # --------------------------------------------------

    return {
        "attack_category": attack_category,
        "attack_likelihood": attack_likelihood,
        "severity": severity,
        "evidence": list(dict.fromkeys(evidence))
    }