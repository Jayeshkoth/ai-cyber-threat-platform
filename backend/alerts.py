def generate_alert(scan):
    """
    Generate an alert for a scan when its risk level,
    prediction, or security finding indicates a potentially
    dangerous URL.
    """

    risk_score = scan.get("risk_score", 0)
    prediction = scan.get("prediction", "UNKNOWN")
    findings = scan.get("findings", [])

    if risk_score >= 70:
        severity = "High"
    elif (
        prediction == "PHISHING"
        or risk_score >= 40
        or any(
            "impersonate" in finding.lower()
            for finding in findings
        )
    ):
        severity = "Medium"
    else:
        severity = "Low"

    if (
        risk_score >= 70
        or prediction == "PHISHING"
        or any(
            "impersonate" in finding.lower()
            for finding in findings
        )
    ):
        return {
            "alert": True,
            "severity": severity,
            "message": "Potentially malicious URL detected.",
            "prediction": prediction,
            "risk_score": risk_score,
        }

    return {
        "alert": False,
        "severity": severity,
        "message": "No significant threat detected.",
        "prediction": prediction,
        "risk_score": risk_score,
    }