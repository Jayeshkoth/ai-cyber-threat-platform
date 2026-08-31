import os
import requests


PHISHTANK_URL = "https://checkurl.phishtank.com/checkurl/"


def check_url(url: str) -> dict:
    """
    Check whether a URL is present in PhishTank.
    """

    app_key = os.getenv("PHISHTANK_APP_KEY")

    payload = {
        "url": url,
        "format": "json"
    }

    if app_key:
        payload["app_key"] = app_key

    headers = {
        "User-Agent": "AI-Cyber-Threat-Platform/1.0"
    }

    try:
        response = requests.post(
            PHISHTANK_URL,
            data=payload,
            headers=headers,
            timeout=10
        )

        response.raise_for_status()

        data = response.json()
        result = data.get("results", {})

        in_database = result.get("in_database", False)

        return {
            "source": "PhishTank",
            "status": "success",
            "malicious": bool(in_database),
            "details": {
                "in_database": in_database,
                "verified": result.get("verified"),
                "valid": result.get("valid"),
                "phish_id": result.get("phish_id")
            }
        }

    except requests.RequestException as error:
        return {
            "source": "PhishTank",
            "status": "error",
            "malicious": None,
            "details": str(error)
        }