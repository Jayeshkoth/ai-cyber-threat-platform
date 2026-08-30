import os
import base64
import requests
from dotenv import load_dotenv

load_dotenv()


VT_URL = "https://www.virustotal.com/api/v3/urls"

def get_url_id(url: str) -> str:
    """
    Convert a URL into the URL identifier expected by
    the VirusTotal API.
    """
    return base64.urlsafe_b64encode(
        url.encode()
    ).decode().rstrip("=")


def check_url(url: str) -> dict:
    """
    Check a URL against VirusTotal.

    Returns a normalized dictionary instead of exposing
    the raw VirusTotal response to the rest of our project.
    """

    api_key = os.getenv("VIRUSTOTAL_API_KEY")

    if not api_key:
        return {
            "source": "VirusTotal",
            "status": "not_configured",
            "malicious": None,
            "details": "VirusTotal API key is not configured."
        }

    url_id = get_url_id(url)

    headers = {
        "x-apikey": api_key
    }

    try:
        response = requests.get(
            f"{VT_URL}/{url_id}",
            headers=headers,
            timeout=10
        )

        if response.status_code == 404:
            return {
                "source": "VirusTotal",
                "status": "not_found",
                "malicious": None,
                "details": "URL was not found in VirusTotal."
            }

        response.raise_for_status()

        data = response.json()

        stats = data["data"]["attributes"]["last_analysis_stats"]

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        return {
            "source": "VirusTotal",
            "status": "success",
            "malicious": malicious > 0,
            "malicious_detections": malicious,
            "suspicious_detections": suspicious,
            "details": stats
        }

    except requests.RequestException as error:
        return {
            "source": "VirusTotal",
            "status": "error",
            "malicious": None,
            "details": str(error)
        }