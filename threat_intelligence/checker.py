from threat_intelligence.schemas import ThreatIntelResult
from threat_intelligence.providers import virustotal
from threat_intelligence.providers import phishtank


def check_threat_intelligence(url: str) -> ThreatIntelResult:

    result = ThreatIntelResult(url=url)

    providers = [
        ("VirusTotal", virustotal.check_url),
        ("PhishTank", phishtank.check_url),
    ]

    for provider_name, provider_func in providers:

        try:
            provider_result = provider_func(url)

        except Exception as error:
            provider_result = {
                "source": provider_name,
                "status": "error",
                "malicious": None,
                "details": str(error)
            }

        result.sources_checked.append(
            provider_result["source"]
        )

        result.details.append(
            provider_result
        )

    malicious_results = [
        item["malicious"]
        for item in result.details
        if item["malicious"] is not None
    ]

    if any(malicious_results):
        result.reputation = "malicious"
        result.blacklisted = True

    elif malicious_results:
        result.reputation = "clean"

    else:
        result.reputation = "unknown"

    return result