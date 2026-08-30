from threat_intelligence.schemas import ThreatIntelResult
from threat_intelligence.providers import virustotal
from threat_intelligence.providers import phishtank


def check_threat_intelligence(url: str) -> ThreatIntelResult:

    result = ThreatIntelResult(url=url)

    providers = [
        virustotal.check_url,
        phishtank.check_url,
    ]

    for provider in providers:

        provider_result = provider(url)

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