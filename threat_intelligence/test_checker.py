from threat_intelligence.checker import check_threat_intelligence


result = check_threat_intelligence(
    "https://example.com"
)

print("URL:", result.url)
print("Reputation:", result.reputation)
print("Blacklisted:", result.blacklisted)
print("Sources:", result.sources_checked)
print("Details:", result.details)