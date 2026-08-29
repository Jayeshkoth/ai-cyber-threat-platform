from database.operations import (
    save_scan,
    get_recent_scans,
    get_scan,
    get_statistics,
)
from database.utils import scan_to_dict


# 1. Save a test scan
scan = save_scan(
    url="https://example.com",
    prediction="LEGITIMATE",
    confidence=0.95,
)

print("Saved scan:")
print(scan_to_dict(scan))


# 2. Get recent scans
scans = get_recent_scans()

print("\nRecent scans:")
for item in scans:
    print(scan_to_dict(item))


# 3. Get a specific scan
specific_scan = get_scan(scan.id)

print("\nSpecific scan:")
print(scan_to_dict(specific_scan))


# 4. Get statistics
statistics = get_statistics()

print("\nStatistics:")
print(statistics)
phishing_scan = save_scan(
    url="http://suspicious-test-site.com",
    prediction="PHISHING",
    confidence=0.91,
)

print("\nSaved phishing scan:")
print(scan_to_dict(phishing_scan))

print("\nUpdated statistics:")
print(get_statistics())