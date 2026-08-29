from datetime import datetime, timezone


def utc_now() -> datetime:
    """Return the current UTC time."""
    return datetime.now(timezone.utc)


def scan_to_dict(scan) -> dict:
    """Convert a ScanHistory object into a dictionary."""
    return {
        "id": scan.id,
        "url": scan.url,
        "prediction": scan.prediction,
        "confidence": scan.confidence,
        "timestamp": scan.timestamp.isoformat() if scan.timestamp else None,
        "security_analysis": scan.security_analysis,
        "threat_intelligence": scan.threat_intelligence,
    }