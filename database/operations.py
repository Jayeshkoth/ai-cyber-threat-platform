from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from .config import DATABASE_URL
from .models import Base, ScanHistory


engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)

Base.metadata.create_all(engine)


VALID_PREDICTIONS = {"PHISHING", "LEGITIMATE"}


def save_scan(
    url: str,
    prediction: str,
    confidence: float,
    timestamp: Optional[datetime] = None,
    security_analysis: Optional[str] = None,
    threat_intelligence: Optional[str] = None,
) -> ScanHistory:
    """Save a URL scan result to the database."""

    if not isinstance(url, str) or not url.strip():
        raise ValueError("URL cannot be empty")

    if prediction not in VALID_PREDICTIONS:
        raise ValueError("Invalid prediction value")

    if not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
        raise ValueError("Confidence must be between 0 and 1")

    scan = ScanHistory(
        url=url.strip(),
        prediction=prediction,
        confidence=float(confidence),
        timestamp=timestamp or datetime.now(timezone.utc),
        security_analysis=security_analysis,
        threat_intelligence=threat_intelligence,
    )

    with Session(engine) as session:
        session.add(scan)
        session.commit()
        session.refresh(scan)
        return scan


def get_recent_scans(limit: int = 10) -> list[ScanHistory]:
    """Return the most recent scan results."""

    if not isinstance(limit, int) or limit <= 0:
        raise ValueError("Limit must be a positive integer")

    with Session(engine) as session:
        statement = (
            select(ScanHistory)
            .order_by(ScanHistory.timestamp.desc())
            .limit(limit)
        )

        return list(session.scalars(statement).all())


def get_scan(scan_id: int) -> Optional[ScanHistory]:
    """Return a specific scan by its ID."""

    if not isinstance(scan_id, int) or scan_id <= 0:
        return None

    with Session(engine) as session:
        return session.get(ScanHistory, scan_id)


def get_statistics() -> dict:
    """Return basic scan statistics."""

    with Session(engine) as session:
        total = session.scalar(
            select(func.count(ScanHistory.id))
        ) or 0

        phishing = session.scalar(
            select(func.count(ScanHistory.id)).where(
                ScanHistory.prediction == "PHISHING"
            )
        ) or 0

        legitimate = session.scalar(
            select(func.count(ScanHistory.id)).where(
                ScanHistory.prediction == "LEGITIMATE"
            )
        ) or 0

        return {
            "total_scans": total,
            "phishing_count": phishing,
            "legitimate_count": legitimate,
        }

