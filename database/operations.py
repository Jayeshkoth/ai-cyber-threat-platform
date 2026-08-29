from datetime import datetime
from typing import Optional

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from .config import DATABASE_URL
from .models import Base, ScanHistory


# Create database engine
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)


# Create tables if they do not exist
Base.metadata.create_all(engine)


def save_scan(
    url: str,
    prediction: str,
    confidence: float,
    timestamp: Optional[datetime] = None,
    security_analysis: Optional[str] = None,
    threat_intelligence: Optional[str] = None,
) -> ScanHistory:
    """Save a URL scan result to the database."""

    scan = ScanHistory(
        url=url,
        prediction=prediction,
        confidence=confidence,
        timestamp=timestamp or datetime.now(),
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

    with Session(engine) as session:
        statement = (
            select(ScanHistory)
            .order_by(ScanHistory.timestamp.desc())
            .limit(limit)
        )

        return list(session.scalars(statement).all())


def get_scan(scan_id: int) -> Optional[ScanHistory]:
    """Return a specific scan by its ID."""

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