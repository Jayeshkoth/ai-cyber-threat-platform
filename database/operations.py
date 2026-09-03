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


def get_threat_history(
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
) -> list[ScanHistory]:
    """Return scans within an optional time range."""

    with Session(engine) as session:
        statement = select(ScanHistory)

        if start_time is not None:
            statement = statement.where(
                ScanHistory.timestamp >= start_time
            )

        if end_time is not None:
            statement = statement.where(
                ScanHistory.timestamp <= end_time
            )

        statement = statement.order_by(ScanHistory.timestamp.asc())

        return list(session.scalars(statement).all())


def get_repeated_urls() -> list[dict]:
    """Return URLs that have been scanned more than once."""

    with Session(engine) as session:
        statement = (
            select(
                ScanHistory.url,
                func.count(ScanHistory.id).label("scan_count"),
                func.min(ScanHistory.timestamp).label("first_seen"),
                func.max(ScanHistory.timestamp).label("last_seen"),
            )
            .group_by(ScanHistory.url)
            .having(func.count(ScanHistory.id) > 1)
            .order_by(func.count(ScanHistory.id).desc())
        )

        results = session.execute(statement).all()

        return [
            {
                "url": row.url,
                "scan_count": row.scan_count,
                "first_seen": row.first_seen,
                "last_seen": row.last_seen,
            }
            for row in results
        ]


def get_prediction_distribution(
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
) -> dict:
    """Return phishing vs legitimate scan distribution."""

    with Session(engine) as session:
        statement = select(
            ScanHistory.prediction,
            func.count(ScanHistory.id).label("count"),
        )

        if start_time is not None:
            statement = statement.where(
                ScanHistory.timestamp >= start_time
            )

        if end_time is not None:
            statement = statement.where(
                ScanHistory.timestamp <= end_time
            )

        statement = statement.group_by(ScanHistory.prediction)

        results = session.execute(statement).all()

        distribution = {
            "PHISHING": 0,
            "LEGITIMATE": 0,
        }

        for row in results:
            distribution[row.prediction] = row.count

        return distribution


def get_threat_trends(
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
) -> list[dict]:
    """Return daily phishing and legitimate scan counts."""

    with Session(engine) as session:
        statement = select(
            func.date(ScanHistory.timestamp).label("date"),
            ScanHistory.prediction,
            func.count(ScanHistory.id).label("count"),
        )

        if start_time is not None:
            statement = statement.where(
                ScanHistory.timestamp >= start_time
            )

        if end_time is not None:
            statement = statement.where(
                ScanHistory.timestamp <= end_time
            )

        statement = statement.group_by(
            func.date(ScanHistory.timestamp),
            ScanHistory.prediction,
        ).order_by(
            func.date(ScanHistory.timestamp).asc()
        )

        results = session.execute(statement).all()

        trends = {}

        for row in results:
            date_key = str(row.date)

            if date_key not in trends:
                trends[date_key] = {
                    "date": date_key,
                    "PHISHING": 0,
                    "LEGITIMATE": 0,
                }

            trends[date_key][row.prediction] = row.count

        return list(trends.values())


def get_increased_risk_urls() -> list[dict]:
    """Return URLs whose phishing confidence increased across scans."""

    with Session(engine) as session:
        scans = list(
            session.scalars(
                select(ScanHistory).order_by(
                    ScanHistory.url.asc(),
                    ScanHistory.timestamp.asc(),
                )
            ).all()
        )

    history = {}

    for scan in scans:
        if scan.url not in history:
            history[scan.url] = []

        history[scan.url].append(scan)

    increased = []

    for url, url_scans in history.items():
        phishing_scans = [
            scan
            for scan in url_scans
            if scan.prediction == "PHISHING"
        ]

        if len(phishing_scans) < 2:
            continue

        first_confidence = phishing_scans[0].confidence
        last_confidence = phishing_scans[-1].confidence

        if last_confidence > first_confidence:
            increased.append(
                {
                    "url": url,
                    "first_risk": first_confidence,
                    "latest_risk": last_confidence,
                    "risk_increase": last_confidence - first_confidence,
                    "first_seen": phishing_scans[0].timestamp,
                    "last_seen": phishing_scans[-1].timestamp,
                }
            )

    return increased


def get_threat_statistics(
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
) -> dict:
    """Return threat statistics for an optional time range."""

    with Session(engine) as session:
        statement = select(
            ScanHistory.prediction,
            func.count(ScanHistory.id).label("count"),
        )

        if start_time is not None:
            statement = statement.where(
                ScanHistory.timestamp >= start_time
            )

        if end_time is not None:
            statement = statement.where(
                ScanHistory.timestamp <= end_time
            )

        statement = statement.group_by(ScanHistory.prediction)

        results = session.execute(statement).all()

        phishing_count = 0
        legitimate_count = 0

        for row in results:
            if row.prediction == "PHISHING":
                phishing_count = row.count
            elif row.prediction == "LEGITIMATE":
                legitimate_count = row.count

        return {
            "total_scans": phishing_count + legitimate_count,
            "phishing_count": phishing_count,
            "legitimate_count": legitimate_count,
        }