from dataclasses import dataclass, field
from typing import Any


@dataclass
class ThreatIntelResult:
    url: str
    reputation: str = "unknown"
    blacklisted: bool = False
    sources_checked: list[str] = field(default_factory=list)
    details: list[dict[str, Any]] = field(default_factory=list)