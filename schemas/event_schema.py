"""Canonical event model used to normalize security telemetry."""

from dataclasses import dataclass, field


@dataclass
class Event:
    """A normalized security event from a source system or log."""

    event_id: str
    timestamp: str
    event_type: str
    event_category: str
    source_system: str
    source_log: str
    user_id: str | None = None
    device_id: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    correlation_id: str | None = None
    related_entities: list[str] = field(default_factory=list)
    metadata: dict[str, object] = field(default_factory=dict)
    severity: str = "low"
    confidence: float = 1.0
