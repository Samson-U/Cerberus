"""Schema for confidence-scored relationships between observed entities."""

from dataclasses import dataclass, field


@dataclass
class Link:
    """A probabilistic relationship supported by one or more evidence records."""

    link_id: str
    source_entity: str
    target_entity: str
    relationship: str
    confidence: float
    evidence_count: int
    first_seen: str | None = None
    last_seen: str | None = None
    metadata: dict[str, object] = field(default_factory=dict)
