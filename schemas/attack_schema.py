"""Dataclasses for reconstructed attacks, their evidence, and timelines."""

from dataclasses import dataclass, field

from .event_schema import Event


@dataclass
class AttackStage:
    """A classified stage in an attack lifecycle."""

    stage_id: str
    name: str
    classification: str
    description: str = ""
    started_at: str | None = None
    ended_at: str | None = None
    risk_score: float = 0.0
    confidence: float = 1.0
    evidence_ids: list[str] = field(default_factory=list)
    user_id: str | None = None
    device_id: str | None = None
    file_count: int | None = None
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass
class AttackEvidence:
    """An evidence item linking source observations to an attack hypothesis."""

    evidence_id: str
    description: str
    source_system: str
    source_log: str
    observed_at: str
    event_ids: list[str] = field(default_factory=list)
    entity_ids: list[str] = field(default_factory=list)
    severity: str = "low"
    confidence: float = 1.0
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass
class AttackChain:
    """An ordered reconstruction of related attack stages and evidence."""

    chain_id: str
    title: str
    stages: list[AttackStage] = field(default_factory=list)
    evidence: list[AttackEvidence] = field(default_factory=list)
    risk_score: float = 0.0
    confidence: float = 1.0
    summary: str = ""
    attack_type: str = ""
    user_id: str | None = None
    device_id: str | None = None
    start_time: str | None = None
    end_time: str | None = None
    stage_ids: list[str] = field(default_factory=list)
    graph: dict[str, object] = field(default_factory=dict)


@dataclass
class AttackTimeline:
    """Chronologically ordered events and evidence for an attack chain."""

    timeline_id: str
    chain_id: str
    events: list[Event] = field(default_factory=list)
    evidence: list[AttackEvidence] = field(default_factory=list)
    start_time: str | None = None
    end_time: str | None = None
    generated_at: str | None = None


@dataclass
class AttackReport:
    """A report containing a reconstructed chain, timeline, and risk assessment."""

    report_id: str
    title: str
    summary: str
    chain: AttackChain
    timeline: AttackTimeline
    risk_score: float = 0.0
    severity: str = "low"
    confidence: float = 1.0
    recommendations: list[str] = field(default_factory=list)
    generated_at: str | None = None
    metadata: dict[str, object] = field(default_factory=dict)
