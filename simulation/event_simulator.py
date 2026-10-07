"""Create canonical normalized event records from scenario definitions."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import hashlib
from typing import Callable

from schemas.event_schema import Event

from .scenario_library import Scenario


class EventSimulator:
    """Build schema-compatible, sequential, timestamped event records."""

    def __init__(
        self,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def generate(
        self,
        scenario: Scenario,
        *,
        user_id: str,
        device_id: str,
        first_event_number: int,
        after: datetime | None = None,
        target_device_id: str | None = None,
    ) -> list[dict[str, object]]:
        """Return one complete scenario as normalized event dictionaries."""
        now = self._as_utc(self._clock())
        timestamp = max(now, self._as_utc(after) + timedelta(seconds=1)) if after else now
        records: list[dict[str, object]] = []
        for offset, template in enumerate(scenario.events):
            metadata = dict(template.metadata)
            if metadata.get("malware_hash") == "sha256:simulated-indicator":
                seed = f"{scenario.name}:{user_id}:{device_id}".encode("utf-8")
                metadata["malware_hash"] = hashlib.sha256(seed).hexdigest()
            if metadata.get("target_device_id") == "pending":
                metadata["target_device_id"] = target_device_id or device_id
            if template.event_type == "FILE_ACCESS" and scenario.attack_type == "INSIDER_THEFT":
                metadata["filename"] = f"confidential_report_{offset:02d}.xlsx"
            event = Event(
                event_id=f"EVT{first_event_number + offset:06d}",
                timestamp=(timestamp + timedelta(seconds=offset))
                .replace(tzinfo=None)
                .isoformat(timespec="seconds"),
                event_type=template.event_type,
                event_category=template.event_category,
                source_system="Cerberus Simulation",
                source_log=template.source_log,
                user_id=user_id,
                device_id=device_id,
                src_ip="10.24.8.15",
                dst_ip="203.0.113.25" if template.event_category == "NETWORK_ACTIVITY" else None,
                correlation_id=f"SIM-{first_event_number:08d}",
                related_entities=[
                    str(value)
                    for key, value in metadata.items()
                    if key in {"filename", "target_device_id", "destination_domain"}
                    and isinstance(value, str)
                ],
                metadata=metadata,
                severity=template.severity,
                confidence=0.99 if scenario.is_attack else 0.98,
            )
            records.append(asdict(event))
        return records

    @staticmethod
    def _as_utc(value: datetime) -> datetime:
        """Normalize naive timestamps as UTC and preserve explicit offsets."""
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
