"""Detect possible exfiltration only after collection and USB insertion evidence."""

from datetime import datetime, timedelta
from pathlib import Path

from schemas.attack_schema import AttackStage

from .common import iso_timestamp, iter_json_array, require_event_fields

USB_INSERT_EVENT_TYPE = "USB_INSERT"
MAX_USB_AFTER_COLLECTION = timedelta(minutes=15)


def detect_exfiltration(
    events_path: Path,
    collection_stages: list[AttackStage],
) -> list[AttackStage]:
    """Correlate qualifying collection stages with later same-user/device USB."""
    collections: dict[tuple[str, str], list[AttackStage]] = {}
    for stage in collection_stages:
        if stage.user_id is None or stage.device_id is None or stage.ended_at is None:
            continue
        collections.setdefault((stage.user_id, stage.device_id), []).append(stage)

    stages: list[AttackStage] = []
    for index, event in enumerate(iter_json_array(events_path), start=1):
        if event.get("event_type") != USB_INSERT_EVENT_TYPE:
            continue
        event_id, _, user_id, device_id, timestamp = require_event_fields(
            event, source=events_path, index=index
        )
        matching = [
            collection
            for collection in collections.get((user_id, device_id), [])
            if collection.ended_at is not None
            and timedelta(0)
            <= timestamp
            - datetime.fromisoformat(collection.ended_at)
            <= MAX_USB_AFTER_COLLECTION
        ]
        if not matching:
            continue

        collection = min(
            matching,
            key=lambda item: abs(
                (timestamp - datetime.fromisoformat(item.ended_at)).total_seconds()
            ),
        )
        gap = timestamp - datetime.fromisoformat(collection.ended_at)
        gap_minutes = gap.total_seconds() / 60
        usb_confidence = 0.90 - 0.01 * gap_minutes
        confidence = min(
            0.99,
            max(0.0, 0.5 * collection.confidence + 0.5 * usb_confidence),
        )
        evidence_ids = sorted(set(collection.evidence_ids) | {event_id})
        stages.append(
            AttackStage(
                stage_id="",
                name="EXFILTRATION",
                classification="COLLECTION_FOLLOWED_BY_USB_INSERTION",
                description=(
                    "High-volume distinct-file access was followed by a USB "
                    "insertion on the same user-associated endpoint."
                ),
                started_at=collection.started_at,
                ended_at=iso_timestamp(timestamp),
                risk_score=confidence,
                confidence=confidence,
                evidence_ids=evidence_ids,
                user_id=user_id,
                device_id=device_id,
                file_count=collection.file_count,
                metadata={
                    "collection_confidence": collection.confidence,
                    "collection_evidence_count": len(collection.evidence_ids),
                    "usb_event_id": event_id,
                    "minutes_after_collection": round(gap_minutes, 3),
                    "usb_event_source": "observed USB_INSERT",
                    "physical_usb_identity_available": False,
                },
            )
        )
    return stages
