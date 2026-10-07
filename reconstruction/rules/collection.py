"""Detect high-volume distinct-file collection within a rolling time window."""

from collections import Counter, defaultdict, deque
from datetime import timedelta
from pathlib import Path
from typing import Any

from schemas.attack_schema import AttackStage

from .common import iso_timestamp, iter_json_array, require_event_fields

COLLECTION_WINDOW = timedelta(minutes=10)
MIN_DISTINCT_FILES = 20
FILE_EVENT_TYPE = "FILE_ACCESS"


def _score_collection(distinct_file_count: int) -> float:
    """Score collection by how far distinct files exceed the minimum trigger."""
    return min(
        0.99,
        0.80 + max(0, distinct_file_count - MIN_DISTINCT_FILES) * 0.002,
    )


def detect_collection(events_path: Path) -> list[AttackStage]:
    """Detect user/device pairs accessing at least 50 distinct files in 10m."""
    windows: dict[tuple[str, str], deque[tuple[Any, str, str]]] = defaultdict(deque)
    filename_counts: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
    active: dict[tuple[str, str], dict[str, Any]] = {}
    stages: list[AttackStage] = []

    def finalize(key: tuple[str, str], record: dict[str, Any]) -> None:
        file_count = len(record["filenames"])
        confidence = _score_collection(file_count)
        stages.append(
            AttackStage(
                stage_id="",
                name="COLLECTION",
                classification="HIGH_VOLUME_FILE_ACCESS",
                description=(
                    f"At least {MIN_DISTINCT_FILES} distinct files were accessed "
                    f"within a rolling {int(COLLECTION_WINDOW.total_seconds() / 60)}-minute window."
                ),
                started_at=iso_timestamp(record["start_time"]),
                ended_at=iso_timestamp(record["end_time"]),
                risk_score=confidence,
                confidence=confidence,
                evidence_ids=sorted(record["event_ids"]),
                user_id=key[0],
                device_id=key[1],
                file_count=file_count,
                metadata={
                    "window_minutes": int(COLLECTION_WINDOW.total_seconds() / 60),
                    "minimum_distinct_files": MIN_DISTINCT_FILES,
                    "evidence_event_count": len(record["event_ids"]),
                    "distinct_file_count": file_count,
                },
            )
        )

    for index, event in enumerate(iter_json_array(events_path), start=1):
        if event.get("event_type") != FILE_EVENT_TYPE:
            continue
        event_id, _, user_id, device_id, timestamp = require_event_fields(
            event, source=events_path, index=index
        )
        metadata = event.get("metadata")
        filename = metadata.get("filename") if isinstance(metadata, dict) else None
        if not isinstance(filename, str) or not filename:
            raise ValueError(f"File event {event_id!r} has no filename metadata")
        key = (user_id, device_id)
        window = windows[key]
        counts = filename_counts[key]
        window.append((timestamp, event_id, filename))
        counts[filename.casefold()] += 1
        cutoff = timestamp - COLLECTION_WINDOW
        while window and window[0][0] < cutoff:
            _, _, expired_filename = window.popleft()
            counts[expired_filename.casefold()] -= 1
            if counts[expired_filename.casefold()] == 0:
                del counts[expired_filename.casefold()]

        record = active.get(key)
        if len(counts) >= MIN_DISTINCT_FILES:
            if record is None:
                record = {
                    "start_time": window[0][0],
                    "end_time": timestamp,
                    "event_ids": set(),
                    "filenames": set(),
                }
                active[key] = record
            record["end_time"] = timestamp
            record["event_ids"].update(row[1] for row in window)
            record["filenames"].update(row[2].casefold() for row in window)
        elif record is not None:
            finalize(key, record)
            del active[key]

    for key, record in active.items():
        finalize(key, record)
    return stages
