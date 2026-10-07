"""Write a unified, canonical CERT event collection incrementally."""

import json
import heapq
import os
import tempfile
from collections.abc import Iterable, Iterator
from dataclasses import asdict, replace
from datetime import datetime
from pathlib import Path

from schemas.event_schema import Event

SOURCE_TIMESTAMP_FORMAT = "%m/%d/%Y %H:%M:%S"


def _parse_timestamp(value: str) -> datetime:
    """Parse source timestamps and ISO timestamps into comparable values."""
    try:
        return datetime.strptime(value, SOURCE_TIMESTAMP_FORMAT)
    except ValueError:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as error:
            raise ValueError(f"Unsupported event timestamp {value!r}") from error


def write_normalized_events(
    event_streams: Iterable[Iterable[Event]],
    output_path: Path,
) -> int:
    """Chronologically merge parser streams and assign sequential event IDs.

    Each input stream must be timestamp ordered. Equal timestamps are ordered
    deterministically by source log, then by original row order within each
    stream. The merge and JSON serialization are incremental.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    event_count = 0
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            newline="\n",
            dir=output_path.parent,
            prefix=f".{output_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as output:
            temporary_path = Path(output.name)
            output.write("[")
            first_event = True
            for event in _merge_chronologically(event_streams):
                event_count += 1
                normalized = replace(event, event_id=f"EVT{event_count:06d}")
                if not first_event:
                    output.write(",")
                json.dump(
                    asdict(normalized),
                    output,
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                first_event = False
            output.write("]\n")
        os.replace(temporary_path, output_path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()
    return event_count


def _merge_chronologically(event_streams: Iterable[Iterable[Event]]) -> Iterator[Event]:
    """Yield a deterministic k-way merge of timestamp-ordered event streams."""
    iterators = [iter(stream) for stream in event_streams]
    previous_timestamps: list[datetime | None] = [None] * len(iterators)
    stream_positions = [0] * len(iterators)
    heap: list[tuple[datetime, str, int, int, Event]] = []

    def add_next(stream_index: int) -> None:
        try:
            event = next(iterators[stream_index])
        except StopIteration:
            return

        event_time = _parse_timestamp(event.timestamp)
        previous_time = previous_timestamps[stream_index]
        if previous_time is not None and event_time < previous_time:
            raise ValueError(
                f"Event stream {event.source_log!r} is not timestamp ordered: "
                f"{event.timestamp!r} follows a later timestamp"
            )
        previous_timestamps[stream_index] = event_time
        stream_position = stream_positions[stream_index]
        stream_positions[stream_index] += 1
        heapq.heappush(
            heap,
            (
                event_time,
                event.source_log,
                stream_index,
                stream_position,
                event,
            ),
        )

    for index in range(len(iterators)):
        add_next(index)

    while heap:
        _, _, stream_index, _, event = heapq.heappop(heap)
        yield event
        add_next(stream_index)
