"""Shared input validation and event utilities for reconstruction rules."""

import json
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any


SOURCE_TIMESTAMP_FORMAT = "%m/%d/%Y %H:%M:%S"


def iter_json_array(path: Path) -> Iterator[dict[str, Any]]:
    """Yield dictionary items from a JSON array with bounded input buffering."""
    decoder = json.JSONDecoder()
    with path.open("r", encoding="utf-8") as source:
        buffer = ""
        position = 0
        started = False
        while True:
            while position < len(buffer) and buffer[position] in " \r\n\t,":
                position += 1

            if not started:
                if position >= len(buffer):
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        raise ValueError(f"{path} is empty or has no JSON array")
                    buffer = buffer[position:] + chunk
                    position = 0
                    continue
                if buffer[position] != "[":
                    raise ValueError(f"{path} must contain a JSON array")
                position += 1
                started = True
                continue

            if position < len(buffer) and buffer[position] == "]":
                position += 1
                if buffer[position:].strip() or source.read().strip():
                    raise ValueError(f"{path} has content after its JSON array")
                return

            try:
                value, end = decoder.raw_decode(buffer, position)
            except json.JSONDecodeError:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    raise ValueError(f"{path} contains an incomplete JSON array")
                buffer = buffer[position:] + chunk
                position = 0
                continue

            if not isinstance(value, dict):
                raise ValueError(f"{path} contains a non-object array item")
            position = end
            if position > 1024 * 1024:
                buffer = buffer[position:]
                position = 0
            yield value


def parse_event_time(value: str, *, event_id: str, source: Path) -> datetime:
    """Parse a CERT event timestamp, accepting the normalized source format."""
    try:
        return datetime.strptime(value, SOURCE_TIMESTAMP_FORMAT)
    except ValueError:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as error:
            raise ValueError(
                f"{source}: event {event_id!r} has invalid timestamp {value!r}"
            ) from error


def iso_timestamp(value: datetime) -> str:
    """Format event time as second-precision ISO 8601."""
    return value.isoformat(timespec="seconds")


def require_event_fields(
    event: dict[str, Any],
    *,
    source: Path,
    index: int,
) -> tuple[str, str, str, str, datetime]:
    """Validate and return the common identifiers and timestamp for an event."""
    event_id = event.get("event_id")
    event_type = event.get("event_type")
    timestamp = event.get("timestamp")
    if not all(isinstance(value, str) and value for value in (event_id, event_type, timestamp)):
        raise ValueError(f"{source}: event at position {index} lacks ID/type/timestamp")
    user_id = event.get("user_id")
    device_id = event.get("device_id")
    if not isinstance(user_id, str) or not isinstance(device_id, str):
        raise ValueError(
            f"{source}: event {event_id!r} lacks user/device linkage"
        )
    return (
        event_id,
        event_type,
        user_id,
        device_id,
        parse_event_time(timestamp, event_id=event_id, source=source),
    )
