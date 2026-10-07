"""Build confidence-scored entity links from normalized CERT evidence."""

import argparse
import hashlib
import json
import math
import os
import tempfile
from collections import defaultdict
from collections.abc import Iterator
from dataclasses import asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from schemas.link_schema import Link

SOURCE_TIMESTAMP_FORMAT = "%m/%d/%Y %H:%M:%S"
LOGIN_EVENT_TYPE = "LOGIN_SUCCESS"
FILE_EVENT_TYPE = "FILE_ACCESS"
USB_INSERT_EVENT_TYPE = "USB_INSERT"
USB_LOGIN_WINDOW = timedelta(minutes=15)


def _iter_json_array(path: Path) -> Iterator[dict[str, Any]]:
    """Decode a JSON array incrementally so large event stores stay bounded."""
    decoder = json.JSONDecoder()
    with path.open("r", encoding="utf-8") as source:
        buffer = ""
        position = 0
        started = False
        finished = False
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
                finished = True
                if buffer[position:].strip() or source.read().strip():
                    raise ValueError(f"{path} has content after the JSON array")
                break

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

        if not finished:
            raise ValueError(f"{path} contains an incomplete JSON array")


def _parse_timestamp(value: str, *, path: Path, event_id: str) -> datetime:
    """Parse the CERT source time or an ISO-8601 timestamp."""
    try:
        return datetime.strptime(value, SOURCE_TIMESTAMP_FORMAT)
    except ValueError:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as error:
            raise ValueError(
                f"{path}: event {event_id!r} has invalid timestamp {value!r}"
            ) from error


def _time_bounds(
    aggregate: dict[tuple[str, str], dict[str, Any]],
    key: tuple[str, str],
    timestamp: datetime,
    event_id: str,
) -> None:
    """Increment a pair aggregate and track its observed time bounds."""
    item = aggregate.setdefault(
        key,
        {
            "evidence_count": 0,
            "first_seen": timestamp,
            "last_seen": timestamp,
            "sample_event_ids": [],
        },
    )
    item["evidence_count"] += 1
    item["first_seen"] = min(item["first_seen"], timestamp)
    item["last_seen"] = max(item["last_seen"], timestamp)
    if len(item["sample_event_ids"]) < 10:
        item["sample_event_ids"].append(event_id)


def _stable_target(prefix: str, value: str) -> str:
    """Create a deterministic, non-order-dependent entity reference."""
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:20].upper()
    return f"{prefix}-{digest}"


def _repeat_confidence(evidence_count: int) -> float:
    """Score repeated observations using the documented saturation formula."""
    return evidence_count / (evidence_count + 2)


def _timestamp_string(value: datetime) -> str:
    """Serialize a timestamp consistently to ISO-8601 second precision."""
    return value.isoformat(timespec="seconds")


def _link_sort_key(link: Link) -> tuple[str, str, str]:
    """Return the stable order used before sequential link IDs are assigned."""
    return (link.source_entity, link.target_entity, link.relationship)


def _atomic_write_json(path: Path, records: object) -> None:
    """Atomically write JSON beside its destination."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            newline="\n",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as output:
            temporary_path = Path(output.name)
            json.dump(
                records,
                output,
                ensure_ascii=False,
                separators=(",", ":"),
            )
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()


def build_entity_links(
    users_path: Path,
    devices_path: Path,
    events_path: Path,
    output_path: Path,
) -> list[Link]:
    """Infer supported CERT entity relationships and write the link collection.

    User/device links use successful logon events; file links use file access
    events; USB-use links require a recent successful login on the same
    endpoint and point to an observed USB insertion activity rather than an
    unidentified physical peripheral.
    """
    users_data = json.loads(users_path.read_text(encoding="utf-8"))
    devices_data = json.loads(devices_path.read_text(encoding="utf-8"))
    if not isinstance(users_data, list) or not isinstance(devices_data, list):
        raise ValueError("User and device registries must be JSON arrays")

    user_ids = {record.get("user_id") for record in users_data}
    device_ids = {record.get("device_id") for record in devices_data}
    if None in user_ids or None in device_ids:
        raise ValueError("User and device registries require stable IDs")
    valid_users = {str(value) for value in user_ids}
    valid_devices = {str(value) for value in device_ids}

    user_device: dict[tuple[str, str], dict[str, Any]] = {}
    user_file: dict[tuple[str, str], dict[str, Any]] = {}
    device_file: dict[tuple[str, str], dict[str, Any]] = {}
    login_times: dict[tuple[str, str], list[tuple[datetime, str]]] = defaultdict(list)
    usb_activity_links: list[Link] = []
    known_file_ids: set[str] = set()
    known_usb_activity_ids: set[str] = set()

    for event in _iter_json_array(events_path):
        event_id = event.get("event_id")
        timestamp_value = event.get("timestamp")
        event_type = event.get("event_type")
        if not isinstance(event_id, str) or not isinstance(timestamp_value, str):
            raise ValueError(f"{events_path} contains an event missing ID or timestamp")
        timestamp = _parse_timestamp(
            timestamp_value, path=events_path, event_id=event_id
        )
        user_id = event.get("user_id")
        device_id = event.get("device_id")
        if user_id is not None and user_id not in valid_users:
            raise ValueError(f"Event {event_id} references missing user {user_id!r}")
        if device_id is not None and device_id not in valid_devices:
            raise ValueError(
                f"Event {event_id} references missing device {device_id!r}"
            )

        if event_type == LOGIN_EVENT_TYPE and user_id and device_id:
            key = (user_id, device_id)
            _time_bounds(user_device, key, timestamp, event_id)
            login_times[key].append((timestamp, event_id))

        if event_type == FILE_EVENT_TYPE:
            if not user_id or not device_id:
                raise ValueError(
                    f"File event {event_id} is missing its user or endpoint"
                )
            metadata = event.get("metadata")
            filename = metadata.get("filename") if isinstance(metadata, dict) else None
            if not isinstance(filename, str) or not filename:
                raise ValueError(f"File event {event_id} has no source filename")
            file_id = _stable_target("FILE", filename.casefold())
            known_file_ids.add(file_id)
            _time_bounds(user_file, (user_id, file_id), timestamp, event_id)
            _time_bounds(device_file, (device_id, file_id), timestamp, event_id)

        if event_type == USB_INSERT_EVENT_TYPE:
            if not device_id:
                raise ValueError(f"USB insertion event {event_id} has no endpoint")
            metadata = event.get("metadata")
            source_record_id = (
                metadata.get("source_record_id")
                if isinstance(metadata, dict)
                else None
            )
            if not isinstance(source_record_id, str) or not source_record_id:
                raise ValueError(
                    f"USB insertion event {event_id} has no source record ID"
                )
            usb_id = _stable_target(
                "USB-ACTIVITY", f"{event.get('source_log', '')}:{source_record_id}"
            )
            known_usb_activity_ids.add(usb_id)
            usb_activity_links.append(
                Link(
                    link_id="",
                    source_entity=device_id,
                    target_entity=usb_id,
                    relationship="RECORDED_USB_ACTIVITY",
                    confidence=0.99,
                    evidence_count=1,
                    first_seen=_timestamp_string(timestamp),
                    last_seen=_timestamp_string(timestamp),
                    metadata={
                        "source_entity_type": "DEVICE",
                        "target_entity_type": "USB_ACTIVITY",
                        "source_event_id": event_id,
                        "source_record_id": source_record_id,
                        "physical_usb_identity_available": False,
                    },
                )
            )

    links: list[Link] = []
    for (user_id, device_id), aggregate in user_device.items():
        count = aggregate["evidence_count"]
        links.append(
            Link(
                link_id="",
                source_entity=user_id,
                target_entity=device_id,
                relationship="USES",
                confidence=_repeat_confidence(count),
                evidence_count=count,
                first_seen=_timestamp_string(aggregate["first_seen"]),
                last_seen=_timestamp_string(aggregate["last_seen"]),
                metadata={
                    "source_entity_type": "USER",
                    "target_entity_type": "DEVICE",
                    "sample_event_ids": aggregate["sample_event_ids"],
                    "sample_event_ids_truncated": count
                    > len(aggregate["sample_event_ids"]),
                    "evidence_type": LOGIN_EVENT_TYPE,
                },
            )
        )

    for (user_id, file_id), aggregate in user_file.items():
        count = aggregate["evidence_count"]
        links.append(
            Link(
                link_id="",
                source_entity=user_id,
                target_entity=file_id,
                relationship="ACCESSED",
                confidence=_repeat_confidence(count),
                evidence_count=count,
                first_seen=_timestamp_string(aggregate["first_seen"]),
                last_seen=_timestamp_string(aggregate["last_seen"]),
                metadata={
                    "source_entity_type": "USER",
                    "target_entity_type": "FILE",
                    "sample_event_ids": aggregate["sample_event_ids"],
                    "sample_event_ids_truncated": count
                    > len(aggregate["sample_event_ids"]),
                },
            )
        )

    for (device_id, file_id), aggregate in device_file.items():
        count = aggregate["evidence_count"]
        links.append(
            Link(
                link_id="",
                source_entity=device_id,
                target_entity=file_id,
                relationship="ACCESSED",
                confidence=_repeat_confidence(count),
                evidence_count=count,
                first_seen=_timestamp_string(aggregate["first_seen"]),
                last_seen=_timestamp_string(aggregate["last_seen"]),
                metadata={
                    "source_entity_type": "DEVICE",
                    "target_entity_type": "FILE",
                    "sample_event_ids": aggregate["sample_event_ids"],
                    "sample_event_ids_truncated": count
                    > len(aggregate["sample_event_ids"]),
                },
            )
        )

    links.extend(usb_activity_links)

    for event in _iter_json_array(events_path):
        if event.get("event_type") != USB_INSERT_EVENT_TYPE:
            continue
        user_id = event.get("user_id")
        device_id = event.get("device_id")
        if not user_id or not device_id:
            continue
        event_id = event["event_id"]
        timestamp = _parse_timestamp(
            event["timestamp"], path=events_path, event_id=event_id
        )
        metadata = event.get("metadata")
        source_record_id = (
            metadata.get("source_record_id") if isinstance(metadata, dict) else None
        )
        usb_id = _stable_target(
            "USB-ACTIVITY", f"{event.get('source_log', '')}:{source_record_id}"
        )
        candidates = login_times.get((user_id, device_id), [])
        matching_login: tuple[datetime, str] | None = None
        for login_time, login_event_id in reversed(candidates):
            if login_time > timestamp:
                continue
            if timestamp - login_time <= USB_LOGIN_WINDOW:
                matching_login = (login_time, login_event_id)
            break
        if matching_login is None:
            continue

        gap_seconds = (timestamp - matching_login[0]).total_seconds()
        confidence = 0.75 + 0.25 * math.exp(-gap_seconds / 300)
        links.append(
            Link(
                link_id="",
                source_entity=user_id,
                target_entity=usb_id,
                relationship="USED_USB",
                confidence=min(1.0, max(0.0, confidence)),
                evidence_count=2,
                first_seen=_timestamp_string(timestamp),
                last_seen=_timestamp_string(timestamp),
                metadata={
                    "source_entity_type": "USER",
                    "target_entity_type": "USB_ACTIVITY",
                    "source_event_id": event_id,
                    "login_event_id": matching_login[1],
                    "endpoint_device_id": device_id,
                    "login_to_insert_seconds": int(gap_seconds),
                    "physical_usb_identity_available": False,
                },
            )
        )

    links.sort(key=_link_sort_key)
    for index, link in enumerate(links, start=1):
        link.link_id = f"LINK{index:06d}"

    _validate_links(
        links,
        valid_users=valid_users,
        valid_devices=valid_devices,
        file_ids=known_file_ids,
        usb_activity_ids=known_usb_activity_ids,
    )
    _atomic_write_json(output_path, [asdict(link) for link in links])
    return links


def _validate_links(
    links: list[Link],
    *,
    valid_users: set[str],
    valid_devices: set[str],
    file_ids: set[str],
    usb_activity_ids: set[str],
) -> None:
    """Reject duplicate IDs, unsupported entity references, or invalid scores."""
    link_ids = [link.link_id for link in links]
    if len(link_ids) != len(set(link_ids)):
        raise ValueError("Generated duplicate link IDs")
    for link in links:
        if not 0.0 <= link.confidence <= 1.0:
            raise ValueError(f"Link {link.link_id} has invalid confidence")
        if link.evidence_count < 1:
            raise ValueError(f"Link {link.link_id} has no supporting evidence")
        source_type = link.metadata.get("source_entity_type")
        target_type = link.metadata.get("target_entity_type")
        valid_sources = {
            "USER": valid_users,
            "DEVICE": valid_devices,
        }.get(str(source_type), set())
        valid_targets = {
            "USER": valid_users,
            "DEVICE": valid_devices,
            "FILE": file_ids,
            "USB_ACTIVITY": usb_activity_ids,
        }.get(str(target_type), set())
        if link.source_entity not in valid_sources:
            raise ValueError(
                f"Link {link.link_id} references missing source "
                f"{link.source_entity!r}"
            )
        if link.target_entity not in valid_targets:
            raise ValueError(
                f"Link {link.link_id} references missing target "
                f"{link.target_entity!r}"
            )


def confidence_band(confidence: float) -> str:
    """Classify a confidence score using documented, non-overlapping bands."""
    if confidence >= 0.95:
        return "Very Strong"
    if confidence >= 0.85:
        return "Strong"
    if confidence >= 0.70:
        return "Moderate"
    if confidence >= 0.50:
        return "Weak"
    return "Unverified"


def _print_statistics(links: list[Link]) -> None:
    """Print requested counts, score distribution, and strongest user/device links."""
    user_device = [link for link in links if link.relationship == "USES"]
    user_file = [
        link
        for link in links
        if link.relationship == "ACCESSED"
        and link.metadata.get("source_entity_type") == "USER"
    ]
    user_usb = [link for link in links if link.relationship == "USED_USB"]
    distribution: dict[str, int] = defaultdict(int)
    for link in links:
        distribution[confidence_band(link.confidence)] += 1

    print(f"Total links: {len(links)}")
    print(f"User-device links: {len(user_device)}")
    print(f"User-file links: {len(user_file)}")
    print(f"User-USB activity links: {len(user_usb)}")
    print("Confidence distribution:")
    for band in ("Very Strong", "Strong", "Moderate", "Weak", "Unverified"):
        print(f"  {band}: {distribution.get(band, 0)}")
    print("Top 20 strongest user-device relationships:")
    for link in sorted(
        user_device,
        key=lambda item: (-item.confidence, -item.evidence_count, item.source_entity, item.target_entity),
    )[:20]:
        print(
            f"  {link.source_entity} -> {link.target_entity}: "
            f"confidence={link.confidence:.4f}, evidence={link.evidence_count}"
        )


def main() -> None:
    """Build links using paths relative to the Cerberus project root."""
    project_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="Build confidence-scored entity links from CERT data."
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=project_root,
        help="Cerberus project root (defaults to the root containing this package).",
    )
    arguments = parser.parse_args()
    root = arguments.project_root.resolve()
    links = build_entity_links(
        root / "data" / "processed" / "users.json",
        root / "data" / "processed" / "devices.json",
        root / "data" / "normalized" / "normalized_events.json",
        root / "data" / "processed" / "entity_links.json",
    )
    _print_statistics(links)


if __name__ == "__main__":
    main()
