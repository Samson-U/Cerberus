"""Normalize CERT device connection records into canonical events."""

from collections.abc import Iterator, Mapping
from pathlib import Path

from schemas.event_schema import Event

from .common import iter_csv_rows, registry_id, required_value

EVENT_TYPES = {"connect": "USB_INSERT", "disconnect": "USB_REMOVE"}
REQUIRED_COLUMNS = {"id", "date", "user", "pc", "activity"}


def parse_device(
    path: Path,
    user_ids: Mapping[str, str],
    device_ids: Mapping[str, str],
) -> Iterator[Event]:
    """Yield canonical events for CERT device connection/disconnection records."""
    for index, (line_number, row) in enumerate(
        iter_csv_rows(path, REQUIRED_COLUMNS), start=1
    ):
        source_id = required_value(row, "id", path=path, line_number=line_number)
        timestamp = required_value(
            row, "date", path=path, line_number=line_number
        )
        source_user = required_value(
            row, "user", path=path, line_number=line_number
        )
        source_device = required_value(
            row, "pc", path=path, line_number=line_number
        )
        activity = required_value(
            row, "activity", path=path, line_number=line_number
        )
        event_type = EVENT_TYPES.get(activity.casefold())
        if event_type is None:
            raise ValueError(
                f"{path}:{line_number}: unsupported device activity {activity!r}"
            )

        yield Event(
            event_id=f"EVT{index:06d}",
            timestamp=timestamp,
            event_type=event_type,
            event_category="DEVICE_ACTIVITY",
            source_system="CERT",
            source_log=path.name,
            user_id=registry_id(
                user_ids,
                source_user,
                entity="user",
                path=path,
                line_number=line_number,
            ),
            device_id=registry_id(
                device_ids,
                source_device,
                entity="device",
                path=path,
                line_number=line_number,
            ),
            related_entities=[source_device],
            metadata={"source_record_id": source_id, "activity": activity},
        )
