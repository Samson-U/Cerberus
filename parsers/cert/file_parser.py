"""Normalize CERT file records into canonical file activity events."""

from collections.abc import Iterator, Mapping
from pathlib import Path

from schemas.event_schema import Event

from .common import iter_csv_rows, registry_id, required_value

REQUIRED_COLUMNS = {"id", "date", "user", "pc", "filename", "content"}


def parse_file(
    path: Path,
    user_ids: Mapping[str, str],
    device_ids: Mapping[str, str],
) -> Iterator[Event]:
    """Yield file-access events while retaining the source filename and content.

    `file.csv` has no action/activity column, so creation, modification,
    deletion, or copy events cannot be inferred from its observed schema.
    """
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
        filename = required_value(
            row, "filename", path=path, line_number=line_number
        )
        content = row.get("content")
        if content is None:
            raise ValueError(
                f"{path}:{line_number}: required column 'content' is missing"
            )

        yield Event(
            event_id=f"EVT{index:06d}",
            timestamp=timestamp,
            event_type="FILE_ACCESS",
            event_category="FILE_ACTIVITY",
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
            related_entities=[filename],
            metadata={
                "source_record_id": source_id,
                "filename": filename,
                "content": content,
            },
        )
