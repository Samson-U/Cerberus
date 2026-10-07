"""Shared CSV and registry lookup helpers for CERT parsers."""

import csv
from collections.abc import Iterator, Mapping
from pathlib import Path


def iter_csv_rows(
    path: Path,
    required_columns: set[str],
) -> Iterator[tuple[int, dict[str, str | None]]]:
    """Yield CSV rows with source line numbers after validating the header."""
    with path.open("r", encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source)
        if reader.fieldnames is None:
            raise ValueError(f"{path} is empty or has no CSV header")

        missing = required_columns.difference(reader.fieldnames)
        if missing:
            columns = ", ".join(sorted(missing))
            raise ValueError(f"{path} is missing required column(s): {columns}")

        for row in reader:
            yield reader.line_num, row


def required_value(
    row: Mapping[str, str | None],
    column: str,
    *,
    path: Path,
    line_number: int,
) -> str:
    """Return a non-empty source value or raise a location-specific error."""
    value = row.get(column)
    if value is None or not value.strip():
        raise ValueError(
            f"{path}:{line_number}: required column {column!r} is empty"
        )
    return value


def registry_id(
    registry: Mapping[str, str],
    source_value: str,
    *,
    entity: str,
    path: Path,
    line_number: int,
) -> str:
    """Resolve a source identifier to its stable canonical registry ID."""
    try:
        return registry[source_value]
    except KeyError as error:
        raise ValueError(
            f"{path}:{line_number}: {entity} {source_value!r} is missing "
            "from the registry; rebuild the registries from the same CERT data"
        ) from error
