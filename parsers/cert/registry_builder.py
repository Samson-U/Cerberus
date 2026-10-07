"""Build stable user and device registries from CERT directory and log data."""

import json
import os
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

from .common import iter_csv_rows, required_value

LDAP_COLUMNS = {
    "user_id",
    "employee_name",
    "email",
    "role",
    "department",
    "supervisor",
}
LOG_COLUMNS = {"date", "user", "pc"}
REGISTRY_LOGS = ("logon.csv", "file.csv", "device.csv")
SOURCE_TIMESTAMP_FORMAT = "%m/%d/%Y %H:%M:%S"


def _atomic_write_json(path: Path, value: object) -> None:
    """Write JSON to a temporary sibling and atomically replace the target."""
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
        ) as temporary:
            temporary_path = Path(temporary.name)
            json.dump(value, temporary, ensure_ascii=False, indent=2)
            temporary.write("\n")
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()


def _timestamp(value: str, *, source: str) -> datetime:
    """Parse a CERT event timestamp, preserving its timezone-naive source time."""
    try:
        return datetime.strptime(value, SOURCE_TIMESTAMP_FORMAT)
    except ValueError as error:
        raise ValueError(f"{source}: invalid CERT timestamp {value!r}") from error


def _iso_timestamp(value: datetime) -> str:
    """Format registry timestamps consistently to second precision."""
    return value.isoformat(timespec="seconds")


def build_registries(
    cert_root: Path,
    processed_dir: Path,
) -> tuple[dict[str, str], dict[str, str]]:
    """Build registries and return source-username/hostname to stable-ID maps.

    LDAP snapshots are deduplicated by their source `user_id`. Endpoint
    assignments are inferred from observed user/PC pairs in the three
    supported CERT logs; shared endpoints retain every observed user.
    """
    cert_root = cert_root.resolve()
    ldap_dir = cert_root / "LDAP"
    if not ldap_dir.is_dir():
        raise FileNotFoundError(f"CERT LDAP directory not found: {ldap_dir}")
    ldap_files = sorted(ldap_dir.glob("*.csv"))
    if not ldap_files:
        raise FileNotFoundError(f"No LDAP CSV snapshots found in {ldap_dir}")

    users: dict[str, dict[str, Any]] = {}
    user_observations: dict[str, list[datetime]] = {}
    device_observations: dict[str, list[datetime]] = {}
    device_users: dict[str, set[str]] = {}

    for snapshot in ldap_files:
        month = snapshot.stem
        try:
            snapshot_time = datetime.strptime(month, "%Y-%m")
        except ValueError as error:
            raise ValueError(
                f"LDAP snapshot filename must use YYYY-MM.csv: {snapshot}"
            ) from error
        snapshot_time = snapshot_time.replace(day=1)
        for line_number, row in iter_csv_rows(snapshot, LDAP_COLUMNS):
            username = required_value(
                row, "user_id", path=snapshot, line_number=line_number
            )
            user = users.setdefault(
                username,
                {
                    "username": username,
                    "email": None,
                    "employee_name": None,
                    "department": None,
                    "role": None,
                    "manager": None,
                    "business_unit": None,
                    "functional_unit": None,
                    "team": None,
                    "first_seen": snapshot_time,
                    "last_seen": snapshot_time,
                },
            )
            user["email"] = row.get("email") or None
            user["employee_name"] = row.get("employee_name") or None
            user["department"] = row.get("department") or None
            user["role"] = row.get("role") or None
            user["manager"] = row.get("supervisor") or None
            user["business_unit"] = row.get("business_unit") or None
            user["functional_unit"] = row.get("functional_unit") or None
            user["team"] = row.get("team") or None
            user["first_seen"] = min(user["first_seen"], snapshot_time)
            user["last_seen"] = max(user["last_seen"], snapshot_time)

    for log_name in REGISTRY_LOGS:
        log_path = cert_root / log_name
        if not log_path.is_file():
            raise FileNotFoundError(f"Required CERT log not found: {log_path}")
        for line_number, row in iter_csv_rows(log_path, LOG_COLUMNS):
            username = required_value(
                row, "user", path=log_path, line_number=line_number
            )
            hostname = required_value(
                row, "pc", path=log_path, line_number=line_number
            )
            raw_timestamp = required_value(
                row, "date", path=log_path, line_number=line_number
            )
            event_time = _timestamp(
                raw_timestamp, source=f"{log_path}:{line_number}"
            )

            user = users.setdefault(
                username,
                {
                    "username": username,
                    "email": None,
                    "employee_name": None,
                    "department": None,
                    "role": None,
                    "manager": None,
                    "business_unit": None,
                    "functional_unit": None,
                    "team": None,
                    "first_seen": event_time,
                    "last_seen": event_time,
                },
            )
            user_observations.setdefault(username, []).append(event_time)
            device_observations.setdefault(hostname, []).append(event_time)
            device_users.setdefault(hostname, set()).add(username)

    user_ids = {
        username: f"USR{index:04d}"
        for index, username in enumerate(
            sorted(users, key=lambda value: (value.casefold(), value)), start=1
        )
    }
    device_ids = {
        hostname: f"DEV{index:04d}"
        for index, hostname in enumerate(
            sorted(device_observations, key=lambda value: (value.casefold(), value)),
            start=1,
        )
    }

    user_records: list[dict[str, Any]] = []
    for username in sorted(user_ids, key=lambda value: user_ids[value]):
        user = users[username]
        observations = user_observations.get(username, [])
        first_seen = min([user["first_seen"], *observations])
        last_seen = max([user["last_seen"], *observations])
        observed_devices = sorted(
            (
                device_ids[hostname]
                for hostname, assigned_users in device_users.items()
                if username in assigned_users
            )
        )
        user_records.append(
            {
                "user_id": user_ids[username],
                "username": username,
                "email": user["email"],
                "employee_name": user["employee_name"],
                "department": user["department"],
                "role": user["role"],
                "manager": user["manager"],
                "business_unit": user["business_unit"],
                "functional_unit": user["functional_unit"],
                "team": user["team"],
                "first_seen": _iso_timestamp(first_seen),
                "last_seen": _iso_timestamp(last_seen),
                "device_ids": observed_devices,
            }
        )

    device_records: list[dict[str, Any]] = []
    for hostname in sorted(device_ids, key=lambda value: device_ids[value]):
        assigned_users = sorted(
            user_ids[username] for username in device_users[hostname]
        )
        observations = device_observations[hostname]
        device_records.append(
            {
                "device_id": device_ids[hostname],
                "hostname": hostname,
                "assigned_user": assigned_users[0] if len(assigned_users) == 1 else None,
                "assigned_users": assigned_users,
                "first_seen": _iso_timestamp(min(observations)),
                "last_seen": _iso_timestamp(max(observations)),
                "assignment_source": "observed CERT user/PC associations",
            }
        )

    _atomic_write_json(processed_dir / "users.json", user_records)
    _atomic_write_json(processed_dir / "devices.json", device_records)
    return user_ids, device_ids


def main() -> None:
    """Build registries using paths relative to the Cerberus project root."""
    project_root = Path(__file__).resolve().parents[2]
    user_ids, device_ids = build_registries(
        project_root / "data" / "raw" / "cert",
        project_root / "data" / "processed",
    )
    print(
        f"Wrote {len(user_ids)} users and {len(device_ids)} devices to "
        f"{project_root / 'data' / 'processed'}"
    )


if __name__ == "__main__":
    main()
