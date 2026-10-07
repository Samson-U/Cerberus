"""Build CERT registries and the normalized event store."""

import argparse
from pathlib import Path

from .device_parser import parse_device
from .event_merger import write_normalized_events
from .file_parser import parse_file
from .logon_parser import parse_logon
from .registry_builder import build_registries


def build_outputs(project_root: Path) -> int:
    """Generate user/device registries and all normalized CERT events."""
    project_root = project_root.resolve()
    cert_root = project_root / "data" / "raw" / "cert"
    processed_dir = project_root / "data" / "processed"
    user_ids, device_ids = build_registries(cert_root, processed_dir)

    event_count = write_normalized_events(
        (
            parse_logon(cert_root / "logon.csv", user_ids, device_ids),
            parse_file(cert_root / "file.csv", user_ids, device_ids),
            parse_device(cert_root / "device.csv", user_ids, device_ids),
        ),
        project_root / "data" / "normalized" / "normalized_events.json",
    )
    return event_count


def main() -> None:
    """Run the CERT normalization pipeline from the command line."""
    default_root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(
        description="Build CERT registries and normalized events."
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=default_root,
        help="Cerberus project root (defaults to the root containing this parser).",
    )
    arguments = parser.parse_args()
    count = build_outputs(arguments.project_root)
    print(
        f"Wrote users.json, devices.json, and {count} events under "
        f"{arguments.project_root.resolve() / 'data'}"
    )


if __name__ == "__main__":
    main()
