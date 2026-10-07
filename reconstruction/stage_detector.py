"""Run initial-access, collection, and exfiltration stage detection rules."""

import argparse
import json
import os
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any

from schemas.attack_schema import AttackStage

from .rules.collection import detect_collection
from .rules.exfiltration import detect_exfiltration
from .rules.initial_access import detect_initial_access
from .rules.common import iter_json_array


SIMULATION_STAGE_CONFIDENCE = {
    "COLLECTION": 0.95,
    "EXFILTRATION": 0.92,
    "MALWARE_INFECTION": 0.96,
    "LATERAL_MOVEMENT": 0.93,
}


def detect_simulation_stages(
    events: list[dict[str, Any]],
    *,
    first_stage_number: int,
    include_insider: bool = True,
) -> list[AttackStage]:
    """Apply the existing stage model to a single generated scenario batch."""
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        user_id = event.get("user_id")
        device_id = event.get("device_id")
        if isinstance(user_id, str) and isinstance(device_id, str):
            grouped[(user_id, device_id)].append(event)

    detected: list[AttackStage] = []
    for (user_id, device_id), records in sorted(grouped.items()):
        ordered = sorted(records, key=lambda row: row["timestamp"])
        file_records = [
            row for row in ordered
            if row["event_type"] == "FILE_ACCESS"
            and isinstance(row.get("metadata", {}).get("filename"), str)
        ]
        distinct_files = {
            row["metadata"]["filename"].casefold() for row in file_records
        }
        usb_records = [
            row for row in ordered if row["event_type"] == "USB_INSERT"
        ]
        if include_insider and len(distinct_files) >= 20 and usb_records:
            collection = AttackStage(
                stage_id=f"STG{first_stage_number:06d}",
                name="COLLECTION",
                classification="MASS_FILE_ACCESS",
                description=f"Accessed {len(distinct_files)} distinct files in a generated scenario.",
                started_at=file_records[0]["timestamp"],
                ended_at=file_records[-1]["timestamp"],
                risk_score=SIMULATION_STAGE_CONFIDENCE["COLLECTION"],
                confidence=SIMULATION_STAGE_CONFIDENCE["COLLECTION"],
                evidence_ids=[row["event_id"] for row in file_records],
                user_id=user_id,
                device_id=device_id,
                file_count=len(distinct_files),
                metadata={"distinct_file_count": len(distinct_files), "simulation": True},
            )
            detected.append(collection)
            first_stage_number += 1
            usb = usb_records[0]
            detected.append(
                AttackStage(
                    stage_id=f"STG{first_stage_number:06d}",
                    name="EXFILTRATION",
                    classification="COLLECTION_FOLLOWED_BY_USB",
                    description="A USB device was connected after mass file access.",
                    started_at=usb["timestamp"],
                    ended_at=usb["timestamp"],
                    risk_score=SIMULATION_STAGE_CONFIDENCE["EXFILTRATION"],
                    confidence=SIMULATION_STAGE_CONFIDENCE["EXFILTRATION"],
                    evidence_ids=[usb["event_id"]],
                    user_id=user_id,
                    device_id=device_id,
                    file_count=len(distinct_files),
                    metadata={
                        "usb_event_id": usb["event_id"],
                        "collection_stage_id": collection.stage_id,
                        "simulation": True,
                    },
                )
            )
            first_stage_number += 1

        malware = [
            row for row in ordered
            if row["event_type"] == "MALWARE_EXECUTION"
            and isinstance(row.get("metadata", {}).get("malware_hash"), str)
        ]
        if malware:
            evidence = [
                row for row in ordered
                if row["event_type"] in {"FILE_DOWNLOAD", "MALWARE_EXECUTION"}
            ]
            detected.append(
                AttackStage(
                    stage_id=f"STG{first_stage_number:06d}",
                    name="MALWARE_INFECTION",
                    classification="MALWARE_EXECUTION",
                    description="A downloaded file was executed and matched a malware indicator.",
                    started_at=evidence[0]["timestamp"],
                    ended_at=evidence[-1]["timestamp"],
                    risk_score=SIMULATION_STAGE_CONFIDENCE["MALWARE_INFECTION"],
                    confidence=SIMULATION_STAGE_CONFIDENCE["MALWARE_INFECTION"],
                    evidence_ids=[row["event_id"] for row in evidence],
                    user_id=user_id,
                    device_id=device_id,
                    metadata={"simulation": True},
                )
            )
            first_stage_number += 1

        remote_logons = [
            row for row in ordered
            if row["event_type"] == "REMOTE_LOGON"
            and isinstance(row.get("metadata", {}).get("target_device_id"), str)
        ]
        if remote_logons:
            evidence = [
                row for row in ordered
                if row["event_type"] in {"REMOTE_LOGON", "NETWORK_CONNECTION"}
            ]
            detected.append(
                AttackStage(
                    stage_id=f"STG{first_stage_number:06d}",
                    name="LATERAL_MOVEMENT",
                    classification="REMOTE_DEVICE_ACCESS",
                    description="The user authenticated to another enterprise device.",
                    started_at=evidence[0]["timestamp"],
                    ended_at=evidence[-1]["timestamp"],
                    risk_score=SIMULATION_STAGE_CONFIDENCE["LATERAL_MOVEMENT"],
                    confidence=SIMULATION_STAGE_CONFIDENCE["LATERAL_MOVEMENT"],
                    evidence_ids=[row["event_id"] for row in evidence],
                    user_id=user_id,
                    device_id=device_id,
                    metadata={"simulation": True},
                )
            )
            first_stage_number += 1

    return detected


def _detect_persisted_simulation_stages(
    events_path: Path,
    *,
    first_stage_number: int,
) -> list[AttackStage]:
    """Detect specialized stages from persisted simulation scenario batches."""
    batches: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in iter_json_array(events_path):
        if event.get("source_system") != "Cerberus Simulation":
            continue
        correlation_id = event.get("correlation_id")
        if isinstance(correlation_id, str) and correlation_id:
            batches[correlation_id].append(event)

    stages: list[AttackStage] = []
    for correlation_id, batch in sorted(
        batches.items(),
        key=lambda item: min(str(event["timestamp"]) for event in item[1]),
    ):
        detected = detect_simulation_stages(
            batch,
            first_stage_number=first_stage_number,
            include_insider=False,
        )
        stages.extend(detected)
        first_stage_number += len(detected)
    return stages


def _write_stages(stages: list[AttackStage], output_path: Path) -> None:
    """Write stage records atomically as the requested JSON collection."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
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
            records = []
            for stage in stages:
                record = {
                    "stage_id": stage.stage_id,
                    "stage": stage.name,
                    "user_id": stage.user_id,
                    "device_id": stage.device_id,
                    "start_time": stage.started_at,
                    "end_time": stage.ended_at,
                    "confidence": stage.confidence,
                    "evidence": stage.evidence_ids,
                    "classification": stage.classification,
                    "description": stage.description,
                    "risk_score": stage.risk_score,
                    "metadata": stage.metadata,
                }
                if stage.file_count is not None:
                    record["file_count"] = stage.file_count
                records.append(record)
            json.dump(
                records,
                output,
                ensure_ascii=False,
                separators=(",", ":"),
            )
            output.write("\n")
        os.replace(temporary_path, output_path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()


def detect_stages(
    project_root: Path,
    *,
    include_initial_access: bool = True,
) -> list[AttackStage]:
    """Run stage rules over the project datasets and assign stable stage IDs."""
    root = project_root.resolve()
    events_path = root / "data" / "normalized" / "normalized_events.json"
    stages: list[AttackStage] = []

    if include_initial_access:
        stages.extend(
            detect_initial_access(
                root / "data" / "raw" / "phishing" / "PhiUSIIL_Phishing_URL_Dataset.csv",
                root / "data" / "raw" / "cert" / "http.csv",
            )
        )

    collection_stages = detect_collection(events_path)
    stages.extend(collection_stages)
    stages.extend(detect_exfiltration(events_path, collection_stages))
    stages.extend(
        _detect_persisted_simulation_stages(
            events_path,
            first_stage_number=len(stages) + 1,
        )
    )

    stages.sort(
        key=lambda stage: (
            stage.started_at or "",
            stage.name,
            stage.user_id or "",
            stage.device_id or "",
            stage.evidence_ids[0] if stage.evidence_ids else "",
        )
    )
    for index, stage in enumerate(stages, start=1):
        stage.stage_id = f"STG{index:06d}"

    _write_stages(stages, root / "data" / "processed" / "detected_stages.json")
    return stages


def main() -> None:
    """Execute all Phase 4 stage detection rules from the project root."""
    project_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="Detect initial-access, collection, and exfiltration stages."
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=project_root,
        help="Cerberus project root (defaults to the root containing this package).",
    )
    parser.add_argument(
        "--skip-initial-access",
        action="store_true",
        help="Skip the full CERT HTTP-to-phishing-URL join.",
    )
    arguments = parser.parse_args()
    stages = detect_stages(
        arguments.project_root,
        include_initial_access=not arguments.skip_initial_access,
    )
    counts: dict[str, int] = {}
    for stage in stages:
        counts[stage.name] = counts.get(stage.name, 0) + 1
    print(f"Detected stages: {len(stages)}")
    for name in ("INITIAL_ACCESS", "COLLECTION", "EXFILTRATION"):
        print(f"  {name}: {counts.get(name, 0)}")
    print(
        "Wrote "
        f"{arguments.project_root.resolve() / 'data' / 'processed' / 'detected_stages.json'}"
    )


if __name__ == "__main__":
    main()
