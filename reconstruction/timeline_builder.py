"""Build explainable, chronologically ordered timelines for attack chains."""

import argparse
import csv
import json
import os
import tempfile
from collections import defaultdict
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from schemas.attack_schema import AttackEvidence, AttackTimeline
from schemas.event_schema import Event

from .chain_builder import _load_stages
from .rules.common import iso_timestamp, iter_json_array, parse_event_time

EVENT_DESCRIPTIONS: dict[str, str] = {
    "LOGIN_SUCCESS": "User logged into workstation",
    "LOGOUT": "User logged out",
    "FILE_ACCESS": "File accessed",
    "USB_INSERT": "USB device connected",
    "USB_REMOVE": "USB device removed",
    "HTTP_REQUEST": "User visited a URL",
    "URL_VISITED": "User visited a URL",
    "FILE_DOWNLOAD": "File downloaded",
    "MALWARE_EXECUTION": "Potential malware executed",
    "REMOTE_LOGON": "User authenticated to a remote device",
    "NETWORK_CONNECTION": "Network connection established",
    "EMAIL_RECEIVED": "Email received",
}


def _parse_attack_time(value: str, *, attack_id: str, field: str) -> datetime:
    """Parse chain ISO timestamps and raise a contextual validation error."""
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(
            f"Attack {attack_id!r} has invalid {field}: {value!r}"
        ) from error


def _load_chains(path: Path) -> list[dict[str, Any]]:
    """Load and validate chain records required by the timeline builder."""
    chains = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(chains, list):
        raise ValueError(f"{path} must contain a JSON array")
    seen: set[str] = set()
    for index, chain in enumerate(chains, start=1):
        if not isinstance(chain, dict):
            raise ValueError(f"{path}: chain at position {index} is not an object")
        attack_id = chain.get("attack_id")
        if not isinstance(attack_id, str) or not attack_id or attack_id in seen:
            raise ValueError(f"{path}: missing or duplicate attack_id at {index}")
        seen.add(attack_id)
        required = ("attack_type", "user_id", "device_id", "risk_score", "evidence")
        if any(key not in chain for key in required):
            raise ValueError(f"{path}: chain {attack_id!r} is missing required fields")
        if not isinstance(chain["evidence"], list) or not all(
            isinstance(item, str) and item for item in chain["evidence"]
        ):
            raise ValueError(f"{path}: chain {attack_id!r} has malformed evidence")
        if not isinstance(chain.get("stage_ids"), list):
            raise ValueError(f"{path}: chain {attack_id!r} has no stage_ids array")
        chain["_start_time"] = _parse_attack_time(
            chain["start_time"], attack_id=attack_id, field="start_time"
        )
        chain["_end_time"] = _parse_attack_time(
            chain["end_time"], attack_id=attack_id, field="end_time"
        )
        if chain["_end_time"] < chain["_start_time"]:
            raise ValueError(f"{path}: chain {attack_id!r} ends before it starts")
    return chains


def _load_http_evidence(
    http_path: Path,
    evidence_ids: set[str],
) -> dict[str, dict[str, str]]:
    """Resolve initial-access references to actual rows in CERT http.csv."""
    raw_ids = {
        evidence_id[len("CERT-HTTP:") :]
        for evidence_id in evidence_ids
        if evidence_id.startswith("CERT-HTTP:")
    }
    unsupported = {
        evidence_id
        for evidence_id in evidence_ids
        if not evidence_id.startswith("EVT") and not evidence_id.startswith("CERT-HTTP:")
    }
    if unsupported:
        raise ValueError(f"Unsupported timeline evidence IDs: {sorted(unsupported)[:5]}")
    if not raw_ids:
        return {}
    found: dict[str, dict[str, str]] = {}
    with http_path.open(
        "r",
        encoding="utf-8-sig",
        errors="replace",
        newline="",
    ) as source:
        reader = csv.DictReader(source)
        required = {"id", "date", "user", "pc", "url"}
        if reader.fieldnames is None or not required.issubset(reader.fieldnames):
            raise ValueError(f"{http_path} lacks required CERT HTTP columns")
        for row in reader:
            source_id = row.get("id")
            if source_id in raw_ids:
                found[f"CERT-HTTP:{source_id}"] = row
                if len(found) == len(raw_ids):
                    break
    missing = {
        f"CERT-HTTP:{source_id}" for source_id in raw_ids
    } - set(found)
    if missing:
        raise ValueError(f"Missing CERT HTTP evidence records: {sorted(missing)[:5]}")
    return found


def _stage_annotations(
    chains: list[dict[str, Any]],
    stages: dict[str, Any],
) -> dict[str, set[str]]:
    """Map evidence references to their actual contributing stage labels."""
    annotations: dict[str, set[str]] = defaultdict(set)
    for chain in chains:
        for stage_id in chain["stage_ids"]:
            stage = stages.get(stage_id)
            if stage is None:
                raise ValueError(
                    f"Attack {chain['attack_id']} references missing stage {stage_id}"
                )
            stage_name = stage.name
            if stage_name == "EXFILTRATION":
                usb_event_id = stage.metadata.get("usb_event_id")
                if isinstance(usb_event_id, str):
                    annotations[usb_event_id].add(stage_name)
                    continue
                matching_collection_ids = {
                    evidence_id
                    for related_stage_id in chain["stage_ids"]
                    if (related_stage := stages.get(related_stage_id)) is not None
                    and related_stage.name == "COLLECTION"
                    for evidence_id in related_stage.evidence_ids
                }
                stage_evidence = set(stage.evidence_ids) - matching_collection_ids
            else:
                stage_evidence = set(stage.evidence_ids)
            for evidence_id in stage_evidence:
                annotations[evidence_id].add(stage_name)
    return annotations


def _event_to_model(record: dict[str, Any]) -> Event:
    """Convert a normalized event dictionary to the existing Event dataclass."""
    try:
        return Event(**record)
    except TypeError as error:
        event_id = record.get("event_id", "<unknown>")
        raise ValueError(
            f"Normalized event {event_id!r} does not match Event schema"
        ) from error


def _describe_event(event_type: str) -> str:
    """Return the centralized analyst-facing description for an event type."""
    return EVENT_DESCRIPTIONS.get(event_type, f"Observed {event_type.replace('_', ' ').lower()}")


def _make_timeline_entry(
    record: dict[str, Any],
    annotations: dict[str, set[str]],
    *,
    raw_http: bool = False,
    is_evidence: bool = False,
) -> dict[str, Any]:
    """Create one analyst-readable timeline item with its full source record."""
    if raw_http:
        event_id = record["evidence_id"]
        timestamp = datetime.strptime(
            record["date"], "%m/%d/%Y %H:%M:%S"
        )
        entry: dict[str, Any] = {
            "event_id": event_id,
            "timestamp": iso_timestamp(timestamp),
            "event": "User visited a URL identified as phishing",
            "source_log": "http.csv",
            "source_record": record["source_record"],
        }
    else:
        event_id = record["event_id"]
        timestamp = parse_event_time(
            record["timestamp"],
            event_id=event_id,
            source=Path("normalized_events.json"),
        )
        entry = {
            "event_id": event_id,
            "timestamp": iso_timestamp(timestamp),
            "event": _describe_event(record["event_type"]),
            "source_log": record.get("source_log"),
            "event_record": record,
        }

    stage_names = sorted(annotations.get(event_id, set()))
    if len(stage_names) == 1:
        entry["stage"] = stage_names[0]
    elif stage_names:
        entry["stage"] = stage_names[0]
        entry["stages"] = stage_names
    entry["is_evidence"] = is_evidence
    return entry


def build_simulation_timeline(
    chain: dict[str, Any],
    stages: list[Any],
    event_records: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Format and validate a live chain timeline without rescanning history."""
    stage_lookup = {stage.stage_id: stage for stage in stages}
    annotations = _stage_annotations([chain], stage_lookup)
    evidence_ids = set(chain["evidence"])
    correlation_ids = {
        record.get("correlation_id")
        for event_id, record in event_records.items()
        if event_id in evidence_ids and isinstance(record.get("correlation_id"), str)
    }
    context_events = [
        record
        for record in event_records.values()
        if record.get("user_id") == chain["user_id"]
        and record.get("device_id") == chain["device_id"]
        and record.get("correlation_id") in correlation_ids
    ]
    entries = [
        _make_timeline_entry(
            record,
            annotations,
            is_evidence=record["event_id"] in evidence_ids,
        )
        for record in context_events
    ]
    entries.sort(key=lambda row: (datetime.fromisoformat(row["timestamp"]), row["event_id"]))
    included_evidence = {
        entry["event_id"] for entry in entries if entry.get("is_evidence")
    }
    if included_evidence != evidence_ids:
        raise ValueError(f"Timeline {chain['attack_id']} is missing event evidence")
    timeline = {
        "attack_id": chain["attack_id"],
        "attack_type": chain["attack_type"],
        "user_id": chain["user_id"],
        "device_id": chain["device_id"],
        "risk_score": chain["risk_score"],
        "risk_level": chain["risk_level"],
        "start_time": chain["start_time"],
        "end_time": chain["end_time"],
        "timeline": entries,
        "evidence_records": chain["evidence_records"],
        "simulation": True,
    }
    _validate_timelines([timeline])
    return timeline


def _atomic_write_json(path: Path, records: object) -> None:
    """Atomically write timeline JSON to its output path."""
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
            json.dump(records, output, ensure_ascii=False, separators=(",", ":"))
            output.write("\n")
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()


def build_attack_timelines(project_root: Path) -> list[dict[str, Any]]:
    """Retrieve evidence/context events and write attack_timelines.json."""
    root = project_root.resolve()
    processed = root / "data" / "processed"
    normalized_path = root / "data" / "normalized" / "normalized_events.json"
    chains = _load_chains(processed / "attack_chains.json")
    if not chains:
        _atomic_write_json(processed / "attack_timelines.json", [])
        return []

    stages_list = _load_stages(processed / "detected_stages.json")
    stages = {stage.stage_id: stage for stage in stages_list}
    annotations = _stage_annotations(chains, stages)
    all_evidence = {item for chain in chains for item in chain["evidence"]}
    event_evidence = {item for item in all_evidence if item.startswith("EVT")}
    missing_evidence = set(event_evidence)
    context_by_attack: dict[str, list[dict[str, Any]]] = defaultdict(list)
    event_records_by_attack: dict[str, list[dict[str, Any]]] = defaultdict(list)

    intervals: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for chain in chains:
        intervals[(chain["user_id"], chain["device_id"])].append(chain)
    for pair_intervals in intervals.values():
        pair_intervals.sort(key=lambda item: item["_start_time"])

    for record in iter_json_array(normalized_path):
        event_id = record.get("event_id")
        if not isinstance(event_id, str):
            raise ValueError(f"{normalized_path} contains an event without event_id")
        is_evidence = event_id in event_evidence
        user_id = record.get("user_id")
        device_id = record.get("device_id")
        timestamp = None
        if not is_evidence and isinstance(user_id, str) and isinstance(device_id, str):
            matching_chains = intervals.get((user_id, device_id), [])
            if matching_chains:
                timestamp = parse_event_time(
                    record.get("timestamp", ""),
                    event_id=event_id,
                    source=normalized_path,
                )
        elif is_evidence:
            timestamp = parse_event_time(
                record.get("timestamp", ""),
                event_id=event_id,
                source=normalized_path,
            )

        if is_evidence:
            missing_evidence.discard(event_id)
        if timestamp is None:
            continue
        for chain in intervals.get((user_id, device_id), []):
            chain_is_evidence = event_id in chain["evidence"]
            if chain_is_evidence or chain["_start_time"] <= timestamp <= chain["_end_time"]:
                context_by_attack[chain["attack_id"]].append(
                    _make_timeline_entry(
                        record,
                        annotations,
                        is_evidence=chain_is_evidence,
                    )
                )
                event_records_by_attack[chain["attack_id"]].append(record)

    if missing_evidence:
        raise ValueError(
            f"Attack chain evidence missing from normalized events: "
            f"{sorted(missing_evidence)[:5]}"
        )

    http_refs = all_evidence - event_evidence
    http_rows = _load_http_evidence(
        root / "data" / "raw" / "cert" / "http.csv",
        http_refs,
    )

    timelines: list[dict[str, Any]] = []
    for chain in chains:
        attack_id = chain["attack_id"]
        entries = context_by_attack.get(attack_id, [])
        for evidence_id in chain["evidence"]:
            if evidence_id.startswith("CERT-HTTP:"):
                row = http_rows[evidence_id]
                entry_record = {
                    "evidence_id": evidence_id,
                    "source_record": row,
                    "date": row["date"],
                }
                entries.append(
                    _make_timeline_entry(
                        entry_record,
                        annotations,
                        raw_http=True,
                        is_evidence=True,
                    )
                )

        entries.sort(
            key=lambda item: (
                datetime.fromisoformat(item["timestamp"]),
                item.get("event_id", ""),
            )
        )
        evidence_set = set(chain["evidence"])
        included_evidence = {
            item["event_id"] for item in entries if item.get("is_evidence")
        } | {
            item["event_id"]
            for item in entries
            if item["event_id"].startswith("CERT-HTTP:")
        }
        missing_for_chain = evidence_set - included_evidence
        if missing_for_chain:
            raise ValueError(
                f"Timeline {attack_id} is missing evidence "
                f"{sorted(missing_for_chain)[:5]}"
            )
        event_models = [
            _event_to_model(record)
            for record in event_records_by_attack.get(attack_id, [])
        ]
        evidence_models = [
            AttackEvidence(
                evidence_id=stage_id,
                description=stages[stage_id].description
                or stages[stage_id].classification,
                source_system="CERT",
                source_log=stages[stage_id].name,
                observed_at=stages[stage_id].started_at or "",
                event_ids=stages[stage_id].evidence_ids,
                entity_ids=[
                    entity_id
                    for entity_id in (
                        stages[stage_id].user_id,
                        stages[stage_id].device_id,
                    )
                    if entity_id
                ],
                confidence=stages[stage_id].confidence,
                metadata={"stage": stages[stage_id].name},
            )
            for stage_id in chain["stage_ids"]
        ]
        timeline_model = AttackTimeline(
            timeline_id=f"TL-{attack_id}",
            chain_id=attack_id,
            events=event_models,
            evidence=evidence_models,
            start_time=chain["start_time"],
            end_time=chain["end_time"],
        )
        timelines.append(
            {
                "attack_id": attack_id,
                "attack_type": chain["attack_type"],
                "user_id": chain["user_id"],
                "device_id": chain["device_id"],
                "risk_score": chain["risk_score"],
                "risk_level": chain["risk_level"],
                "start_time": timeline_model.start_time,
                "end_time": timeline_model.end_time,
                "timeline": entries,
                "evidence_records": [asdict(item) for item in timeline_model.evidence],
            }
        )

    _validate_timelines(timelines)
    _atomic_write_json(processed / "attack_timelines.json", timelines)
    return timelines


def _validate_timelines(timelines: list[dict[str, Any]]) -> None:
    """Verify evidence inclusion, chronological order, and valid annotations."""
    valid_stages = {
        "INITIAL_ACCESS",
        "COLLECTION",
        "EXFILTRATION",
        "MALWARE_INFECTION",
        "LATERAL_MOVEMENT",
    }
    for timeline in timelines:
        attack_id = timeline["attack_id"]
        entries = timeline["timeline"]
        parsed_times = [
            datetime.fromisoformat(entry["timestamp"]) for entry in entries
        ]
        if parsed_times != sorted(parsed_times):
            raise ValueError(f"Timeline {attack_id} is not chronological")
        for entry in entries:
            stage = entry.get("stage")
            stage_names = entry.get("stages", [stage] if stage else [])
            if any(name not in valid_stages for name in stage_names):
                raise ValueError(
                    f"Timeline {attack_id} has invalid stage annotation {stage_names}"
                )
            if entry.get("event_id", "").startswith("EVT") and not isinstance(
                entry.get("event_record"), dict
            ):
                raise ValueError(
                    f"Timeline {attack_id} event {entry['event_id']} has no full record"
                )


def main() -> None:
    """Build attack timelines and print an output summary."""
    parser = argparse.ArgumentParser(description="Build explainable attack timelines.")
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Cerberus project root.",
    )
    arguments = parser.parse_args()
    timelines = build_attack_timelines(arguments.project_root)
    print(f"Generated timelines: {len(timelines)}")
    print(
        f"Wrote {arguments.project_root.resolve() / 'data/processed/attack_timelines.json'}"
    )


if __name__ == "__main__":
    main()
