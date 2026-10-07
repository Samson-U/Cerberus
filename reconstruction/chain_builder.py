"""Reconstruct evidence-backed attack chains from detected stages."""

import argparse
import csv
import hashlib
import json
import os
import tempfile
from collections import defaultdict
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from schemas.attack_schema import AttackChain, AttackEvidence, AttackStage

from .rules.common import iter_json_array

ATTACK_PATTERNS: dict[str, tuple[str, ...]] = {
    "INSIDER_DATA_THEFT": ("COLLECTION", "EXFILTRATION"),
    "COMPROMISED_USER_DATA_THEFT": (
        "INITIAL_ACCESS",
        "COLLECTION",
        "EXFILTRATION",
    ),
    "MALWARE_INFECTION": ("MALWARE_INFECTION",),
    "LATERAL_MOVEMENT": ("LATERAL_MOVEMENT",),
}
STAGE_RISK_POINTS = {
    "COLLECTION": 40,
    "EXFILTRATION": 50,
    "MALWARE_INFECTION": 70,
    "LATERAL_MOVEMENT": 65,
}
FILE_COUNT_BONUS_THRESHOLD = 100
FILE_COUNT_BONUS = 10
RISK_LEVELS = ((90, "CRITICAL"), (70, "HIGH"), (40, "MEDIUM"), (0, "LOW"))


def _parse_iso(value: str, *, field_name: str, stage_id: str) -> datetime:
    """Parse an ISO timestamp and identify malformed stage data clearly."""
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(
            f"Stage {stage_id!r} has invalid {field_name}: {value!r}"
        ) from error


def _load_stages(path: Path) -> list[AttackStage]:
    """Load stage JSON records into the existing AttackStage model."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"{path} must contain a JSON array")

    stages: list[AttackStage] = []
    seen_ids: set[str] = set()
    for index, record in enumerate(data, start=1):
        if not isinstance(record, dict):
            raise ValueError(f"{path}: stage at position {index} is not an object")
        stage_id = record.get("stage_id")
        name = record.get("stage", record.get("name"))
        start_time = record.get("start_time", record.get("started_at"))
        end_time = record.get("end_time", record.get("ended_at"))
        evidence = record.get("evidence", record.get("evidence_ids", []))
        confidence = record.get("confidence", 1.0)
        risk_score = record.get("risk_score", confidence)
        if not isinstance(stage_id, str) or not stage_id:
            raise ValueError(f"{path}: stage at position {index} has no stage_id")
        if stage_id in seen_ids:
            raise ValueError(f"{path}: duplicate stage_id {stage_id!r}")
        seen_ids.add(stage_id)
        if not isinstance(name, str) or not name:
            raise ValueError(f"{path}: stage {stage_id!r} has no stage/name")
        if not isinstance(start_time, str) or not isinstance(end_time, str):
            raise ValueError(f"{path}: stage {stage_id!r} has no time bounds")
        start = _parse_iso(start_time, field_name="start_time", stage_id=stage_id)
        end = _parse_iso(end_time, field_name="end_time", stage_id=stage_id)
        if end < start:
            raise ValueError(f"{path}: stage {stage_id!r} ends before it starts")
        if not isinstance(evidence, list) or not all(
            isinstance(item, str) and item for item in evidence
        ):
            raise ValueError(f"{path}: stage {stage_id!r} has malformed evidence")
        if not evidence:
            raise ValueError(f"{path}: stage {stage_id!r} has no evidence")
        if not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
            raise ValueError(f"{path}: stage {stage_id!r} has invalid confidence")

        metadata = record.get("metadata", {})
        if not isinstance(metadata, dict):
            raise ValueError(f"{path}: stage {stage_id!r} metadata is not an object")
        file_count = record.get("file_count", metadata.get("distinct_file_count"))
        if file_count is not None and (
            not isinstance(file_count, int) or file_count < 0
        ):
            raise ValueError(f"{path}: stage {stage_id!r} has invalid file_count")
        stages.append(
            AttackStage(
                stage_id=stage_id,
                name=name,
                classification=str(record.get("classification", name)),
                description=str(record.get("description", "")),
                started_at=start_time,
                ended_at=end_time,
                risk_score=float(risk_score),
                confidence=float(confidence),
                evidence_ids=evidence,
                user_id=record.get("user_id"),
                device_id=record.get("device_id"),
                file_count=file_count,
                metadata=metadata,
            )
        )
    return stages


def _risk_score(stages: list[AttackStage]) -> int:
    """Calculate the documented bounded chain-level risk score."""
    score = sum(STAGE_RISK_POINTS.get(stage.name, 0) for stage in stages)
    if max((stage.file_count or 0 for stage in stages), default=0) > FILE_COUNT_BONUS_THRESHOLD:
        score += FILE_COUNT_BONUS
    return min(100, score)


def _risk_level(score: int) -> str:
    """Map a numeric score to the documented risk band."""
    for minimum, level in RISK_LEVELS:
        if score >= minimum:
            return level
    return "LOW"


def _validate_http_evidence(project_root: Path, evidence_ids: set[str]) -> None:
    """Verify initial-access references against the raw CERT HTTP source."""
    prefixes = ("CERT-HTTP:",)
    source_ids = {
        evidence_id[len("CERT-HTTP:") :]
        for evidence_id in evidence_ids
        if evidence_id.startswith("CERT-HTTP:")
    }
    unsupported = {
        evidence_id
        for evidence_id in evidence_ids
        if not evidence_id.startswith("EVT") and not evidence_id.startswith(prefixes)
    }
    if unsupported:
        raise ValueError(
            f"Unsupported stage evidence reference: {sorted(unsupported)[:5]}"
        )
    if not source_ids:
        return
    http_path = project_root / "data" / "raw" / "cert" / "http.csv"
    found: set[str] = set()
    with http_path.open("r", encoding="utf-8-sig", errors="replace", newline="") as source:
        reader = csv.DictReader(source)
        if reader.fieldnames is None or "id" not in reader.fieldnames:
            raise ValueError(f"{http_path} has no id column")
        for row in reader:
            source_id = row.get("id")
            if source_id in source_ids:
                found.add(source_id)
                if found == source_ids:
                    break
    missing = source_ids - found
    if missing:
        raise ValueError(
            f"Initial-access evidence references missing HTTP records: "
            f"{sorted(missing)[:5]}"
        )


def _stage_time(stage: AttackStage) -> datetime:
    """Return a parsed start timestamp for stable chronological sorting."""
    if stage.started_at is None:
        raise ValueError(f"Stage {stage.stage_id!r} has no start time")
    return _parse_iso(
        stage.started_at, field_name="start_time", stage_id=stage.stage_id
    )


def _matching_collection(
    exfiltration: AttackStage,
    candidates: list[AttackStage],
) -> AttackStage | None:
    """Find the collection stage whose evidence was carried into exfiltration."""
    exfil_evidence = set(exfiltration.evidence_ids)
    exact_matches = [
        stage
        for stage in candidates
        if stage.name == "COLLECTION"
        and stage.user_id == exfiltration.user_id
        and stage.device_id == exfiltration.device_id
        and set(stage.evidence_ids).issubset(exfil_evidence)
    ]
    if exact_matches:
        return max(exact_matches, key=_stage_time)

    if exfiltration.ended_at is None:
        return None
    exfil_end = _parse_iso(
        exfiltration.ended_at,
        field_name="end_time",
        stage_id=exfiltration.stage_id,
    )
    temporal_matches = [
        stage
        for stage in candidates
        if stage.name == "COLLECTION"
        and stage.user_id == exfiltration.user_id
        and stage.device_id == exfiltration.device_id
        and stage.ended_at is not None
        and _parse_iso(
            stage.ended_at,
            field_name="end_time",
            stage_id=stage.stage_id,
        )
        <= exfil_end
        and (
            exfiltration.started_at is None
            or _parse_iso(
                stage.ended_at,
                field_name="end_time",
                stage_id=stage.stage_id,
            )
            <= _parse_iso(
                exfiltration.started_at,
                field_name="start_time",
                stage_id=exfiltration.stage_id,
            )
        )
    ]
    return max(temporal_matches, key=_stage_time) if temporal_matches else None


def _pattern_stages(
    group: list[AttackStage],
) -> list[tuple[str, list[AttackStage]]]:
    """Recognize declared chain patterns from chronological stage evidence."""
    ordered = sorted(
        group,
        key=lambda stage: (
            _stage_time(stage),
            stage.name,
            stage.stage_id,
        ),
    )
    collections = [stage for stage in ordered if stage.name == "COLLECTION"]
    initial_access = [stage for stage in ordered if stage.name == "INITIAL_ACCESS"]
    exfiltrations = [stage for stage in ordered if stage.name == "EXFILTRATION"]
    matches: list[tuple[str, list[AttackStage]]] = []
    for exfiltration in exfiltrations:
        collection = _matching_collection(exfiltration, collections)
        if collection is None:
            continue
        initial_candidates = [
            stage for stage in initial_access if _stage_time(stage) <= _stage_time(collection)
        ]
        initial = max(initial_candidates, key=_stage_time) if initial_candidates else None
        if initial is None:
            pattern_name = "INSIDER_DATA_THEFT"
            pattern = ATTACK_PATTERNS[pattern_name]
            selected = [collection, exfiltration]
        else:
            pattern_name = "COMPROMISED_USER_DATA_THEFT"
            pattern = ATTACK_PATTERNS[pattern_name]
            selected = [initial, collection, exfiltration]
        selected_names = tuple(stage.name for stage in selected)
        if selected_names != pattern:
            raise ValueError(
                f"Pattern {pattern_name} expected {pattern}, found {selected_names}"
            )
        matches.append(
            (
                pattern_name,
                sorted(
                    selected,
                    key=lambda stage: (
                        _stage_time(stage),
                        stage.name,
                        stage.stage_id,
                    ),
                ),
            )
        )
    for attack_type, pattern in ATTACK_PATTERNS.items():
        if len(pattern) != 1:
            continue
        matches.extend(
            (attack_type, [stage])
            for stage in ordered
            if stage.name == pattern[0]
        )
    return matches


def _stable_entity(prefix: str, value: str) -> str:
    """Match the entity linker’s deterministic file/activity ID convention."""
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:20].upper()
    return f"{prefix}-{digest}"


def _build_graph(
    user_id: str,
    device_id: str,
    stages: list[AttackStage],
    event_records: dict[str, dict[str, Any]],
    entity_link_edges: set[tuple[str, str, str]],
) -> dict[str, list[dict[str, str]]]:
    """Build a graph-ready subgraph using observed events and existing links."""
    nodes: dict[str, dict[str, str]] = {
        user_id: {"id": user_id, "type": "User"},
        device_id: {"id": device_id, "type": "Device"},
    }
    edges: set[tuple[str, str, str]] = set()
    stage_evidence = {item for stage in stages for item in stage.evidence_ids}

    for event_id in sorted(stage_evidence):
        event = event_records.get(event_id)
        if event is None:
            continue
        nodes[event_id] = {"id": event_id, "type": "Event"}
        edges.add((user_id, event_id, "PERFORMED"))
        edges.add((device_id, event_id, "OBSERVED_ON"))
        if event.get("event_type") == "FILE_ACCESS":
            metadata = event.get("metadata")
            filename = metadata.get("filename") if isinstance(metadata, dict) else None
            if isinstance(filename, str) and filename:
                file_id = _stable_entity("FILE", filename.casefold())
                nodes[file_id] = {"id": file_id, "type": "File"}
                edges.add((event_id, file_id, "REFERENCES_FILE"))
        elif event.get("event_type") == "MALWARE_EXECUTION":
            metadata = event.get("metadata")
            malware_hash = metadata.get("malware_hash") if isinstance(metadata, dict) else None
            if isinstance(malware_hash, str) and malware_hash:
                malware_id = _stable_entity("MALWARE", malware_hash.casefold())
                nodes[malware_id] = {"id": malware_id, "type": "Malware"}
                edges.add((event_id, malware_id, "EXECUTES"))
        metadata = event.get("metadata")
        target_device = metadata.get("target_device_id") if isinstance(metadata, dict) else None
        if isinstance(target_device, str) and target_device:
            nodes[target_device] = {"id": target_device, "type": "Device"}
            edges.add((device_id, target_device, "LATERAL_MOVEMENT"))
        elif event.get("event_type") in {"USB_INSERT", "USB_REMOVE"}:
            metadata = event.get("metadata")
            record_id = (
                metadata.get("source_record_id") if isinstance(metadata, dict) else None
            )
            if isinstance(record_id, str):
                usb_id = _stable_entity(
                    "USB-ACTIVITY",
                    f"{event.get('source_log', '')}:{record_id}",
                )
                nodes[usb_id] = {"id": usb_id, "type": "USBActivity"}
                edges.add((event_id, usb_id, "REFERENCES_USB_ACTIVITY"))

    for source, target, relationship in entity_link_edges:
        if source in nodes and target in nodes:
            edges.add((source, target, relationship))

    return {
        "nodes": sorted(nodes.values(), key=lambda node: (node["type"], node["id"])),
        "edges": [
            {"source": source, "target": target, "relationship": relationship}
            for source, target, relationship in sorted(edges)
        ],
    }


def build_simulation_attack_chain(
    attack_id: str,
    stages: list[AttackStage],
    event_records: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Build one live chain using the same pattern, risk, and graph helpers."""
    if not stages:
        raise ValueError("A simulated attack chain requires at least one stage")
    user_id = stages[0].user_id
    device_id = stages[0].device_id
    if not user_id or not device_id or any(
        stage.user_id != user_id or stage.device_id != device_id for stage in stages
    ):
        raise ValueError("Simulated chain stages must share user and device IDs")
    matches = _pattern_stages(stages)
    if len(matches) != 1:
        raise ValueError(f"Expected one recognized simulated chain; found {len(matches)}")
    attack_type, chain_stages = matches[0]
    evidence = sorted({
        evidence_id for stage in chain_stages for evidence_id in stage.evidence_ids
    })
    missing = set(evidence) - event_records.keys()
    if missing:
        raise ValueError(f"Simulated chain has missing event evidence: {sorted(missing)}")
    start_time = min(
        (stage.started_at for stage in chain_stages if stage.started_at),
        key=lambda value: _parse_iso(value, field_name="start_time", stage_id=attack_id),
    )
    end_time = max(
        (stage.ended_at for stage in chain_stages if stage.ended_at),
        key=lambda value: _parse_iso(value, field_name="end_time", stage_id=attack_id),
    )
    score = _risk_score(chain_stages)
    evidence_records = [
        AttackEvidence(
            evidence_id=stage.stage_id,
            description=stage.description or stage.classification,
            source_system="Cerberus Simulation",
            source_log=stage.name,
            observed_at=stage.started_at or "",
            event_ids=stage.evidence_ids,
            entity_ids=[user_id, device_id],
            confidence=stage.confidence,
            metadata={"stage": stage.name, "simulation": True},
        )
        for stage in chain_stages
    ]
    chain = AttackChain(
        chain_id=attack_id,
        title=attack_type.replace("_", " ").title(),
        stages=chain_stages,
        evidence=evidence_records,
        risk_score=score,
        confidence=min(stage.confidence for stage in chain_stages),
        summary=f"Simulated {attack_type.replace('_', ' ').lower()} scenario involving {user_id} on {device_id}.",
        attack_type=attack_type,
        user_id=user_id,
        device_id=device_id,
        start_time=start_time,
        end_time=end_time,
        stage_ids=[stage.stage_id for stage in chain_stages],
        graph=_build_graph(user_id, device_id, chain_stages, event_records, set()),
    )
    record = asdict(chain)
    record.update({
        "attack_id": attack_id,
        "stages": [stage.name for stage in chain_stages],
        "stage_ids": [stage.stage_id for stage in chain_stages],
        "evidence": evidence,
        "evidence_records": [asdict(item) for item in evidence_records],
        "risk_level": _risk_level(score),
        "confidence": chain.confidence,
        "simulation": True,
    })
    _validate_chains(
        [record],
        event_records,
        {stage.stage_id: stage for stage in chain_stages},
        first_index=int(attack_id.removeprefix("ATTK")),
    )
    return record


def _atomic_write_json(path: Path, records: object) -> None:
    """Atomically serialize an output JSON file."""
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


def build_attack_chains(project_root: Path) -> list[dict[str, Any]]:
    """Reconstruct recognized attack patterns and write attack_chains.json."""
    root = project_root.resolve()
    processed = root / "data" / "processed"
    normalized_path = root / "data" / "normalized" / "normalized_events.json"
    stages_path = processed / "detected_stages.json"
    stages = _load_stages(stages_path)

    groups: dict[tuple[str, str], list[AttackStage]] = defaultdict(list)
    users_path = processed / "users.json"
    devices_path = processed / "devices.json"
    users_data = json.loads(users_path.read_text(encoding="utf-8"))
    devices_data = json.loads(devices_path.read_text(encoding="utf-8"))
    user_ids = {record.get("user_id") for record in users_data}
    device_ids = {record.get("device_id") for record in devices_data}
    for stage in stages:
        if not stage.user_id or not stage.device_id:
            raise ValueError(
                f"Stage {stage.stage_id!r} cannot be grouped without user/device IDs"
            )
        if stage.user_id not in user_ids or stage.device_id not in device_ids:
            raise ValueError(
                f"Stage {stage.stage_id!r} references a missing registry entity"
            )
        groups[(stage.user_id, stage.device_id)].append(stage)

    recognized: list[tuple[str, str, str, list[AttackStage]]] = []
    for (user_id, device_id), group in sorted(groups.items()):
        for attack_type, chain_stages in _pattern_stages(group):
            recognized.append((user_id, device_id, attack_type, chain_stages))
    evidence_ids = {
        evidence_id
        for _, _, _, chain_stages in recognized
        for stage in chain_stages
        for evidence_id in stage.evidence_ids
        if evidence_id.startswith("EVT")
    }
    all_evidence_ids = {
        evidence_id
        for _, _, _, chain_stages in recognized
        for stage in chain_stages
        for evidence_id in stage.evidence_ids
    }
    _validate_http_evidence(root, all_evidence_ids)
    event_records: dict[str, dict[str, Any]] = {}
    missing_event_ids = set(evidence_ids)
    for event in iter_json_array(normalized_path):
        event_id = event.get("event_id")
        if event_id in evidence_ids:
            event_records[event_id] = event
            missing_event_ids.discard(event_id)
    if missing_event_ids:
        sample = ", ".join(sorted(missing_event_ids)[:5])
        raise ValueError(f"Stage evidence references missing normalized events: {sample}")

    entity_links_path = processed / "entity_links.json"
    relevant_entity_ids = {
        entity_id
        for _, _, _, chain_stages in recognized
        for entity_id in (
            chain_stages[0].user_id,
            chain_stages[0].device_id,
        )
        if entity_id
    }
    for event in event_records.values():
        if event.get("event_type") == "FILE_ACCESS":
            metadata = event.get("metadata")
            filename = metadata.get("filename") if isinstance(metadata, dict) else None
            if isinstance(filename, str) and filename:
                relevant_entity_ids.add(_stable_entity("FILE", filename.casefold()))
        elif event.get("event_type") in {"USB_INSERT", "USB_REMOVE"}:
            metadata = event.get("metadata")
            record_id = (
                metadata.get("source_record_id") if isinstance(metadata, dict) else None
            )
            if isinstance(record_id, str):
                relevant_entity_ids.add(
                    _stable_entity(
                        "USB-ACTIVITY",
                        f"{event.get('source_log', '')}:{record_id}",
                    )
                )
    entity_link_edges: set[tuple[str, str, str]] = set()
    if entity_links_path.is_file():
        for link in iter_json_array(entity_links_path):
            source = link.get("source_entity")
            target = link.get("target_entity")
            relationship = link.get("relationship")
            if (
                isinstance(source, str)
                and isinstance(target, str)
                and isinstance(relationship, str)
                and source in relevant_entity_ids
                and target in relevant_entity_ids
            ):
                entity_link_edges.add((source, target, relationship))

    chains: list[AttackChain] = []
    serialized: list[dict[str, Any]] = []
    for index, (user_id, device_id, attack_type, chain_stages) in enumerate(
        sorted(
            recognized,
            key=lambda item: (
                _stage_time(item[3][0]),
                item[0],
                item[1],
                item[2],
                item[3][-1].stage_id,
            ),
        ),
        start=1,
    ):
        evidence = sorted(
            {
                evidence_id
                for stage in chain_stages
                for evidence_id in stage.evidence_ids
            }
        )
        start_time = min(
            (stage.started_at for stage in chain_stages if stage.started_at),
            key=lambda value: _parse_iso(
                value,
                field_name="start_time",
                stage_id=chain_stages[0].stage_id,
            ),
        )
        end_time = max(
            (stage.ended_at for stage in chain_stages if stage.ended_at),
            key=lambda value: _parse_iso(
                value,
                field_name="end_time",
                stage_id=chain_stages[-1].stage_id,
            ),
        )
        score = _risk_score(chain_stages)
        attack_id = f"ATTK{index:06d}"
        evidence_records = [
            AttackEvidence(
                evidence_id=stage.stage_id,
                description=stage.description or stage.classification,
                source_system="CERT",
                source_log=stage.name,
                observed_at=stage.started_at or "",
                event_ids=stage.evidence_ids,
                entity_ids=[user_id, device_id],
                confidence=stage.confidence,
                metadata={
                    "stage": stage.name,
                    "classification": stage.classification,
                },
            )
            for stage in chain_stages
        ]
        graph = _build_graph(
            user_id,
            device_id,
            chain_stages,
            event_records,
            entity_link_edges,
        )
        chain = AttackChain(
            chain_id=attack_id,
            title=attack_type.replace("_", " ").title(),
            stages=chain_stages,
            evidence=evidence_records,
            risk_score=score,
            confidence=min(stage.confidence for stage in chain_stages),
            summary=(
                f"{attack_type.replace('_', ' ').title()} involving {user_id} "
                f"on {device_id}, with {len(chain_stages)} detected stages."
            ),
            attack_type=attack_type,
            user_id=user_id,
            device_id=device_id,
            start_time=start_time,
            end_time=end_time,
            stage_ids=[stage.stage_id for stage in chain_stages],
            graph=graph,
        )
        record = asdict(chain)
        record["attack_id"] = record.pop("chain_id")
        record["stages"] = [stage.name for stage in chain_stages]
        record["stage_ids"] = [stage.stage_id for stage in chain_stages]
        record["evidence"] = evidence
        record["evidence_records"] = [asdict(item) for item in evidence_records]
        record["risk_level"] = _risk_level(score)
        record["confidence"] = chain.confidence
        chains.append(chain)
        serialized.append(record)

    _validate_chains(
        serialized,
        event_records,
        {stage.stage_id: stage for stage in stages},
    )
    _atomic_write_json(processed / "attack_chains.json", serialized if recognized else [])
    return serialized if recognized else []


def _validate_chains(
    chains: list[dict[str, Any]],
    event_records: dict[str, dict[str, Any]],
    stage_lookup: dict[str, AttackStage],
    *,
    first_index: int = 1,
) -> None:
    """Validate generated chain identities, risk bands, order, and evidence."""
    attack_ids: set[str] = set()
    for index, chain in enumerate(chains, start=first_index):
        attack_id = chain["attack_id"]
        if attack_id in attack_ids or attack_id != f"ATTK{index:06d}":
            raise ValueError(f"Attack IDs are duplicated or not sequential: {attack_id}")
        attack_ids.add(attack_id)
        score = chain["risk_score"]
        if not isinstance(score, int) or not 0 <= score <= 100:
            raise ValueError(f"Attack {attack_id} has invalid risk score {score!r}")
        if chain["risk_level"] != _risk_level(score):
            raise ValueError(f"Attack {attack_id} has inconsistent risk level")
        chain_stages = [
            stage_lookup[stage_id] for stage_id in chain["stage_ids"]
        ]
        if [stage.name for stage in chain_stages] != chain["stages"]:
            raise ValueError(f"Attack {attack_id} stage names do not match stage IDs")
        stage_times = [_stage_time(stage) for stage in chain_stages]
        if stage_times != sorted(stage_times):
            raise ValueError(f"Attack {attack_id} stages are not chronological")
        missing = [
            evidence_id
            for evidence_id in chain["evidence"]
            if evidence_id.startswith("EVT") and evidence_id not in event_records
        ]
        if missing:
            raise ValueError(
                f"Attack {attack_id} has missing event evidence: {missing[:5]}"
            )


def main() -> None:
    """Build and summarize attack chains for the project root."""
    parser = argparse.ArgumentParser(description="Build reconstructed attack chains.")
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Cerberus project root.",
    )
    arguments = parser.parse_args()
    chains = build_attack_chains(arguments.project_root)
    type_counts: dict[str, int] = defaultdict(int)
    risk_counts: dict[str, int] = defaultdict(int)
    for chain in chains:
        type_counts[chain["attack_type"]] += 1
        risk_counts[chain["risk_level"]] += 1
    print(f"Reconstructed attacks: {len(chains)}")
    print(f"Attack types: {dict(type_counts)}")
    print(f"Risk levels: {dict(risk_counts)}")
    print(f"Wrote {arguments.project_root.resolve() / 'data/processed/attack_chains.json'}")


if __name__ == "__main__":
    main()
