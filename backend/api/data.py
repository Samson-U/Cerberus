"""Read and adapt persisted Cerberus pipeline artifacts for API routes."""

from __future__ import annotations

import json
import os
import re
from collections import Counter
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterator

from fastapi import HTTPException

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PROCESSED = PROJECT_ROOT / "data" / "processed"
RUNTIME = PROJECT_ROOT / "data" / "runtime"
NORMALIZED_EVENTS = RUNTIME / "simulated_events.json"
EVENT_DESCRIPTIONS = {
    "LOGIN_SUCCESS": "User logged into workstation",
    "LOGOUT": "User logged out",
    "FILE_ACCESS": "File accessed",
    "USB_INSERT": "USB device connected",
    "USB_REMOVE": "USB device removed",
    "HTTP_VISIT": "URL visited",
}
_runtime_event_count: int | None = None


def read_json(name: str, default: Any = None) -> Any:
    path = PROCESSED / name
    if not path.exists():
        return default
    with path.open(encoding="utf-8") as source:
        return json.load(source)


def read_runtime_json(name: str, default: Any = None) -> Any:
    """Read simulator-owned data, never falling back to CERT historical files."""
    path = RUNTIME / name
    if not path.exists():
        return default
    with path.open(encoding="utf-8") as source:
        return json.load(source)


@lru_cache(maxsize=1)
def _timelines() -> list[dict[str, Any]]:
    return read_runtime_json("simulated_timelines.json", [])


@lru_cache(maxsize=1)
def _stages() -> list[dict[str, Any]]:
    return read_runtime_json("simulated_stages.json", [])


@lru_cache(maxsize=1)
def _users() -> dict[str, dict[str, Any]]:
    return {record["user_id"]: record for record in read_json("users.json", [])}


@lru_cache(maxsize=1)
def _devices() -> dict[str, dict[str, Any]]:
    return {record["device_id"]: record for record in read_json("devices.json", [])}


@lru_cache(maxsize=1)
def incidents() -> list[dict[str, Any]]:
    """Return runtime-only simulated incidents."""
    chains = read_runtime_json("simulated_incidents.json", [])
    timeline_by_key = {
        (
            row.get("user_id"),
            row.get("device_id"),
            row.get("start_time"),
            row.get("end_time"),
        ): row
        for row in _timelines()
    }
    output = []
    for index, chain in enumerate(chains, start=1):
        timeline = timeline_by_key.get(
            (
                chain.get("user_id"),
                chain.get("device_id"),
                chain.get("start_time"),
                chain.get("end_time"),
            )
        )
        attack_id = chain.get("incident_id") or chain.get("attack_id")
        if not attack_id and timeline:
            attack_id = timeline.get("attack_id")
        if not attack_id:
            attack_id = f"ATTK{index:06d}"
        score = max(0, min(100, int(chain.get("risk_score", 0))))
        levels = [(90, "CRITICAL"), (70, "HIGH"), (40, "MEDIUM"), (0, "LOW")]
        risk_level = chain.get("risk_level") or next(name for floor, name in levels if score >= floor)
        start = chain.get("start_time", "")
        end = chain.get("end_time", start)
        duration = _duration(start, end)
        stage_rows = [
            stage
            for stage in _stages()
            if stage.get("stage_id") in chain.get("stage_ids", [])
        ]
        output.append(
            {
                **chain,
                "incident_id": attack_id,
                "attack_id": attack_id,
                "risk_level": risk_level,
                "status": _status_overrides().get(attack_id, chain.get("status", "Active")),
                "title": chain.get("title") or chain.get("attack_type", "Reconstructed attack").replace("_", " ").title(),
                "confidence": float(chain.get("confidence", 0.0)),
                "start_time": start,
                "end_time": end,
                "duration": duration,
                "stage_records": stage_rows,
                "timeline_id": timeline.get("attack_id") if timeline else attack_id,
            }
        )
    return output


@lru_cache(maxsize=1)
def _status_overrides() -> dict[str, str]:
    return read_runtime_json("investigation_status.json", {})


def set_incident_status(incident_id: str, status: str) -> None:
    allowed = {"Active", "Investigating", "Contained", "Completed", "Report Generated", "False Positive"}
    if status not in allowed:
        raise HTTPException(status_code=422, detail=f"Unsupported investigation status: {status}")
    record = get_incident(incident_id)
    overrides = dict(_status_overrides())
    overrides[record["incident_id"]] = status
    path = RUNTIME / "investigation_status.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(overrides, indent=2), encoding="utf-8")
    _status_overrides.cache_clear()
    incidents.cache_clear()


def _duration(start: str, end: str) -> str:
    try:
        seconds = max(0, int((datetime.fromisoformat(end) - datetime.fromisoformat(start)).total_seconds()))
    except (ValueError, TypeError):
        return "Unknown"
    return f"{seconds // 60}m {seconds % 60}s"


def get_incident(incident_id: str) -> dict[str, Any]:
    for record in incidents():
        if incident_id in (record["incident_id"], record.get("attack_id")):
            return record
    raise HTTPException(status_code=404, detail=f"Investigation {incident_id} was not found")


def investigation_summary(record: dict[str, Any]) -> dict[str, Any]:
    entities = entities_for(record)
    user = next((entity["name"] for entity in entities if entity["entity_id"] == record.get("user_id")), None)
    device = next((entity["name"] for entity in entities if entity["entity_id"] == record.get("device_id")), None)
    return {
        "id": record["incident_id"],
        "title": record["title"],
        "attack_type": record["attack_type"],
        "severity": record["risk_level"].title(),
        "risk_score": record["risk_score"],
        "status": record["status"],
        "confidence": record["confidence"],
        "user_id": record.get("user_id"),
        "device_id": record.get("device_id"),
        "user_name": user,
        "device_name": device,
        "start_time": record["start_time"],
        "end_time": record["end_time"],
        "duration": record["duration"],
        "stages": record.get("stages", []),
        "evidence_count": len(record.get("evidence", [])),
    }


def _timeline_for(incident: dict[str, Any]) -> dict[str, Any]:
    for timeline in _timelines():
        if timeline.get("attack_id") == incident.get("timeline_id"):
            return timeline
        if (
            timeline.get("user_id") == incident.get("user_id")
            and timeline.get("device_id") == incident.get("device_id")
            and timeline.get("start_time") == incident.get("start_time")
            and timeline.get("end_time") == incident.get("end_time")
        ):
            return timeline
    return {}


def invalidate_simulation_caches(event_count: int) -> None:
    """Refresh runtime API views and maintain the event count incrementally."""
    global _runtime_event_count
    if event_count < 0:
        raise ValueError("event_count cannot be negative")
    if _runtime_event_count is not None:
        _runtime_event_count += event_count
    incidents.cache_clear()
    _timelines.cache_clear()
    _stages.cache_clear()
    _recent_normalized_events.cache_clear()
    _status_overrides.cache_clear()


def clear_runtime_caches() -> None:
    """Forget state derived from the previous simulation session."""
    global _runtime_event_count
    _runtime_event_count = None
    incidents.cache_clear()
    _timelines.cache_clear()
    _stages.cache_clear()
    _recent_normalized_events.cache_clear()
    _status_overrides.cache_clear()


def timeline_entries(incident: dict[str, Any]) -> list[dict[str, Any]]:
    timeline = _timeline_for(incident)
    entries = timeline.get("timeline", [])
    return sorted(entries, key=lambda item: (item.get("timestamp", ""), item.get("event_id", "")))


def evidence_for(incident: dict[str, Any]) -> list[dict[str, Any]]:
    evidence_ids = set(incident.get("evidence", []))
    if not evidence_ids:
        evidence_ids = {
            event_id
            for stage in incident.get("stage_records", [])
            for event_id in stage.get("evidence", [])
        }
    entries = timeline_entries(incident)
    found: dict[str, dict[str, Any]] = {}
    for item in entries:
        event = item.get("event_record") or item
        event_id = event.get("event_id", item.get("event_id"))
        if event_id in evidence_ids:
            found[event_id] = _canonical_event(event, item.get("event"))
    missing = evidence_ids - found.keys()
    if missing and NORMALIZED_EVENTS.exists():
        for event in iter_normalized_events():
            event_id = event.get("event_id")
            if event_id in missing:
                found[event_id] = _canonical_event(event)
                missing.remove(event_id)
                if not missing:
                    break
    return sorted(found.values(), key=lambda event: (event["timestamp"], event["event_id"]))


def _canonical_event(event: dict[str, Any], description: str | None = None) -> dict[str, Any]:
    timestamp = str(event.get("timestamp", ""))
    try:
        timestamp = datetime.strptime(timestamp, "%m/%d/%Y %H:%M:%S").isoformat()
    except ValueError:
        pass
    return {
        **event,
        "event_id": event.get("event_id", ""),
        "timestamp": timestamp,
        "description": EVENT_DESCRIPTIONS.get(event.get("event_type")) or description or event.get("description") or event.get("event_type", "Event").replace("_", " ").title(),
        "related_entities": event.get("related_entities", []),
        "metadata": event.get("metadata", {}),
    }


def entities_for(incident: dict[str, Any]) -> list[dict[str, Any]]:
    entity_ids = {incident.get("user_id"), incident.get("device_id")}
    graph = incident.get("graph", {})
    entity_ids.update(
        node.get("id")
        for node in graph.get("nodes", [])
        if node.get("type") not in ("Event",)
    )
    users, devices = _users(), _devices()
    output: list[dict[str, Any]] = []
    for entity_id in sorted(item for item in entity_ids if item):
        if entity_id in users:
            user = users[entity_id]
            simulated = incident.get("simulation") is True
            output.append(
                {
                    "entity_id": entity_id,
                    "entity_type": "User",
                    "name": entity_id if simulated else user.get("employee_name") or user.get("username", entity_id),
                    "context": "Observed in simulated event stream" if simulated else user.get("department") or "CERT user registry",
                    "risk": incident["risk_level"].title() if entity_id == incident.get("user_id") else "Low",
                    "related_event_ids": incident.get("evidence", []),
                    "attributes": {} if simulated else user,
                }
            )
        elif entity_id in devices:
            device = devices[entity_id]
            simulated = incident.get("simulation") is True
            output.append(
                {
                    "entity_id": entity_id,
                    "entity_type": "Device",
                    "name": entity_id if simulated else device.get("hostname") or entity_id,
                    "context": "Observed in simulated event stream" if simulated else device.get("assignment_source", "CERT device registry"),
                    "risk": incident["risk_level"].title() if entity_id == incident.get("device_id") else "Low",
                    "related_event_ids": incident.get("evidence", []),
                    "attributes": {} if simulated else device,
                }
            )
        elif entity_id.startswith("FILE-"):
            output.append(
                {
                    "entity_id": entity_id,
                    "entity_type": "File",
                    "name": entity_id,
                    "context": "Observed in attack graph",
                    "risk": incident["risk_level"].title(),
                    "related_event_ids": incident.get("evidence", []),
                    "attributes": {},
                }
            )
        elif any(
            node.get("id") == entity_id and node.get("type") == "USBActivity"
            for node in graph.get("nodes", [])
        ):
            output.append(
                {
                    "entity_id": entity_id,
                    "entity_type": "USBActivity",
                    "name": entity_id,
                    "context": "Observed USB activity in the attack graph",
                    "risk": incident["risk_level"].title(),
                    "related_event_ids": incident.get("evidence", []),
                    "attributes": {},
                }
            )
        elif any(
            node.get("id") == entity_id and node.get("type") == "Malware"
            for node in graph.get("nodes", [])
        ):
            output.append(
                {
                    "entity_id": entity_id,
                    "entity_type": "Malware",
                    "name": entity_id,
                    "context": "Malware indicator observed in the attack graph",
                    "risk": incident["risk_level"].title(),
                    "related_event_ids": incident.get("evidence", []),
                    "attributes": {},
                }
            )
    return output


def graph_for(incident: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    graph = incident.get("graph")
    if graph and isinstance(graph.get("nodes"), list) and isinstance(graph.get("edges"), list):
        return graph
    nodes = [
        {"id": entity["entity_id"], "type": entity["entity_type"]}
        for entity in entities_for(incident)
    ]
    return {"nodes": nodes, "edges": []}


def iter_normalized_events() -> Iterator[dict[str, Any]]:
    """Stream a JSON array to avoid loading the full CERT event store into RAM."""
    if not NORMALIZED_EVENTS.exists():
        return
    decoder = json.JSONDecoder()
    buffer = ""
    with NORMALIZED_EVENTS.open(encoding="utf-8") as source:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk and not buffer.strip():
                return
            buffer += chunk
            cursor = 0
            while cursor < len(buffer):
                while cursor < len(buffer) and buffer[cursor] in " \r\n\t[,]":
                    cursor += 1
                if cursor >= len(buffer):
                    buffer = ""
                    break
                if buffer[cursor] == "]":
                    return
                try:
                    value, end = decoder.raw_decode(buffer, cursor)
                except json.JSONDecodeError:
                    buffer = buffer[cursor:]
                    break
                cursor = end
                if isinstance(value, dict):
                    yield value
            if not chunk:
                return


def dashboard_data() -> dict[str, Any]:
    records = incidents()
    risk_counts = Counter(row["risk_level"] for row in records)
    users: set[str] = set()
    devices: set[str] = set()
    for record in records:
        if record.get("user_id"):
            users.add(record["user_id"])
        if record.get("device_id"):
            devices.add(record["device_id"])
    latest_events = _recent_normalized_events()
    activity_counts: Counter[str] = Counter()
    seen_events: set[str] = set()
    for record in records:
        for entry in timeline_entries(record):
            event = entry.get("event_record") or entry
            event_id = event.get("event_id")
            if event_id and event_id not in seen_events:
                seen_events.add(event_id)
                activity_counts[str(entry.get("timestamp", ""))[:10]] += 1
    events_processed = _normalized_event_count()
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "security_posture": max(0, 100 - round(sum(row["risk_score"] for row in records) / max(len(records), 1))),
        "active_threats": len(records),
        "critical_incidents": risk_counts["CRITICAL"],
        "events_processed": events_processed,
        "suspicious_entities": len(users) + len(devices),
        "reconstructed_attacks": len(records),
        "recent_events": [_canonical_event(row) for row in latest_events],
        "activity_series": [
            {"timestamp": day, "count": activity_counts[day]}
            for day in sorted(activity_counts)[-7:]
        ],
    }


@lru_cache(maxsize=1)
def _recent_normalized_events() -> list[dict[str, Any]]:
    if NORMALIZED_EVENTS.exists():
        latest = _tail_normalized_events(8)
        if latest:
            return latest
    fallback = [
        entry.get("event_record") or entry
        for incident in incidents()
        for entry in timeline_entries(incident)
    ]
    return sorted(fallback, key=lambda row: row.get("timestamp", ""))[-8:]


def _base_normalized_event_count() -> int:
    if not NORMALIZED_EVENTS.exists():
        return 0
    count = 0
    token = b'"event_id":'
    overlap = b""
    with NORMALIZED_EVENTS.open("rb") as source:
        while chunk := source.read(8 * 1024 * 1024):
            data = overlap + chunk
            count += data.count(token)
            overlap = data[-(len(token) - 1) :]
    return count


def _normalized_event_count() -> int:
    """Return the runtime event count, caching and incrementing by batch."""
    global _runtime_event_count
    if _runtime_event_count is None:
        _runtime_event_count = _base_normalized_event_count()
    return _runtime_event_count


def _tail_normalized_events(limit: int) -> list[dict[str, Any]]:
    """Read a bounded number of recent array records without scanning history."""
    if limit <= 0 or not NORMALIZED_EVENTS.exists():
        return []
    decoder = json.JSONDecoder()
    with NORMALIZED_EVENTS.open("rb") as source:
        source.seek(max(0, NORMALIZED_EVENTS.stat().st_size - 2 * 1024 * 1024))
        tail = source.read().decode("utf-8")
    records = []
    for match in re.finditer(r'\{"event_id":', tail):
        try:
            event, _ = decoder.raw_decode(tail, match.start())
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict):
            records.append(event)
    return records[-limit:]


def live_normalized_events(limit: int = 100) -> list[dict[str, Any]]:
    """Return recent runtime events for the live-stream API."""
    bounded_limit = max(1, min(limit, 200))
    return [_canonical_event(event) for event in _tail_normalized_events(bounded_limit)]


def settings_data() -> dict[str, Any]:
    return {
        "api_available": True,
        "ollama_available": _ollama_available(),
        "data_sources": {
            "incidents": "data/runtime/simulated_incidents.json",
            "entities": "simulation entity graph",
            "events": str(NORMALIZED_EVENTS.relative_to(PROJECT_ROOT)) if NORMALIZED_EVENTS.exists() else None,
        },
    }


def _ollama_available() -> bool:
    from urllib.request import urlopen

    url = f"{os.getenv('OLLAMA_URL', 'http://localhost:11434').rstrip('/')}/api/tags"
    try:
        with urlopen(url, timeout=0.5) as response:
            return response.status == 200
    except OSError:
        return False


def report_records() -> list[dict[str, Any]]:
    return read_runtime_json("simulated_reports.json", [])


def save_report(report: dict[str, Any]) -> None:
    reports = report_records()
    reports.append(report)
    path = RUNTIME / "simulated_reports.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(reports, indent=2), encoding="utf-8")
    temporary.replace(path)


def ai_analysis(incident: dict[str, Any]) -> dict[str, Any]:
    evidence = evidence_for(incident)
    stages = incident.get("stages", [])
    summary = (
        f"{incident['title']} was reconstructed from {len(stages)} detected stage(s) "
        f"and {len(evidence)} evidence event(s), with a risk score of {incident['risk_score']}/100."
    )
    fallback = {
        "summary": summary,
        "why_suspicious": [
            f"Detected stages: {', '.join(stages) or 'none'}",
            f"The evidence set contains {len(evidence)} events associated with this chain.",
            f"Reconstruction confidence is {round(float(incident.get('confidence', 0)) * 100)}%.",
        ],
        "recommendations": recommendations_for(incident),
        "evidence_references": [item["event_id"] for item in evidence],
        "provider": "evidence-based",
    }
    if not _ollama_available():
        return fallback
    from urllib.request import Request, urlopen

    model = os.getenv("OLLAMA_MODEL", "llama3.1")
    prompt = (
        "Analyze only the supplied Cerberus incident data. Do not infer facts absent from it. "
        "Return JSON with keys summary, why_suspicious (string list), recommendations (string list). "
        f"Incident: {json.dumps({key: incident.get(key) for key in ('incident_id', 'attack_type', 'risk_score', 'stages', 'evidence')})}"
    )
    request = Request(
        f"{os.getenv('OLLAMA_URL', 'http://localhost:11434').rstrip('/')}/api/generate",
        data=json.dumps({"model": model, "prompt": prompt, "stream": False, "format": "json"}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=30) as response:
            generated = json.loads(response.read().decode()).get("response", "")
        result = json.loads(generated)
        if not isinstance(result.get("summary"), str):
            raise ValueError("Ollama returned no string summary")
        return {
            **fallback,
            "summary": result["summary"],
            "why_suspicious": result.get("why_suspicious", fallback["why_suspicious"]),
            "recommendations": result.get("recommendations", fallback["recommendations"]),
            "provider": f"Ollama ({model})",
        }
    except (OSError, json.JSONDecodeError, ValueError) as error:
        raise HTTPException(status_code=502, detail=f"Ollama analysis failed: {error}") from error


def recommendations_for(incident: dict[str, Any]) -> list[str]:
    stages = set(incident.get("stages", []))
    recommendations = []
    if "COLLECTION" in stages:
        recommendations.append("Review the files and timestamps included in the collection evidence.")
    if "EXFILTRATION" in stages:
        recommendations.append("Validate the associated removable-device activity with the device owner.")
    recommendations.extend(
        [
            "Preserve the source event records referenced by this reconstruction.",
            "Validate the user and device activity with the relevant system owner.",
        ]
    )
    return recommendations
