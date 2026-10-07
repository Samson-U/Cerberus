"""Investigation evidence and chronological timeline endpoints."""

from fastapi import APIRouter

from backend.api.data import EVENT_DESCRIPTIONS, evidence_for, get_incident, timeline_entries

router = APIRouter(tags=["evidence"])


@router.get("/investigations/{incident_id}/timeline")
def investigation_timeline(incident_id: str) -> dict:
    incident = get_incident(incident_id)
    stages_by_event: dict[str, list[str]] = {}
    for stage in sorted(
        incident.get("stage_records", []),
        key=lambda stage: (stage.get("end_time", ""), stage.get("stage_id", "")),
    ):
        for event_id in stage.get("evidence", []):
            stages_by_event.setdefault(event_id, []).append(stage["stage"])
    timeline = []
    for item in timeline_entries(incident):
        event_record = item.get("event_record") or item
        event_id = item.get("event_id") or event_record.get("event_id")
        entry = {
            **event_record,
            **item,
            "event_id": event_id,
            "timestamp": item.get("timestamp", event_record.get("timestamp", "")),
            "event": EVENT_DESCRIPTIONS.get(event_record.get("event_type"))
            or item.get("event")
            or event_record.get("event_type", "Event"),
        }
        if event_id in stages_by_event:
            entry["stages"] = stages_by_event[event_id]
            entry["stage"] = stages_by_event[event_id][-1]
        timeline.append(entry)
    return {"attack_id": incident["incident_id"], "timeline": timeline}


@router.get("/investigations/{incident_id}/evidence")
def investigation_evidence(incident_id: str) -> list[dict]:
    return evidence_for(get_incident(incident_id))
