"""Investigation, evidence, timeline, entity and graph endpoints."""

from fastapi import APIRouter
from pydantic import BaseModel

from backend.api.data import (
    entities_for,
    get_incident,
    incidents,
    investigation_summary,
    recommendations_for,
    set_incident_status,
)

router = APIRouter(tags=["investigations"])


class StatusUpdate(BaseModel):
    status: str


@router.get("/investigations")
def list_investigations() -> list[dict]:
    return [investigation_summary(row) for row in incidents()]


@router.patch("/investigations/{incident_id}/status")
def update_investigation_status(incident_id: str, request: StatusUpdate) -> dict:
    set_incident_status(incident_id, request.status)
    return get_incident(incident_id)


@router.get("/investigations/{incident_id}")
def investigation_detail(incident_id: str) -> dict:
    incident = get_incident(incident_id)
    entities = entities_for(incident)
    return {
        **incident,
        "entities": entities,
        "evidence_count": len(incident.get("evidence", [])),
        "recommendations": recommendations_for(incident),
    }
