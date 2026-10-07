"""Investigation entity endpoints."""

from fastapi import APIRouter

from backend.api.data import entities_for, get_incident

router = APIRouter(tags=["entities"])


@router.get("/investigations/{incident_id}/entities")
def investigation_entities(incident_id: str) -> list[dict]:
    return entities_for(get_incident(incident_id))
