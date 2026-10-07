"""Investigation graph endpoint."""

from fastapi import APIRouter

from backend.api.data import get_incident, graph_for

router = APIRouter(tags=["graph"])


@router.get("/investigations/{incident_id}/graph")
def investigation_graph(incident_id: str) -> dict:
    return graph_for(get_incident(incident_id))
