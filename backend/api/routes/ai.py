"""Evidence-grounded investigation analysis endpoint."""

from fastapi import APIRouter

from backend.api.data import ai_analysis, get_incident

router = APIRouter(tags=["ai"])


@router.post("/investigations/{incident_id}/ai-analysis")
def investigation_ai_analysis(incident_id: str) -> dict:
    return ai_analysis(get_incident(incident_id))
