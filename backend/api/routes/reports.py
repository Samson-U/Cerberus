"""Report listing, retrieval and generation endpoints."""

from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException

from backend.api import data
from backend.api.data import (
    ai_analysis,
    entities_for,
    evidence_for,
    get_incident,
    report_records,
    save_report,
)

router = APIRouter(tags=["reports"])


@router.get("/reports")
def list_reports() -> list[dict]:
    return report_records()


@router.get("/reports/{report_id}")
def get_report(report_id: str) -> dict:
    for report in report_records():
        if report.get("id") == report_id:
            return report
    raise HTTPException(status_code=404, detail=f"Report {report_id} was not found")


@router.post("/investigations/{incident_id}/generate-report")
def generate_report(incident_id: str) -> dict:
    incident = get_incident(incident_id)
    reports = report_records()
    report_id = f"SIMRPT-{len(reports) + 1:06d}"
    analysis = ai_analysis(incident)
    timeline = evidence_for(incident)
    report = {
        "id": report_id,
        "investigation_id": incident["incident_id"],
        "title": f"{incident['title']} report",
        "attack_type": incident["attack_type"],
        "severity": incident["risk_level"].title(),
        "confidence": incident["confidence"],
        "risk_score": incident["risk_score"],
        "status": "Final",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "executive_summary": analysis["summary"],
        "overall_analysis": incident.get("summary", analysis["summary"]),
        "timeline": timeline,
        "entities": entities_for(incident),
        "evidence": [
            {
                **event,
                "evidence_id": f"EVD-{event['event_id']}",
                "investigation_id": incident["incident_id"],
                "stage": next(
                    (
                        stage["stage"]
                        for stage in incident.get("stage_records", [])
                        if event["event_id"] in stage.get("evidence", [])
                    ),
                    "Investigation",
                ),
                "verification_status": "Verified",
            }
            for event in timeline
        ],
        "ai_assessment": analysis["summary"],
        "recommendations": analysis["recommendations"],
        "evidence_references": analysis["evidence_references"],
    }
    save_report(report)
    return report
