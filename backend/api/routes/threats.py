"""Active threat queue endpoints."""

from fastapi import APIRouter, Query

from backend.api.data import incidents, investigation_summary

router = APIRouter(tags=["threats"])


@router.get("/threats/active")
def get_active_threats(
    search: str = "",
    severity: str = "",
    status: str = "",
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
) -> dict:
    rows = [
        row
        for row in incidents()
        if row.get("status", "Active").casefold() not in {"completed", "report generated", "false positive"}
    ]
    rows = [investigation_summary(row) for row in rows]
    if search:
        query = search.casefold()
        rows = [
            row
            for row in rows
            if query
            in " ".join(
                str(row.get(key, ""))
                for key in ("id", "incident_id", "title", "attack_type", "user_id", "device_id")
            ).casefold()
        ]
    if severity:
        rows = [row for row in rows if row["severity"].casefold() == severity.casefold()]
    if status:
        rows = [row for row in rows if row["status"].casefold() == status.casefold()]
    total = len(rows)
    start = (page - 1) * page_size
    return {"items": rows[start : start + page_size], "page": page, "page_size": page_size, "total": total}
