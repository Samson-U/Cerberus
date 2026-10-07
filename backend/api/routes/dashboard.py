"""Dashboard endpoints."""

from fastapi import APIRouter

from backend.api.data import dashboard_data

router = APIRouter(tags=["dashboard"])


@router.get("/dashboard")
def get_dashboard() -> dict:
    return dashboard_data()
