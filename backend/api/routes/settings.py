"""Backend capability and data-source settings."""

from fastapi import APIRouter

from backend.api.data import settings_data

router = APIRouter(tags=["settings"])


@router.get("/settings")
def get_settings() -> dict:
    return settings_data()
