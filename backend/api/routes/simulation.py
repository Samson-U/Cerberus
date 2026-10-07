"""Simulation lifecycle and bounded live-data endpoints."""

import threading
from typing import Literal

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from backend.api import data
from simulation import session as session_store
from simulation.stream_engine import StreamEngine

router = APIRouter()
engine = StreamEngine(on_update=data.invalidate_simulation_caches)
_session_lock = threading.RLock()


class SimulationStartRequest(BaseModel):
    """Optional controlled playback settings for a new stream."""

    demo_mode: bool = False
    scenario: Literal["INSIDER_THEFT", "MALWARE_INFECTION", "LATERAL_MOVEMENT"] = "INSIDER_THEFT"
    interval_seconds: float = Field(default=5.0, ge=0.25, le=300)


@router.post("/simulation/start")
def start_simulation(request: SimulationStartRequest) -> dict[str, object]:
    """Create a clean isolated session and start its event stream."""
    with _session_lock:
        engine.reset_state()
        try:
            session = session_store.create_session()
            data.clear_runtime_caches()
            engine.start(
                demo_mode=request.demo_mode,
                scenario=request.scenario,
                interval_seconds=request.interval_seconds,
            )
        except RuntimeError as error:
            session_store.reset_session()
            raise HTTPException(status_code=409, detail=str(error)) from error
        except ValueError as error:
            session_store.reset_session()
            raise HTTPException(status_code=422, detail=str(error)) from error
        return _status_payload(session)


@router.post("/simulation/stop")
def stop_simulation() -> dict[str, object]:
    """Stop event generation without removing generated history."""
    with _session_lock:
        engine.stop()
        return _status_payload(session_store.stop_session())


@router.post("/simulation/reset")
def reset_simulation() -> dict[str, object]:
    """Stop generation and remove this demo's runtime-only records."""
    with _session_lock:
        engine.reset_state()
        session_store.reset_session()
        data.clear_runtime_caches()
        status = engine.status()
        return {
            **status,
            "running": False,
            "session_id": None,
            "start_time": None,
        }


@router.get("/events/live")
def get_live_events(limit: int = Query(default=50, ge=1, le=200)) -> dict[str, object]:
    """Return recently appended simulated canonical events."""
    events = data.live_normalized_events(limit)
    return {"items": events, "count": len(events)}


@router.get("/incidents/live")
def get_live_incidents(limit: int = Query(default=50, ge=1, le=200)) -> dict[str, object]:
    """Return recently reconstructed simulation incidents."""
    records = [
        record for record in data.incidents()
        if record.get("simulation") is True
    ][-limit:]
    return {
        "items": [data.investigation_summary(record) for record in records],
        "count": len(records),
    }


@router.get("/simulation/status")
def simulation_status() -> dict[str, object]:
    """Expose persisted session identity and current stream counters."""
    return _status_payload(session_store.current_session())


def _status_payload(session: dict[str, object]) -> dict[str, object]:
    """Combine in-process stream status with persisted session metadata."""
    status = engine.status()
    return {
        **status,
        "session_id": session.get("active_session_id"),
        "start_time": session.get("simulation_start_timestamp"),
    }
