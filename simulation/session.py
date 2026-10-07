"""Persistent simulation-session metadata and runtime artifact lifecycle."""

from __future__ import annotations

import json
import os
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RUNTIME = PROJECT_ROOT / "data" / "runtime"
SESSION_FILE = RUNTIME / "session.json"
RUNTIME_ARTIFACTS = (
    "simulated_events.json",
    "simulated_stages.json",
    "simulated_chains.json",
    "simulated_incidents.json",
    "simulated_timelines.json",
    "simulated_reports.json",
    "investigation_status.json",
    ".simulated_events.json.simulation-journal",
)


def current_session() -> dict[str, Any]:
    """Return active persisted session metadata, or an empty session state."""
    if not SESSION_FILE.is_file():
        return {}
    with SESSION_FILE.open(encoding="utf-8") as source:
        value = json.load(source)
    if not isinstance(value, dict):
        raise ValueError(f"{SESSION_FILE} must contain a JSON object")
    return value


def create_session() -> dict[str, Any]:
    """Start a clean runtime data set and persist a unique session identity."""
    RUNTIME.mkdir(parents=True, exist_ok=True)
    for filename in RUNTIME_ARTIFACTS:
        path = RUNTIME / filename
        if path.exists():
            path.unlink()
    session = {
        "active_session_id": f"SIMSESSION-{uuid.uuid4().hex[:12].upper()}",
        "simulation_start_timestamp": datetime.now(timezone.utc).isoformat(
            timespec="seconds"
        ),
        "running": True,
    }
    _atomic_write(SESSION_FILE, session)
    return session


def stop_session() -> dict[str, Any]:
    """Mark the current session stopped while preserving its generated records."""
    session = current_session()
    if session:
        session["running"] = False
        _atomic_write(SESSION_FILE, session)
    return session


def reset_session() -> None:
    """Delete only known simulator-owned runtime artifacts."""
    for filename in (*RUNTIME_ARTIFACTS, SESSION_FILE.name):
        path = RUNTIME / filename
        if path.exists():
            path.unlink()


def _atomic_write(path: Path, value: object) -> None:
    """Persist session metadata atomically in its runtime directory."""
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            newline="\n",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as output:
            temporary = Path(output.name)
            json.dump(value, output, ensure_ascii=False, separators=(",", ":"))
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()
