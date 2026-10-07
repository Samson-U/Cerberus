"""Regression coverage for the isolated runtime-only simulation API."""

import json

from backend.api.app import app
from backend.api import data
from backend.api.routes.investigations import list_investigations
from backend.api.routes.reports import list_reports
from backend.api.routes.simulation import get_live_events, get_live_incidents
from backend.api.routes.threats import get_active_threats


def test_required_api_routes_are_registered() -> None:
    paths = app.openapi()["paths"]
    assert "/api/dashboard" in paths
    assert "/api/threats/active" in paths
    assert "/api/investigations/{incident_id}/timeline" in paths
    assert "/api/investigations/{incident_id}/evidence" in paths
    assert "/api/investigations/{incident_id}/entities" in paths
    assert "/api/investigations/{incident_id}/graph" in paths
    assert "/api/investigations/{incident_id}/ai-analysis" in paths
    assert "/api/investigations/{incident_id}/generate-report" in paths
    assert "/api/simulation/start" in paths
    assert "/api/simulation/stop" in paths
    assert "/api/simulation/reset" in paths
    assert "/api/simulation/status" in paths
    assert "/api/events/live" in paths
    assert "/api/incidents/live" in paths


def test_empty_runtime_view_never_falls_back_to_cert_history(tmp_path, monkeypatch) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    monkeypatch.setattr(data, "RUNTIME", runtime)
    monkeypatch.setattr(data, "NORMALIZED_EVENTS", runtime / "simulated_events.json")
    for cached_function in (
        data.incidents,
        data._timelines,
        data._stages,
        data._recent_normalized_events,
        data._status_overrides,
    ):
        cached_function.cache_clear()
    try:
        dashboard = data.dashboard_data()
        threats = get_active_threats(page=1, page_size=25)
        investigations = list_investigations()
        reports = list_reports()
        events = get_live_events(limit=50)
        incidents = get_live_incidents(limit=50)

        assert dashboard["active_threats"] == 0
        assert dashboard["critical_incidents"] == 0
        assert dashboard["events_processed"] == 0
        assert dashboard["recent_events"] == []
        assert dashboard["reconstructed_attacks"] == 0
        assert threats["items"] == []
        assert investigations == []
        assert reports == []
        assert events == {"items": [], "count": 0}
        assert incidents == {"items": [], "count": 0}
    finally:
        for cached_function in (
            data.incidents,
            data._timelines,
            data._stages,
            data._recent_normalized_events,
            data._status_overrides,
        ):
            cached_function.cache_clear()


def test_runtime_artifact_reader_does_not_open_processed_cert_incidents(tmp_path, monkeypatch) -> None:
    runtime = tmp_path / "runtime"
    processed = tmp_path / "processed"
    runtime.mkdir()
    processed.mkdir()
    (processed / "incidents.json").write_text(
        json.dumps([{"incident_id": "HISTORICAL", "attack_type": "CERT"}]),
        encoding="utf-8",
    )
    monkeypatch.setattr(data, "RUNTIME", runtime)
    data.incidents.cache_clear()
    try:
        assert data.incidents() == []
    finally:
        data.incidents.cache_clear()
