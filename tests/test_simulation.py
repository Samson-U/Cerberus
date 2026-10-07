"""Focused regression tests for live scenario generation and reconstruction."""

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from backend.api import data as api_data
from backend.api.routes import simulation as simulation_routes
from backend.api.routes.simulation import (
    SimulationStartRequest,
    get_live_events,
    get_live_incidents,
)
from simulation import session as session_store
from simulation.event_simulator import EventSimulator
from simulation.scenario_library import ATTACK_SCENARIOS, ScenarioLibrary
from simulation.stream_engine import StreamEngine, _append_json_array


class SimulationTests(unittest.TestCase):
    """Validate deterministic mix, canonical events, and incremental outputs."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.processed = self.root / "data" / "processed"
        self.normalized = self.root / "data" / "normalized"
        self.runtime = self.root / "data" / "runtime"
        self.processed.mkdir(parents=True)
        self.normalized.mkdir(parents=True)
        (self.processed / "users.json").write_text(
            json.dumps([{"user_id": "USR0001"}]), encoding="utf-8"
        )
        (self.processed / "devices.json").write_text(
            json.dumps([{"device_id": "DEV0001"}, {"device_id": "DEV0002"}]),
            encoding="utf-8",
        )
        historical = {
            "event_id": "EVT000010",
            "timestamp": "01/01/2025 00:00:00",
            "event_type": "LOGIN_SUCCESS",
            "event_category": "AUTHENTICATION",
            "source_system": "CERT",
            "source_log": "logon.csv",
            "user_id": "USR0001",
            "device_id": "DEV0001",
            "src_ip": None,
            "dst_ip": None,
            "correlation_id": None,
            "related_entities": [],
            "metadata": {},
            "severity": "low",
            "confidence": 1.0,
        }
        (self.normalized / "normalized_events.json").write_text(
            json.dumps([historical]) + "\n", encoding="utf-8"
        )
        (self.processed / "detected_stages.json").write_text("[]", encoding="utf-8")
        (self.processed / "attack_chains.json").write_text(
            json.dumps([{"attack_id": "ATTK000007", "attack_type": "HISTORICAL"}]),
            encoding="utf-8",
        )
        (self.processed / "attack_timelines.json").write_text("[]", encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def engine(self) -> StreamEngine:
        return StreamEngine(
            self.root,
            scenario_library=ScenarioLibrary(seed=42),
            event_simulator=EventSimulator(
                clock=lambda: datetime(2025, 1, 1, tzinfo=timezone.utc)
            ),
            seed=42,
        )

    def test_normal_scenario_mix_is_exactly_seventy_thirty_per_ten(self) -> None:
        library = ScenarioLibrary(seed=7)
        scenarios = [library.next_scenario() for _ in range(10)]

        self.assertEqual(sum(scenario.is_attack for scenario in scenarios), 3)
        self.assertEqual(sum(not scenario.is_attack for scenario in scenarios), 7)
        self.assertEqual(
            {scenario.attack_type for scenario in scenarios if scenario.is_attack},
            set(ATTACK_SCENARIOS),
        )

    def test_event_simulator_emits_sequential_ids_and_monotonic_timestamps(self) -> None:
        events = EventSimulator(
            clock=lambda: datetime(2025, 1, 1, tzinfo=timezone.utc)
        ).generate(
            ATTACK_SCENARIOS["MALWARE_INFECTION"],
            user_id="USR0001",
            device_id="DEV0001",
            first_event_number=11,
            after=datetime(2025, 1, 1, tzinfo=timezone.utc),
        )

        self.assertEqual([row["event_id"] for row in events], [
            "EVT000011", "EVT000012", "EVT000013", "EVT000014"
        ])
        self.assertEqual(
            [row["timestamp"] for row in events],
            sorted(row["timestamp"] for row in events),
        )
        self.assertTrue(all(row["timestamp"] > "2025-01-01T00:00:00+00:00" for row in events))
        self.assertTrue(all(row["source_system"] == "Cerberus Simulation" for row in events))

    def test_demo_scenarios_update_stages_chains_incidents_and_timelines(self) -> None:
        engine = self.engine()
        updates: list[int] = []
        engine._on_update = updates.append

        insider = engine.run_once(demo_mode=True, scenario="INSIDER_THEFT")
        malware = engine.run_once(demo_mode=True, scenario="MALWARE_INFECTION")
        lateral = engine.run_once(demo_mode=True, scenario="LATERAL_MOVEMENT")

        chains = json.loads((self.runtime / "simulated_chains.json").read_text(encoding="utf-8"))
        incidents = json.loads((self.runtime / "simulated_incidents.json").read_text(encoding="utf-8"))
        timelines = json.loads((self.runtime / "simulated_timelines.json").read_text(encoding="utf-8"))
        stages = json.loads((self.runtime / "simulated_stages.json").read_text(encoding="utf-8"))
        events = json.loads((self.runtime / "simulated_events.json").read_text(encoding="utf-8"))
        historical_events = json.loads(
            (self.normalized / "normalized_events.json").read_text(encoding="utf-8")
        )

        self.assertEqual(
            [chain["attack_type"] for chain in chains],
            ["INSIDER_DATA_THEFT", "MALWARE_INFECTION", "LATERAL_MOVEMENT"],
        )
        self.assertEqual(
            [item["incident_id"] for item in incidents],
            ["SIM000001", "SIM000002", "SIM000003"],
        )
        self.assertEqual(
            [timeline["attack_id"] for timeline in timelines],
            ["ATTK000001", "ATTK000002", "ATTK000003"],
        )
        self.assertEqual(
            [insider["incident_id"], malware["incident_id"], lateral["incident_id"]],
            ["SIM000001", "SIM000002", "SIM000003"],
        )
        self.assertEqual(len(events), insider["event_count"] + malware["event_count"] + lateral["event_count"])
        self.assertEqual(len(historical_events), 1)
        self.assertEqual(len(updates), 3)
        self.assertGreaterEqual(len(stages), 4)
        for timeline in timelines:
            timestamps = [entry["timestamp"] for entry in timeline["timeline"]]
            self.assertEqual(timestamps, sorted(timestamps))
            evidence_ids = set(chains[int(timeline["attack_id"][4:]) - 1]["evidence"])
            timeline_evidence = {
                entry["event_id"] for entry in timeline["timeline"] if entry.get("is_evidence")
            }
            self.assertEqual(evidence_ids, timeline_evidence)
        self.assertTrue(any(
            edge["relationship"] == "LATERAL_MOVEMENT"
            for edge in chains[-1]["graph"]["edges"]
        ))

    def test_simulation_uses_runtime_artifacts_without_replacing_cert_outputs(self) -> None:
        engine = self.engine()
        for scenario in ATTACK_SCENARIOS:
            engine.run_once(demo_mode=True, scenario=scenario)

        chains = json.loads((self.runtime / "simulated_chains.json").read_text(encoding="utf-8"))
        timelines = json.loads((self.runtime / "simulated_timelines.json").read_text(encoding="utf-8"))
        self.assertEqual(
            {chain["attack_type"] for chain in chains},
            {"INSIDER_DATA_THEFT", "MALWARE_INFECTION", "LATERAL_MOVEMENT"},
        )
        self.assertEqual(len(timelines), 3)
        self.assertTrue(all(timeline["timeline"] for timeline in timelines))
        self.assertTrue((self.processed / "detected_stages.json").exists())
        self.assertTrue((self.processed / "attack_chains.json").exists())

    def test_json_array_appender_handles_empty_and_existing_arrays(self) -> None:
        path = self.root / "append.json"
        path.write_text("[]\n", encoding="utf-8")
        _append_json_array(path, [{"value": 1}])
        _append_json_array(path, [{"value": 2}])

        self.assertEqual(json.loads(path.read_text(encoding="utf-8")), [{"value": 1}, {"value": 2}])

    def test_json_array_appender_recovers_an_interrupted_write(self) -> None:
        path = self.root / "recover.json"
        original = b"[]\n"
        path.write_bytes(original)
        journal = path.with_name(f".{path.name}.simulation-journal")
        journal.write_text(
            json.dumps({
                "original_size": len(original),
                "closing_bracket": 1,
                "suffix": "\n",
                "records": [{"value": 1}],
            }),
            encoding="utf-8",
        )
        path.write_bytes(b'[{"value":')

        _append_json_array(path, [{"value": 2}])

        self.assertEqual(
            json.loads(path.read_text(encoding="utf-8")),
            [{"value": 1}, {"value": 2}],
        )
        self.assertFalse(journal.exists())

    def test_demo_playback_is_controlled_and_status_tracks_scenario_counts(self) -> None:
        engine = self.engine()
        result = engine.run_once(demo_mode=True, scenario="LATERAL_MOVEMENT")
        status = engine.status()

        self.assertEqual(result["scenario"], "LATERAL_MOVEMENT")
        self.assertEqual(status["scenarios_generated"], 1)
        self.assertEqual(status["attack_scenarios"], 1)
        self.assertEqual(status["benign_scenarios"], 0)
        self.assertEqual(status["attack_ratio"], 1.0)

    def test_background_stream_can_start_and_stop_cleanly(self) -> None:
        engine = self.engine()
        started = engine.start(
            demo_mode=True,
            scenario="MALWARE_INFECTION",
            interval_seconds=0.25,
        )
        stopped = engine.stop()

        self.assertTrue(started["running"])
        self.assertFalse(stopped["running"])
        self.assertFalse(stopped["demo_mode"])
        self.assertGreater(stopped["events_generated"], 0)
        self.assertIsNone(stopped["last_error"])

    def test_simulation_api_routes_start_and_stop_the_configured_engine(self) -> None:
        engine = self.engine()
        with (
            patch.object(simulation_routes, "engine", engine),
            patch.object(session_store, "RUNTIME", self.runtime),
            patch.object(session_store, "SESSION_FILE", self.runtime / "session.json"),
        ):
            started = simulation_routes.start_simulation(
                SimulationStartRequest(
                    demo_mode=True,
                    scenario="LATERAL_MOVEMENT",
                    interval_seconds=0.25,
                )
            )
            stopped = simulation_routes.stop_simulation()

        self.assertTrue(started["running"])
        self.assertFalse(stopped["running"])
        self.assertFalse(stopped["demo_mode"])
        self.assertIsNone(stopped["last_error"])
        self.assertTrue(started["session_id"].startswith("SIMSESSION-"))
        self.assertEqual(started["session_id"], stopped["session_id"])
        self.assertEqual(started["start_time"], stopped["start_time"])

    def test_simulation_reset_removes_only_runtime_data(self) -> None:
        engine = self.engine()
        runtime = self.runtime
        runtime.mkdir()
        (runtime / "simulated_events.json").write_text("[{}]", encoding="utf-8")
        (runtime / "session.json").write_text("{}", encoding="utf-8")
        with (
            patch.object(simulation_routes, "engine", engine),
            patch.object(session_store, "RUNTIME", runtime),
            patch.object(session_store, "SESSION_FILE", runtime / "session.json"),
        ):
            result = simulation_routes.reset_simulation()

        self.assertFalse(result["running"])
        self.assertIsNone(result["session_id"])
        self.assertFalse((runtime / "simulated_events.json").exists())
        self.assertFalse((runtime / "session.json").exists())
        self.assertTrue((self.normalized / "normalized_events.json").exists())

    def test_live_data_routes_expose_persisted_simulation_records(self) -> None:
        self.engine().run_once(demo_mode=True, scenario="INSIDER_THEFT")
        with (
            patch.object(api_data, "PROCESSED", self.processed),
            patch.object(api_data, "RUNTIME", self.runtime),
            patch.object(api_data, "NORMALIZED_EVENTS", self.runtime / "simulated_events.json"),
        ):
            api_data.incidents.cache_clear()
            api_data._timelines.cache_clear()
            api_data._stages.cache_clear()
            api_data._users.cache_clear()
            api_data._devices.cache_clear()
            api_data._status_overrides.cache_clear()
            try:
                events = get_live_events(limit=200)
                incidents = get_live_incidents(limit=50)
            finally:
                api_data.incidents.cache_clear()
                api_data._timelines.cache_clear()
                api_data._stages.cache_clear()
                api_data._users.cache_clear()
                api_data._devices.cache_clear()
                api_data._status_overrides.cache_clear()

        self.assertEqual(events["count"], 22)
        self.assertTrue(all(
            event["source_system"] == "Cerberus Simulation"
            for event in events["items"]
        ))
        self.assertEqual(incidents["count"], 1)
        self.assertEqual(incidents["items"][0]["attack_type"], "INSIDER_DATA_THEFT")


if __name__ == "__main__":
    unittest.main()
