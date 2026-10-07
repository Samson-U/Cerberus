"""Threaded event stream with incremental stage, chain, and timeline processing."""

from __future__ import annotations

import json
import os
import random
import re
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from reconstruction.chain_builder import build_simulation_attack_chain
from reconstruction.stage_detector import detect_simulation_stages
from reconstruction.timeline_builder import build_simulation_timeline

from .event_simulator import EventSimulator
from .scenario_library import ATTACK_SCENARIOS, Scenario, ScenarioLibrary

DEFAULT_PROJECT_ROOT = Path(__file__).resolve().parents[1]
SIMULATION_SOURCE = "Cerberus Simulation"
_APPEND_LOCK = threading.RLock()


def _read_array(path: Path) -> list[dict[str, Any]]:
    """Load one bounded-size generated artifact and validate its outer shape."""
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as source:
        value = json.load(source)
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise ValueError(f"{path} must contain a JSON array of objects")
    return value


def _atomic_write_array(path: Path, records: list[dict[str, Any]]) -> None:
    """Replace a generated artifact atomically without touching source datasets."""
    _atomic_write_json(path, records)


def _atomic_write_json(path: Path, value: object) -> None:
    """Atomically persist a JSON value beside its destination."""
    path.parent.mkdir(parents=True, exist_ok=True)
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


def _array_insert_location(path: Path) -> tuple[int, int, bytes, bytes]:
    """Locate the final array bracket and capture only its small whitespace tail."""
    with path.open("r+b") as output:
        original_size = output.seek(0, os.SEEK_END)
        position = original_size - 1
        while position >= 0:
            output.seek(position)
            byte = output.read(1)
            if byte not in b" \r\n\t":
                break
            position -= 1
        if position < 0 or byte != b"]":
            raise ValueError(f"{path} does not end with a JSON array")
        closing_bracket = position
        output.seek(0)
        previous_content = b""
        remaining = closing_bracket
        while remaining:
            chunk_size = min(remaining, 64 * 1024)
            output.seek(remaining - chunk_size)
            chunk = output.read(chunk_size)
            previous_content = chunk.rstrip(b" \r\n\t")
            if previous_content:
                break
            remaining -= chunk_size
        if not previous_content or previous_content[-1:] not in (b"[", b"}"):
            raise ValueError(f"{path} has an invalid JSON array prefix")
        output.seek(closing_bracket + 1)
        suffix = output.read()
        separator = b"" if previous_content[-1:] == b"[" else b","
        return original_size, closing_bracket, suffix, separator


def _insert_array_records(path: Path, records: list[dict[str, Any]]) -> None:
    payload = b",".join(
        json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        for record in records
    )
    _, closing_bracket, suffix, separator = _array_insert_location(path)
    with path.open("r+b") as output:
        output.seek(closing_bracket)
        output.write(separator + payload + b"]" + suffix)
        output.truncate()
        output.flush()
        os.fsync(output.fileno())


def _recover_array_append(path: Path, journal_path: Path) -> None:
    """Restore the original array tail and replay a journaled append batch."""
    with journal_path.open(encoding="utf-8") as source:
        journal = json.load(source)
    original_size = journal.get("original_size")
    closing_bracket = journal.get("closing_bracket")
    suffix = journal.get("suffix")
    records = journal.get("records")
    if (
        not isinstance(original_size, int)
        or not isinstance(closing_bracket, int)
        or not isinstance(suffix, str)
        or not isinstance(records, list)
        or any(not isinstance(record, dict) for record in records)
    ):
        raise ValueError(f"Invalid JSON-array append journal: {journal_path}")
    with path.open("r+b") as output:
        output.seek(closing_bracket)
        output.write(b"]" + suffix.encode("ascii"))
        output.truncate(original_size)
        output.flush()
        os.fsync(output.fileno())
    _insert_array_records(path, records)
    journal_path.unlink()


def _append_json_array(path: Path, records: list[dict[str, Any]]) -> None:
    """Append array records with a small recovery journal for crash safety."""
    if not records:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    journal_path = path.with_name(f".{path.name}.simulation-journal")
    with _APPEND_LOCK:
        if journal_path.exists():
            _recover_array_append(path, journal_path)
        if not path.exists():
            path.write_bytes(b"[]\n")
        original_size, closing_bracket, suffix, _ = _array_insert_location(path)
        journal = {
            "original_size": original_size,
            "closing_bracket": closing_bracket,
            "suffix": suffix.decode("ascii"),
            "records": records,
        }
        _atomic_write_json(journal_path, journal)
        try:
            _insert_array_records(path, records)
        except OSError:
            _recover_array_append(path, journal_path)
        else:
            journal_path.unlink()


def _tail_last_event(path: Path) -> dict[str, Any] | None:
    """Read only the tail of the normalized store to seed event cursors."""
    if not path.is_file():
        return None
    with path.open("rb") as source:
        size = source.seek(0, os.SEEK_END)
        source.seek(max(0, size - 1024 * 1024))
        tail = source.read().decode("utf-8", errors="strict")
    starts = list(re.finditer(r'\{"event_id"\s*:', tail))
    decoder = json.JSONDecoder()
    for match in reversed(starts):
        try:
            record, _ = decoder.raw_decode(tail, match.start())
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict) and isinstance(record.get("event_id"), str):
            return record
    return None


def _next_numeric_id(records: list[dict[str, Any]], key: str, prefix: str) -> int:
    """Return the next sequential integer for an ID field."""
    values = [
        int(match.group(1))
        for row in records
        if isinstance(row.get(key), str)
        if (match := re.fullmatch(re.escape(prefix) + r"(\d+)", row[key]))
    ]
    return max(values, default=0) + 1


def _stage_record(stage: Any) -> dict[str, Any]:
    """Serialize an AttackStage with the established detected-stage keys."""
    record: dict[str, Any] = {
        "stage_id": stage.stage_id,
        "stage": stage.name,
        "user_id": stage.user_id,
        "device_id": stage.device_id,
        "start_time": stage.started_at,
        "end_time": stage.ended_at,
        "confidence": stage.confidence,
        "evidence": stage.evidence_ids,
        "classification": stage.classification,
        "description": stage.description,
        "risk_score": stage.risk_score,
        "metadata": stage.metadata,
    }
    if stage.file_count is not None:
        record["file_count"] = stage.file_count
    return record


def _incident_records(chains: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Adapt historic chain records if incidents.json has not been created yet."""
    output = []
    for index, chain in enumerate(chains, start=1):
        record = dict(chain)
        record["incident_id"] = record.get("incident_id") or f"INC{index:06d}"
        output.append(record)
    return output


def _as_utc(value: str) -> datetime:
    """Parse normalized or ISO timestamps and normalize them to UTC."""
    parsed: datetime
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        parsed = datetime.strptime(value, "%m/%d/%Y %H:%M:%S")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


class StreamEngine:
    """Generate enterprise scenarios and persist their pipeline outputs."""

    def __init__(
        self,
        project_root: Path = DEFAULT_PROJECT_ROOT,
        *,
        interval_seconds: float = 5.0,
        scenario_library: ScenarioLibrary | None = None,
        event_simulator: EventSimulator | None = None,
        on_update: Callable[[int], None] | None = None,
        clock: Callable[[], datetime] | None = None,
        seed: int | None = None,
    ) -> None:
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be positive")
        self.project_root = project_root.resolve()
        self.processed = self.project_root / "data" / "processed"
        self.runtime = self.project_root / "data" / "runtime"
        self.normalized_path = (
            self.runtime / "simulated_events.json"
        )
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._seed = seed
        self._random = random.Random(seed)
        self._scenario_library = scenario_library or ScenarioLibrary(seed=seed)
        self._event_simulator = event_simulator or EventSimulator(clock=self._clock)
        self._on_update = on_update or (lambda _event_count: None)
        self._interval_seconds = interval_seconds
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._running = False
        self._demo_mode = False
        self._demo_scenario = "INSIDER_THEFT"
        self._last_error: str | None = None
        self._events_generated = 0
        self._scenarios_generated = 0
        self._attack_scenarios = 0
        self._benign_scenarios = 0
        self._last_scenario: str | None = None
        self._last_event_at: str | None = None
        self._last_attack_id: str | None = None

    def status(self) -> dict[str, Any]:
        """Return current stream lifecycle, configuration, and output counters."""
        with self._lock:
            return {
                "running": self._running,
                "demo_mode": self._demo_mode,
                "demo_scenario": self._demo_scenario if self._demo_mode else None,
                "interval_seconds": self._interval_seconds,
                "events_generated": self._events_generated,
                "scenarios_generated": self._scenarios_generated,
                "attack_scenarios": self._attack_scenarios,
                "benign_scenarios": self._benign_scenarios,
                "attack_ratio": (
                    self._attack_scenarios / self._scenarios_generated
                    if self._scenarios_generated
                    else 0.0
                ),
                "last_scenario": self._last_scenario,
                "last_event_at": self._last_event_at,
                "last_attack_id": self._last_attack_id,
                "last_error": self._last_error,
            }

    def start(
        self,
        *,
        demo_mode: bool = False,
        scenario: str = "INSIDER_THEFT",
        interval_seconds: float | None = None,
    ) -> dict[str, Any]:
        """Start the background producer, optionally pinning a demo scenario."""
        if demo_mode and scenario not in ATTACK_SCENARIOS:
            raise ValueError(f"Unsupported demo scenario: {scenario}")
        if interval_seconds is not None and not 0.25 <= interval_seconds <= 300:
            raise ValueError("interval_seconds must be between 0.25 and 300")
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                self._demo_mode = demo_mode
                self._demo_scenario = scenario
                if interval_seconds is not None:
                    self._interval_seconds = interval_seconds
                return self.status()
            if interval_seconds is not None:
                self._interval_seconds = interval_seconds
            self._demo_mode = demo_mode
            self._demo_scenario = scenario
            self._last_error = None
            self._stop_event.clear()
            self._running = True
            self._thread = threading.Thread(
                target=self._run,
                name="cerberus-simulation",
                daemon=True,
            )
            self._thread.start()
            return self.status()

    def stop(self) -> dict[str, Any]:
        """Request stream shutdown and wait briefly for the current batch."""
        with self._lock:
            self._stop_event.set()
            self._demo_mode = False
            thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=5)
        with self._lock:
            if thread is None or not thread.is_alive():
                self._running = False
            return self.status()

    def reset_state(self) -> dict[str, Any]:
        """Stop the producer and clear all in-memory session counters."""
        self.stop()
        with self._lock:
            self._scenario_library = ScenarioLibrary(seed=self._seed)
            self._random = random.Random(self._seed)
            self._demo_mode = False
            self._demo_scenario = "INSIDER_THEFT"
            self._last_error = None
            self._events_generated = 0
            self._scenarios_generated = 0
            self._attack_scenarios = 0
            self._benign_scenarios = 0
            self._last_scenario = None
            self._last_event_at = None
            self._last_attack_id = None
            return self.status()

    def run_once(
        self,
        *,
        demo_mode: bool = False,
        scenario: str = "INSIDER_THEFT",
    ) -> dict[str, Any]:
        """Generate and process one scenario; also used by deterministic tests."""
        selected = self._scenario_library.next_scenario(
            demo_mode=demo_mode,
            scenario_name=scenario,
        )
        return self._process_scenario(selected)

    def _run(self) -> None:
        """Execute periodic scenario batches; publish failures in status."""
        while not self._stop_event.is_set():
            try:
                with self._lock:
                    demo_mode = self._demo_mode
                    scenario = self._demo_scenario
                    interval = self._interval_seconds
                self.run_once(demo_mode=demo_mode, scenario=scenario)
            except Exception as error:
                with self._lock:
                    self._last_error = f"{type(error).__name__}: {error}"
                    self._running = False
                    self._demo_mode = False
                self._stop_event.set()
                return
            if self._stop_event.wait(interval):
                break
        with self._lock:
            self._running = False

    def _process_scenario(self, scenario: Scenario) -> dict[str, Any]:
        users = _read_array(self.processed / "users.json")
        devices = _read_array(self.processed / "devices.json")
        user_ids = [row.get("user_id") for row in users if isinstance(row.get("user_id"), str)]
        device_ids = [row.get("device_id") for row in devices if isinstance(row.get("device_id"), str)]
        if not user_ids or not device_ids:
            raise ValueError("Simulation requires non-empty users.json and devices.json registries")

        source_device = self._random.choice(device_ids)
        target_devices = [device_id for device_id in device_ids if device_id != source_device]
        if scenario.attack_type == "LATERAL_MOVEMENT" and not target_devices:
            raise ValueError("Lateral-movement simulation requires at least two registered devices")

        last_event = _tail_last_event(self.normalized_path)
        last_number = 0
        last_timestamp: datetime | None = None
        if last_event is not None:
            event_id = last_event.get("event_id", "")
            match = re.fullmatch(r"EVT(\d+)", event_id)
            if match:
                last_number = int(match.group(1))
            timestamp = last_event.get("timestamp")
            if isinstance(timestamp, str):
                last_timestamp = _as_utc(timestamp)
        events = self._event_simulator.generate(
            scenario,
            user_id=self._random.choice(user_ids),
            device_id=source_device,
            first_event_number=last_number + 1,
            after=last_timestamp,
            target_device_id=self._random.choice(target_devices) if target_devices else None,
        )
        event_records = {str(row["event_id"]): row for row in events}
        stages_path = self.runtime / "simulated_stages.json"
        existing_stages = _read_array(stages_path)
        first_stage_number = _next_numeric_id(existing_stages, "stage_id", "STG")
        stages = detect_simulation_stages(events, first_stage_number=first_stage_number)

        chains_path = self.runtime / "simulated_chains.json"
        chains = _read_array(chains_path)
        incidents_path = self.runtime / "simulated_incidents.json"
        incidents = (
            _read_array(incidents_path)
            if incidents_path.exists()
            else _incident_records(chains)
        )
        timelines_path = self.runtime / "simulated_timelines.json"
        timelines = _read_array(timelines_path)
        attack_id: str | None = None
        chain: dict[str, Any] | None = None
        timeline: dict[str, Any] | None = None
        incident: dict[str, Any] | None = None
        if stages:
            attack_id = f"ATTK{_next_numeric_id(chains, 'attack_id', 'ATTK'):06d}"
            chain = build_simulation_attack_chain(attack_id, stages, event_records)
            incident_number = _next_numeric_id(incidents, "incident_id", "SIM")
            incident = {**chain, "incident_id": f"SIM{incident_number:06d}"}
            timeline = build_simulation_timeline(chain, stages, event_records)

        with _APPEND_LOCK:
            _append_json_array(self.normalized_path, events)
            if stages:
                _atomic_write_array(
                    stages_path,
                    existing_stages + [_stage_record(stage) for stage in stages],
                )
                assert chain is not None and timeline is not None and incident is not None
                _atomic_write_array(chains_path, chains + [chain])
                _atomic_write_array(incidents_path, incidents + [incident])
                _atomic_write_array(timelines_path, timelines + [timeline])

        self._on_update(len(events))
        with self._lock:
            self._events_generated += len(events)
            self._scenarios_generated += 1
            if scenario.is_attack:
                self._attack_scenarios += 1
            else:
                self._benign_scenarios += 1
            self._last_scenario = scenario.name
            self._last_event_at = str(events[-1]["timestamp"])
            if incident:
                self._last_attack_id = incident["incident_id"]
        return {
            "scenario": scenario.name,
            "is_attack": scenario.is_attack,
            "event_count": len(events),
            "stage_ids": [stage.stage_id for stage in stages],
            "attack_id": attack_id,
            "incident_id": incident["incident_id"] if incident else None,
        }
