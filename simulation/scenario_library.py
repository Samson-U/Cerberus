"""Reusable benign and attack scenario definitions for the simulator."""

from __future__ import annotations

import random
from dataclasses import dataclass, field


@dataclass(frozen=True)
class EventTemplate:
    """Description of one canonical event in a scenario."""

    event_type: str
    event_category: str
    source_log: str
    metadata: dict[str, object] = field(default_factory=dict)
    severity: str = "low"


@dataclass(frozen=True)
class Scenario:
    """A bounded sequence of events representing one enterprise activity."""

    name: str
    attack_type: str | None
    events: tuple[EventTemplate, ...]

    @property
    def is_attack(self) -> bool:
        """Whether this scenario models malicious activity."""
        return self.attack_type is not None


ATTACK_SCENARIOS: dict[str, Scenario] = {
    "INSIDER_THEFT": Scenario(
        name="INSIDER_THEFT",
        attack_type="INSIDER_THEFT",
        events=(
            EventTemplate("LOGIN_SUCCESS", "AUTHENTICATION", "simulation/logon"),
            *tuple(
                EventTemplate(
                    "FILE_ACCESS",
                    "FILE_ACTIVITY",
                    "simulation/file_audit",
                    {"filename": f"confidential_report_{index:02d}.xlsx", "operation": "read"},
                )
                for index in range(1, 21)
            ),
            EventTemplate(
                "USB_INSERT",
                "DEVICE_ACTIVITY",
                "simulation/device",
                {"device_class": "USB_STORAGE", "vendor": "Acme Enterprise"},
            ),
        ),
    ),
    "MALWARE_INFECTION": Scenario(
        name="MALWARE_INFECTION",
        attack_type="MALWARE_INFECTION",
        events=(
            EventTemplate("EMAIL_RECEIVED", "EMAIL_ACTIVITY", "simulation/email"),
            EventTemplate(
                "FILE_DOWNLOAD",
                "FILE_ACTIVITY",
                "simulation/download",
                {"filename": "invoice_review.exe", "malware_hash": "sha256:simulated-indicator"},
                "high",
            ),
            EventTemplate(
                "MALWARE_EXECUTION",
                "PROCESS_ACTIVITY",
                "simulation/endpoint",
                {"filename": "invoice_review.exe", "malware_hash": "sha256:simulated-indicator"},
                "critical",
            ),
            EventTemplate(
                "NETWORK_CONNECTION",
                "NETWORK_ACTIVITY",
                "simulation/network",
                {"destination_domain": "updates.example.invalid", "direction": "egress"},
                "high",
            ),
        ),
    ),
    "LATERAL_MOVEMENT": Scenario(
        name="LATERAL_MOVEMENT",
        attack_type="LATERAL_MOVEMENT",
        events=(
            EventTemplate(
                "REMOTE_LOGON",
                "AUTHENTICATION",
                "simulation/logon",
                {"target_device_id": "pending"},
                "high",
            ),
            EventTemplate(
                "NETWORK_CONNECTION",
                "NETWORK_ACTIVITY",
                "simulation/network",
                {"target_device_id": "pending", "protocol": "SMB"},
                "medium",
            ),
        ),
    ),
}

BENIGN_SCENARIOS: tuple[Scenario, ...] = (
    Scenario(
        "NORMAL_WORKDAY",
        None,
        (
            EventTemplate("LOGIN_SUCCESS", "AUTHENTICATION", "simulation/logon"),
            EventTemplate(
                "FILE_ACCESS",
                "FILE_ACTIVITY",
                "simulation/file_audit",
                {"filename": "team_schedule.xlsx", "operation": "read"},
            ),
        ),
    ),
    Scenario(
        "ROUTINE_WEB_ACTIVITY",
        None,
        (
            EventTemplate(
                "HTTP_REQUEST",
                "NETWORK_ACTIVITY",
                "simulation/network",
                {"url": "https://intranet.example.invalid/home"},
            ),
        ),
    ),
    Scenario(
        "ROUTINE_USB_MAINTENANCE",
        None,
        (
            EventTemplate(
                "USB_INSERT",
                "DEVICE_ACTIVITY",
                "simulation/device",
                {"device_class": "USB_STORAGE", "purpose": "approved backup"},
            ),
            EventTemplate("USB_REMOVE", "DEVICE_ACTIVITY", "simulation/device"),
        ),
    ),
    Scenario(
        "ROUTINE_LOGOUT",
        None,
        (EventTemplate("LOGOUT", "AUTHENTICATION", "simulation/logon"),),
    ),
)


class ScenarioLibrary:
    """Select a deterministic 70/30 scenario mix or a requested demo scenario."""

    def __init__(self, *, seed: int | None = None) -> None:
        self._random = random.Random(seed)
        self._cycle: list[Scenario] = []
        self._position = 0

    def next_scenario(
        self,
        *,
        demo_mode: bool = False,
        scenario_name: str = "INSIDER_THEFT",
    ) -> Scenario:
        """Return one scenario, honoring exact 7-benign/3-attack cycles."""
        if demo_mode:
            try:
                return ATTACK_SCENARIOS[scenario_name]
            except KeyError as error:
                raise ValueError(f"Unsupported demo scenario: {scenario_name}") from error

        if self._position >= len(self._cycle):
            attack_scenarios = list(ATTACK_SCENARIOS.values())
            benign_scenarios = [
                self._random.choice(BENIGN_SCENARIOS) for _ in range(7)
            ]
            self._cycle = benign_scenarios + attack_scenarios
            self._random.shuffle(self._cycle)
            self._position = 0
        scenario = self._cycle[self._position]
        self._position += 1
        return scenario
