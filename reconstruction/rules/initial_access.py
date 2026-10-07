"""Detect CERT HTTP visits to URLs labeled as phishing in the URL dataset."""

import csv
import json
from pathlib import Path
from typing import Any

from schemas.attack_schema import AttackStage

from .common import iso_timestamp

PHISHING_LABEL = "0"
PHISHING_CONFIDENCE = 0.90


def _load_phishing_urls(path: Path) -> set[str]:
    """Load labeled phishing URLs; label semantics follow the dataset coding."""
    urls: set[str] = set()
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as source:
        reader = csv.DictReader(source)
        if reader.fieldnames is None or not {"URL", "label"}.issubset(
            reader.fieldnames
        ):
            raise ValueError(f"{path} must provide URL and label columns")
        for row in reader:
            if row.get("label", "").strip() == PHISHING_LABEL:
                url = row.get("URL", "").strip()
                if url:
                    urls.add(url)
    return urls


def detect_initial_access(
    phishing_dataset: Path,
    http_log: Path,
) -> list[AttackStage]:
    """Find observed CERT visits to URLs labeled phishing.

    SMS spam rows are not used here: the available SMS dataset has no user,
    device, or event-time fields with which to support a user-linked stage.
    """
    phishing_urls = _load_phishing_urls(phishing_dataset)
    findings: dict[tuple[str, str], dict[str, Any]] = {}
    with http_log.open(
        "r", encoding="utf-8-sig", errors="replace", newline=""
    ) as source:
        reader = csv.DictReader(source)
        required = {"id", "date", "user", "pc", "url"}
        if reader.fieldnames is None or not required.issubset(reader.fieldnames):
            raise ValueError(f"{http_log} must provide {', '.join(sorted(required))}")
        for line_number, row in enumerate(reader, start=2):
            url = (row.get("url") or "").strip()
            if url not in phishing_urls:
                continue
            source_id = (row.get("id") or "").strip()
            username = (row.get("user") or "").strip()
            hostname = (row.get("pc") or "").strip()
            timestamp_value = (row.get("date") or "").strip()
            if not all((source_id, username, hostname, timestamp_value)):
                raise ValueError(
                    f"{http_log}:{line_number}: matched phishing visit lacks "
                    "an ID, user, device, or timestamp"
                )
            from datetime import datetime

            try:
                timestamp = datetime.strptime(
                    timestamp_value, "%m/%d/%Y %H:%M:%S"
                )
            except ValueError as error:
                raise ValueError(
                    f"{http_log}:{line_number}: invalid timestamp "
                    f"{timestamp_value!r}"
                ) from error

            key = (username, hostname)
            item = findings.setdefault(
                key,
                {
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                    "evidence": [],
                    "urls": set(),
                },
            )
            item["first_seen"] = min(item["first_seen"], timestamp)
            item["last_seen"] = max(item["last_seen"], timestamp)
            item["evidence"].append(f"CERT-HTTP:{source_id}")
            item["urls"].add(url)

    project_root = http_log.resolve().parents[3]
    users_path = project_root / "data" / "processed" / "users.json"
    devices_path = project_root / "data" / "processed" / "devices.json"
    users = json.loads(users_path.read_text(encoding="utf-8"))
    devices = json.loads(devices_path.read_text(encoding="utf-8"))
    user_ids = {record["username"]: record["user_id"] for record in users}
    device_ids = {record["hostname"]: record["device_id"] for record in devices}
    stages: list[AttackStage] = []
    for (username, hostname), item in sorted(findings.items()):
        user_id = user_ids.get(username)
        device_id = device_ids.get(hostname)
        if user_id is None or device_id is None:
            raise ValueError(
                f"Matched HTTP event for {username!r}/{hostname!r} is absent "
                "from the processed registries"
            )
        stages.append(
            AttackStage(
                stage_id="",
                name="INITIAL_ACCESS",
                classification="PHISHING_URL_VISIT",
                description=(
                    "CERT HTTP telemetry records a user visiting a URL labeled "
                    "phishing in the configured URL dataset."
                ),
                started_at=iso_timestamp(item["first_seen"]),
                ended_at=iso_timestamp(item["last_seen"]),
                risk_score=PHISHING_CONFIDENCE,
                confidence=PHISHING_CONFIDENCE,
                evidence_ids=sorted(item["evidence"]),
                user_id=user_id,
                device_id=device_id,
                metadata={
                    "username": username,
                    "hostname": hostname,
                    "matched_url_count": len(item["urls"]),
                    "matched_urls": sorted(item["urls"])[:20],
                    "evidence_source": "data/raw/cert/http.csv",
                    "phishing_label": PHISHING_LABEL,
                    "evidence_id_format": "CERT-HTTP:<source-record-id>",
                },
            )
        )
    return stages
