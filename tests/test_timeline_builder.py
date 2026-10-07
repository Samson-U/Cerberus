"""Regression tests for explainable and chronologically sorted timelines."""

import csv
import json
import tempfile
import unittest
from pathlib import Path

from reconstruction.chain_builder import build_attack_chains
from reconstruction.timeline_builder import build_attack_timelines


class AttackTimelineBuilderTests(unittest.TestCase):
    """Verify evidence retrieval, sorting, full records, and stage annotations."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.processed = self.root / "data" / "processed"
        self.normalized = self.root / "data" / "normalized"
        self.http = self.root / "data" / "raw" / "cert" / "http.csv"
        self.processed.mkdir(parents=True)
        self.normalized.mkdir(parents=True)
        self.http.parent.mkdir(parents=True)
        (self.processed / "users.json").write_text(
            json.dumps([{"user_id": "USR0001"}]), encoding="utf-8"
        )
        (self.processed / "devices.json").write_text(
            json.dumps([{"device_id": "DEV0001"}]), encoding="utf-8"
        )
        (self.processed / "entity_links.json").write_text("[]", encoding="utf-8")
        with self.http.open("w", encoding="utf-8", newline="") as output:
            writer = csv.DictWriter(
                output, fieldnames=["id", "date", "user", "pc", "url"]
            )
            writer.writeheader()
            writer.writerow(
                {
                    "id": "{HTTP-1}",
                    "date": "01/01/2026 08:00:00",
                    "user": "U1",
                    "pc": "PC1",
                    "url": "https://bad.example/",
                }
            )
        common = {
            "event_category": "activity",
            "source_system": "CERT",
            "user_id": "USR0001",
            "device_id": "DEV0001",
            "src_ip": None,
            "dst_ip": None,
            "correlation_id": None,
            "severity": "low",
            "confidence": 1.0,
        }
        file_event = {
            **common,
            "event_id": "EVT000001",
            "timestamp": "01/01/2026 09:05:00",
            "event_type": "FILE_ACCESS",
            "event_category": "FILE_ACTIVITY",
            "source_log": "file.csv",
            "related_entities": ["report.doc"],
            "metadata": {"source_record_id": "{FILE-1}", "filename": "report.doc"},
        }
        usb_event = {
            **common,
            "event_id": "EVT000002",
            "timestamp": "01/01/2026 09:10:00",
            "event_type": "USB_INSERT",
            "event_category": "DEVICE_ACTIVITY",
            "source_log": "device.csv",
            "related_entities": ["PC1"],
            "metadata": {"source_record_id": "{USB-1}"},
        }
        # Store out of timestamp order; the timeline builder must sort anyway.
        (self.normalized / "normalized_events.json").write_text(
            json.dumps([usb_event, file_event]), encoding="utf-8"
        )
        stages = [
            {
                "stage_id": "STG000001",
                "stage": "INITIAL_ACCESS",
                "user_id": "USR0001",
                "device_id": "DEV0001",
                "start_time": "2026-01-01T08:00:00",
                "end_time": "2026-01-01T08:00:00",
                "confidence": 0.9,
                "evidence": ["CERT-HTTP:{HTTP-1}"],
                "metadata": {},
            },
            {
                "stage_id": "STG000002",
                "stage": "COLLECTION",
                "user_id": "USR0001",
                "device_id": "DEV0001",
                "start_time": "2026-01-01T09:05:00",
                "end_time": "2026-01-01T09:05:00",
                "confidence": 0.9,
                "evidence": ["EVT000001"],
                "file_count": 120,
                "metadata": {},
            },
            {
                "stage_id": "STG000003",
                "stage": "EXFILTRATION",
                "user_id": "USR0001",
                "device_id": "DEV0001",
                "start_time": "2026-01-01T09:05:00",
                "end_time": "2026-01-01T09:10:00",
                "confidence": 0.88,
                "evidence": ["EVT000001", "EVT000002"],
                "file_count": 120,
                "metadata": {"usb_event_id": "EVT000002"},
            },
        ]
        (self.processed / "detected_stages.json").write_text(
            json.dumps(stages), encoding="utf-8"
        )
        build_attack_chains(self.root)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_timeline_sorts_full_events_and_annotates_contributing_stages(self) -> None:
        timelines = build_attack_timelines(self.root)

        self.assertEqual(len(timelines), 1)
        entries = timelines[0]["timeline"]
        self.assertEqual(
            [entry["event_id"] for entry in entries],
            ["CERT-HTTP:{HTTP-1}", "EVT000001", "EVT000002"],
        )
        self.assertEqual(
            [entry["timestamp"] for entry in entries],
            [
                "2026-01-01T08:00:00",
                "2026-01-01T09:05:00",
                "2026-01-01T09:10:00",
            ],
        )
        self.assertEqual(entries[0]["stage"], "INITIAL_ACCESS")
        self.assertEqual(entries[1]["stage"], "COLLECTION")
        self.assertEqual(entries[1]["event"], "File accessed")
        self.assertEqual(entries[1]["event_record"]["event_type"], "FILE_ACCESS")
        self.assertEqual(entries[2]["stage"], "EXFILTRATION")
        self.assertEqual(entries[2]["event"], "USB device connected")
        self.assertEqual(entries[2]["event_record"]["event_type"], "USB_INSERT")


if __name__ == "__main__":
    unittest.main()
