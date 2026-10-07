"""Regression tests for evidence-based attack chain construction."""

import csv
import json
import tempfile
import unittest
from pathlib import Path

from reconstruction.chain_builder import build_attack_chains


class AttackChainBuilderTests(unittest.TestCase):
    """Verify pattern recognition, risk scoring, graph links, and validation."""

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
        (self.processed / "entity_links.json").write_text(
            json.dumps(
                [
                    {
                        "source_entity": "USR0001",
                        "target_entity": "DEV0001",
                        "relationship": "USES",
                    }
                ]
            ),
            encoding="utf-8",
        )
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
        events = [
            {
                "event_id": "EVT000001",
                "timestamp": "01/01/2026 09:05:00",
                "event_type": "FILE_ACCESS",
                "event_category": "FILE_ACTIVITY",
                "source_system": "CERT",
                "source_log": "file.csv",
                "user_id": "USR0001",
                "device_id": "DEV0001",
                "src_ip": None,
                "dst_ip": None,
                "correlation_id": None,
                "related_entities": ["report.doc"],
                "metadata": {
                    "source_record_id": "{FILE-1}",
                    "filename": "report.doc",
                    "content": "fixture",
                },
                "severity": "low",
                "confidence": 1.0,
            },
            {
                "event_id": "EVT000002",
                "timestamp": "01/01/2026 09:10:00",
                "event_type": "USB_INSERT",
                "event_category": "DEVICE_ACTIVITY",
                "source_system": "CERT",
                "source_log": "device.csv",
                "user_id": "USR0001",
                "device_id": "DEV0001",
                "src_ip": None,
                "dst_ip": None,
                "correlation_id": None,
                "related_entities": ["PC1"],
                "metadata": {"source_record_id": "{USB-1}"},
                "severity": "low",
                "confidence": 1.0,
            },
        ]
        (self.normalized / "normalized_events.json").write_text(
            json.dumps(events), encoding="utf-8"
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
                "metadata": {"distinct_file_count": 120},
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

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_compromised_user_chain_and_graph_are_generated(self) -> None:
        chains = build_attack_chains(self.root)

        self.assertEqual(len(chains), 1)
        chain = chains[0]
        self.assertEqual(chain["attack_id"], "ATTK000001")
        self.assertEqual(chain["attack_type"], "COMPROMISED_USER_DATA_THEFT")
        self.assertEqual(chain["stages"], ["INITIAL_ACCESS", "COLLECTION", "EXFILTRATION"])
        self.assertEqual(chain["risk_score"], 100)
        self.assertEqual(chain["risk_level"], "CRITICAL")
        self.assertEqual(
            chain["evidence"],
            ["CERT-HTTP:{HTTP-1}", "EVT000001", "EVT000002"],
        )
        self.assertIn(
            {
                "source": "USR0001",
                "target": "DEV0001",
                "relationship": "USES",
            },
            chain["graph"]["edges"],
        )
        self.assertEqual(chain["stage_ids"], ["STG000001", "STG000002", "STG000003"])

    def test_usb_without_a_collection_stage_creates_no_attack(self) -> None:
        stages_path = self.processed / "detected_stages.json"
        stages = json.loads(stages_path.read_text(encoding="utf-8"))
        stages = [stage for stage in stages if stage["stage"] != "COLLECTION"]
        stages_path.write_text(json.dumps(stages), encoding="utf-8")

        self.assertEqual(build_attack_chains(self.root), [])

    def test_collection_and_exfiltration_match_insider_theft_pattern(self) -> None:
        stages_path = self.processed / "detected_stages.json"
        stages = json.loads(stages_path.read_text(encoding="utf-8"))
        stages = [stage for stage in stages if stage["stage"] != "INITIAL_ACCESS"]
        stages_path.write_text(json.dumps(stages), encoding="utf-8")

        chains = build_attack_chains(self.root)

        self.assertEqual(len(chains), 1)
        self.assertEqual(chains[0]["attack_type"], "INSIDER_DATA_THEFT")
        self.assertEqual(chains[0]["risk_score"], 100)


if __name__ == "__main__":
    unittest.main()
