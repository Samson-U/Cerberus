"""Regression tests for evidence-based Phase 4 stage rules."""

import csv
import json
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from reconstruction.rules.initial_access import detect_initial_access
from reconstruction.stage_detector import detect_stages


class StageDetectionTests(unittest.TestCase):
    """Exercise phishing matching, collection thresholds, and USB safeguards."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.data = self.root / "data"
        self.cert = self.data / "raw" / "cert"
        self.phishing = self.data / "raw" / "phishing"
        self.processed = self.data / "processed"
        self.normalized = self.data / "normalized"
        for directory in (self.cert, self.phishing, self.processed, self.normalized):
            directory.mkdir(parents=True)
        (self.processed / "users.json").write_text(
            json.dumps([{"user_id": "USR0001", "username": "U1"}]),
            encoding="utf-8",
        )
        (self.processed / "devices.json").write_text(
            json.dumps([{"device_id": "DEV0001", "hostname": "PC1"}]),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _write_events(self, file_count: int, *, usb_insert: bool) -> None:
        start = datetime(2026, 1, 1, 9)
        events = []
        for index in range(file_count):
            events.append(
                {
                    "event_id": f"EVT{index + 1:06d}",
                    "timestamp": start.strftime("%m/%d/%Y %H:%M:%S"),
                    "event_type": "FILE_ACCESS",
                    "user_id": "USR0001",
                    "device_id": "DEV0001",
                    "source_log": "file.csv",
                    "metadata": {"filename": f"file-{index}.doc"},
                }
            )
        if usb_insert:
            events.append(
                {
                    "event_id": f"EVT{file_count + 1:06d}",
                    "timestamp": (start + timedelta(minutes=5)).strftime(
                        "%m/%d/%Y %H:%M:%S"
                    ),
                    "event_type": "USB_INSERT",
                    "user_id": "USR0001",
                    "device_id": "DEV0001",
                    "source_log": "device.csv",
                    "metadata": {"source_record_id": "USB-1"},
                }
            )
        (self.normalized / "normalized_events.json").write_text(
            json.dumps(events),
            encoding="utf-8",
        )

    def test_exact_phishing_url_visit_is_initial_access_evidence(self) -> None:
        phishing_path = self.phishing / "urls.csv"
        with phishing_path.open("w", encoding="utf-8", newline="") as output:
            writer = csv.DictWriter(output, fieldnames=["URL", "label"])
            writer.writeheader()
            writer.writerow({"URL": "https://bad.example/login", "label": "0"})
            writer.writerow({"URL": "https://safe.example/", "label": "1"})

        http_path = self.cert / "http.csv"
        with http_path.open("w", encoding="utf-8", newline="") as output:
            writer = csv.DictWriter(
                output,
                fieldnames=["id", "date", "user", "pc", "url"],
            )
            writer.writeheader()
            writer.writerow(
                {
                    "id": "{HTTP-1}",
                    "date": "01/01/2020 08:00:00",
                    "user": "U1",
                    "pc": "PC1",
                    "url": "https://bad.example/login",
                }
            )

        stages = detect_initial_access(phishing_path, http_path)

        self.assertEqual(len(stages), 1)
        self.assertEqual(stages[0].name, "INITIAL_ACCESS")
        self.assertEqual(stages[0].user_id, "USR0001")
        self.assertEqual(stages[0].evidence_ids, ["CERT-HTTP:{HTTP-1}"])

    def test_collection_and_exfiltration_require_qualifying_file_activity(self) -> None:
        self._write_events(20, usb_insert=True)

        stages = detect_stages(self.root, include_initial_access=False)
        output = json.loads(
            (self.processed / "detected_stages.json").read_text(encoding="utf-8")
        )

        self.assertEqual([stage.name for stage in stages], ["COLLECTION", "EXFILTRATION"])
        self.assertEqual([record["stage"] for record in output], ["COLLECTION", "EXFILTRATION"])
        self.assertEqual(output[0]["file_count"], 20)
        self.assertIn(output[1]["metadata"]["usb_event_id"], output[1]["evidence"])

    def test_usb_without_collection_does_not_create_exfiltration(self) -> None:
        self._write_events(19, usb_insert=True)

        stages = detect_stages(self.root, include_initial_access=False)

        self.assertEqual(stages, [])
        self.assertEqual(
            json.loads(
                (self.processed / "detected_stages.json").read_text(
                    encoding="utf-8"
                )
            ),
            [],
        )


if __name__ == "__main__":
    unittest.main()
