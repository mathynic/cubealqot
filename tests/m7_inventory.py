"""PP-00 inventory tests; these inspect evidence and do not invoke Sage."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "m7" / "inventory-proof-library.py"
SPEC = importlib.util.spec_from_file_location("m7_inventory", SCRIPT)
assert SPEC and SPEC.loader
inventory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inventory)


class InventoryTests(unittest.TestCase):
    def test_manifest_is_deterministic_and_detects_byte_changes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "z").mkdir()
            (root / "z" / "data.bin").write_bytes(b"first")
            (root / "a.txt").write_text("second\n", encoding="utf-8")

            first = inventory.build_inventory(root)
            second = inventory.build_inventory(root)
            self.assertEqual(first, second)
            original_digest = first["file_manifest_sha256"]

            (root / "z" / "data.bin").write_bytes(b"changed")
            changed = inventory.build_inventory(root)
            self.assertNotEqual(original_digest, changed["file_manifest_sha256"])

    def test_external_status_mapping_does_not_change_proof_meaning(self) -> None:
        self.assertEqual(inventory.external_status("CertifiedEmpty"), "CERTIFIED_EMPTY")
        self.assertEqual(inventory.external_status("Inconclusive"), "INCONCLUSIVE")
        self.assertEqual(inventory.external_status("unknown"), "unknown")

    def test_retained_completed_families_have_initial_and_replay_links(self) -> None:
        library = ROOT / "out" / "m7-proof-library"
        report = inventory.build_inventory(library)
        self.assertEqual(len(report["families"]), 7)
        self.assertTrue(
            all(
                family["category"] == "successful_with_recorded_replay_evidence"
                and family["checks"]["initial_transcript"]
                and family["checks"]["matching_replay_transcript"]
                and family["checks"]["successful_campaign_result"]
                for family in report["families"]
            )
        )
        self.assertEqual(report["completion_accounting"]["unaccounted_known_completions"], 0)
        self.assertEqual(report["benchmark_admissions"], [])


if __name__ == "__main__":
    unittest.main()
