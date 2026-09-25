"""MW-00 evidence accounting tests; no Sage or production store needed."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/m7/record_mw00_baseline.py'
spec = importlib.util.spec_from_file_location('mw00', SCRIPT)
mw00 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mw00)


class BaselineTests(unittest.TestCase):
    def test_manifest_detects_changed_and_added_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'a').write_bytes(b'one')
            before = mw00.manifest(root)
            self.assertEqual(before, mw00.manifest(root))
            (root / 'a').write_bytes(b'two')
            self.assertNotEqual(before, mw00.manifest(root))
            (root / 'b').write_bytes(b'two')
            self.assertEqual(len(mw00.manifest(root)), 2)

    def test_certification_is_not_automatically_a_new_admission(self):
        records = [{'n': '2', 'result': {'status': 'CERTIFIED_EMPTY'}},
                   {'n': '3', 'result': {'status': 'CERTIFIED_EMPTY'}},
                   {'n': '3', 'result': {'status': 'CERTIFIED_EMPTY'}},
                   {'n': '5', 'result': {'status': 'INCONCLUSIVE'}}]
        result = mw00.reconcile({2}, {2, 3}, records)
        self.assertEqual(result['new_admissions'], [3])
        self.assertEqual(result['certified_result_rows'], 3)
        self.assertEqual(result['certified_distinct_n'], [2, 3])

    def test_missing_commit_is_not_counted_as_admitted(self):
        result = mw00.reconcile({2}, {2}, [{'n': '3', 'result': {'status': 'CERTIFIED_EMPTY'}}])
        self.assertEqual(result['certified_without_current_admission'], [3])


if __name__ == '__main__':
    unittest.main()
