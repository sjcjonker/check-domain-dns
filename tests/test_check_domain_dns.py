import unittest
from unittest import mock
import tempfile
import importlib.util
from pathlib import Path

PLUGIN = Path(__file__).resolve().parents[1] / "check_domain_dns.py"
spec = importlib.util.spec_from_file_location("check_domain_dns", PLUGIN)
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)


class DomainDNS(unittest.TestCase):
    def test_record_selection(self):
        plan = plugin.make_plan("example.org", {"www", "caa"})
        self.assertEqual(len(plan), 4)
        self.assertNotIn("www.example.org.|A", plan)

    def test_sorted_set_comparison(self):
        self.assertEqual(plugin.differences({"a": ["x", "y"]}, {"a": ["y", "x"]}), [])
        self.assertTrue(plugin.differences({"a": ["x"]}, {"a": ["z"]}))

    def test_baseline_roundtrip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "example.org.json"
            records = {key: [] for key in plugin.make_plan("example.org", set())}
            document = {"schema": 1, "domain": "example.org", "exclude": [], "records": records}
            plugin.save_state(path, document, False)
            loaded, _ = plugin.load_state(path, "example.org")
            self.assertEqual(loaded["records"], records)
            with self.assertRaises(FileExistsError):
                plugin.save_state(path, document, False)

    def test_invalid_domain(self):
        import argparse
        with self.assertRaises(argparse.ArgumentTypeError):
            plugin.domain_name("../../etc/passwd")

    def test_empty_answers_not_failure(self):
        answer = mock.MagicMock()
        answer.rrset = None
        resolver = mock.Mock()
        resolver.resolve.return_value = answer
        records, errors = plugin.query_plan({"example.org.|CAA": ("example.org.", "CAA")}, resolver)
        self.assertEqual(records, {"example.org.|CAA": []})
        self.assertFalse(errors)

    def test_query_failures(self):
        import dns.resolver
        resolver = mock.Mock()
        resolver.resolve.side_effect = dns.resolver.NXDOMAIN
        records, errors = plugin.query_plan({"example.org.|NS": ("example.org.", "NS")}, resolver)
        self.assertFalse(records)
        self.assertEqual(len(errors), 1)


if __name__ == "__main__":
    unittest.main()
