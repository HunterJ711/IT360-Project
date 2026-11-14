import unittest
from pathlib import Path

from evitriage.detector import detect
from evitriage.parser import parse_events


class DetectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.events = parse_events(Path(__file__).parents[1] / "data" / "sample_incident.csv")
        cls.findings = detect(cls.events)

    def test_expected_rules_fire(self):
        rules = {finding.rule_id for finding in self.findings}
        self.assertEqual({"AUTH_FAILURE_BURST", "SUCCESS_AFTER_FAILURES", "ACCOUNT_CREATED", "SPECIAL_PRIVILEGES"}, rules)

    def test_success_after_failures_is_high(self):
        finding = next(item for item in self.findings if item.rule_id == "SUCCESS_AFTER_FAILURES")
        self.assertEqual("High", finding.severity)
        self.assertEqual(6, len(finding.evidence))


if __name__ == "__main__":
    unittest.main()

