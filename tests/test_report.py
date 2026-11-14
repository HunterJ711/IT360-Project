import unittest
from pathlib import Path

from evitriage.detector import detect
from evitriage.evidence import describe_evidence
from evitriage.parser import parse_events
from evitriage.report import generate_report


class ReportTests(unittest.TestCase):
    def test_report_separates_evidence_and_ai_status(self):
        path = Path(__file__).parents[1] / "data" / "sample_incident.csv"
        events = parse_events(path)
        report = generate_report(describe_evidence(path), events, detect(events))
        self.assertIn("## Evidence Integrity", report)
        self.assertIn("SHA-256", report)
        self.assertIn("## Chronological Timeline", report)
        self.assertIn("AI enhancement was not enabled", report)


if __name__ == "__main__":
    unittest.main()

