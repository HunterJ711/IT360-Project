import json
import os
import unittest
from pathlib import Path
from unittest.mock import patch

from evitriage.ai import AIUnavailable, analyze_with_sushi, serialize_findings, validate_analysis
from evitriage.detector import detect
from evitriage.evidence import describe_evidence
from evitriage.parser import parse_events
from evitriage.report import generate_report
from evitriage.cli import main

PATH = Path(__file__).parents[1] / "data" / "sample_incident.csv"


def sample():
    events = parse_events(PATH)
    return events, detect(events)


def result(findings):
    return {
        "incident_summary": "Suspicious authentication activity warrants review.",
        "finding_explanations": [
            {"finding_index": i, "explanation": f"Review finding {i} carefully."}
            for i in range(1, len(findings) + 1)
        ],
        "investigative_next_steps": ["Verify login with account owner."],
    }


class FakeResponse:
    def __init__(self, content):
        self.content = content

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def read(self, size=-1):
        return json.dumps({"choices": [{"message": {"content": self.content}}]}).encode()


class AITests(unittest.TestCase):
    def test_serialization_preserves_originals(self):
        _, findings = sample()
        original = findings[0].evidence[0].timestamp
        serialized = serialize_findings(findings)
        self.assertEqual(serialized[0]["rule_id"], findings[0].rule_id)
        self.assertEqual(findings[0].evidence[0].timestamp, original)
        self.assertIsInstance(serialized[0]["evidence"][0]["timestamp"], str)

    def test_validation_rejects_invalid_data(self):
        _, findings = sample()
        data = result(findings)
        self.assertEqual(len(validate_analysis(data, len(findings)).finding_explanations), len(findings))
        for bad in [{**data, "severity": "Low"}, {**data, "finding_explanations": []},
                    {**data, "finding_explanations": [{"finding_index": 99, "explanation": "wrong"}] * len(findings)}]:
            with self.assertRaises(AIUnavailable):
                validate_analysis(bad, len(findings))

    @patch.dict(os.environ, {"SUSHI_API_KEY": "test-only-fake-key"})
    @patch("evitriage.ai.urlopen")
    def test_mock_api(self, urlopen):
        events, findings = sample()
        urlopen.return_value = FakeResponse(json.dumps(result(findings)))
        analysis = analyze_with_sushi(findings)
        self.assertIn("authentication", analysis.incident_summary)
        request = urlopen.call_args.args[0]
        self.assertEqual(request.get_header("Authorization"), "Bearer test-only-fake-key")
        self.assertEqual(json.loads(request.data)["model"], "llama3.1:latest")
        report = generate_report(describe_evidence(PATH), events, findings, ai_analysis=analysis)
        self.assertIn("AI interpretation — advisory only", report)
        self.assertIn("## Chronological Timeline", report)
        self.assertIn("SUCCESS_AFTER_FAILURES", report)

    @patch.dict(os.environ, {"SUSHI_API_KEY": "test-only-fake-key"})
    @patch("evitriage.ai.urlopen")
    def test_invalid_json_falls_back(self, urlopen):
        urlopen.return_value = FakeResponse("not json")
        with self.assertRaises(AIUnavailable):
            analyze_with_sushi(sample()[1])

    @patch.dict(os.environ, {"SUSHI_API_KEY": ""})
    def test_cli_falls_back_without_key(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as folder:
            output = Path(folder) / "report.md"
            self.assertEqual(main(["analyze", str(PATH), "--ai", "-o", str(output)]), 0)
            report = output.read_text()
            self.assertIn("AI interpretation unavailable", report)
            self.assertIn("## Findings", report)
            self.assertIn("## Chronological Timeline", report)

    @patch.dict(os.environ, {"SUSHI_API_KEY": "test-only-fake-key"})
    @patch("evitriage.ai.urlopen", side_effect=TimeoutError("request timed out"))
    def test_timeout_falls_back(self, urlopen):
        with self.assertRaises(AIUnavailable):
            analyze_with_sushi(sample()[1])


if __name__ == "__main__":
    unittest.main()
