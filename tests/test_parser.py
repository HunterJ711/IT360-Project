import tempfile
import unittest
from pathlib import Path

from evitriage.parser import parse_events


class ParserTests(unittest.TestCase):
    def test_csv_is_parsed_and_sorted(self):
        content = "timestamp,event_id,computer,user,source_ip,outcome,action,details\n2026-01-02T00:00:00+00:00,4624,PC,a,1.2.3.4,success,login,x\n2026-01-01T00:00:00+00:00,4625,PC,a,1.2.3.4,failure,login,y\n"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.csv"
            path.write_text(content, encoding="utf-8")
            events = parse_events(path)
        self.assertEqual([4625, 4624], [event.event_id for event in events])

    def test_missing_required_fields_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.json"
            path.write_text('[{"user":"a"}]', encoding="utf-8")
            with self.assertRaises(ValueError):
                parse_events(path)


if __name__ == "__main__":
    unittest.main()

