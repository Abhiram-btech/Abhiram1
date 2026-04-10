import tempfile
import unittest
from pathlib import Path

from automation.parser import load_events


class ParserTests(unittest.TestCase):
    def test_load_events_reads_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "sysmon_events.jsonl").write_text(
                '{"EventID":1,"Image":"powershell.exe"}\n', encoding="utf-8"
            )

            events = load_events(tmpdir)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["log_type"], "sysmon")
            self.assertEqual(events[0]["_source_file"], "sysmon_events.jsonl")


if __name__ == "__main__":
    unittest.main()
