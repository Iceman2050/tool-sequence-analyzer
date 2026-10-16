"""Tests for tool-sequence-analyzer."""
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from toolseq.analyzer import (  # noqa: E402
    analyze,
    chain_to_mermaid,
    interesting_tokens,
    load_events,
    load_tool_map,
    system_of,
)

FIX = os.path.join(REPO, "tests", "fixtures")
MAPPING, DEFAULT = load_tool_map(os.path.join(REPO, "default_tools.yaml"))


class TestToolMap(unittest.TestCase):
    def test_default_map_loads(self):
        self.assertGreater(len(MAPPING), 20)
        self.assertEqual(MAPPING["shell.exec"], "admin")
        self.assertEqual(MAPPING["crm.get_contact"], "read-sensitive")
        self.assertEqual(MAPPING["email.send"], "write-sensitive")
        self.assertEqual(DEFAULT, "read-low")

    def test_mini_yaml_parsing(self):
        from toolseq.analyzer import parse_tools_yaml

        mapping, default = parse_tools_yaml(
            "# comment\ntools:\n  my.tool: admin\ndefault_level: read-low\n"
        )
        self.assertEqual(mapping["my.tool"], "admin")
        self.assertEqual(default, "read-low")

    def test_system_extraction(self):
        self.assertEqual(
            system_of({"tool": "x", "args": {"system": "crm"}}), "crm"
        )
        self.assertEqual(system_of({"tool": "crm.get_contact", "args": {}}), "crm")
        self.assertEqual(system_of({"tool": "lonely", "args": {}}), "default")


class TestPlantedChain(unittest.TestCase):
    def setUp(self):
        self.events = load_events(os.path.join(FIX, "planted-chain.jsonl"))
        self.chains = analyze(self.events, MAPPING, DEFAULT, window=6)
        self.rules = {c["rule"] for c in self.chains}

    def test_all_three_rules_fire(self):
        self.assertIn("cross-boundary", self.rules)  # crm read -> mail write
        self.assertIn("escalation", self.rules)  # fs.read -> db.write
        self.assertIn("data-smuggling", self.rules)  # shell.exec args carry vault secret

    def test_smuggling_names_the_secret(self):
        smug = [c for c in self.chains if c["rule"] == "data-smuggling"]
        self.assertTrue(smug)
        self.assertIn("whsec_7HkP2mQx9vRt4YzA", smug[0]["explanation"])

    def test_cross_boundary_names_systems(self):
        cross = [c for c in self.chains if c["rule"] == "cross-boundary"]
        self.assertTrue(cross)
        self.assertIn("crm", cross[0]["explanation"])
        self.assertIn("mail", cross[0]["explanation"])

    def test_ranked_smuggling_first(self):
        self.assertEqual(self.chains[0]["rule"], "data-smuggling")

    def test_mermaid_rendered(self):
        for c in self.chains:
            mm = chain_to_mermaid(c)
            self.assertIn("flowchart", mm)
            self.assertIn(c["rule"], mm)
        smug = [c for c in self.chains if c["rule"] == "data-smuggling"][0]
        self.assertIn("shell.exec", smug["mermaid"])


class TestBenign(unittest.TestCase):
    def test_benign_is_clean(self):
        events = load_events(os.path.join(FIX, "benign.jsonl"))
        self.assertEqual(len(events), 6)
        chains = analyze(events, MAPPING, DEFAULT, window=6)
        self.assertEqual(chains, [])


class TestEdgeCases(unittest.TestCase):
    def test_empty_log(self):
        events = load_events(os.path.join(FIX, "empty.jsonl"))
        self.assertEqual(events, [])
        self.assertEqual(analyze(events, MAPPING, DEFAULT), [])

    def test_single_call(self):
        events = load_events(os.path.join(FIX, "single.jsonl"))
        self.assertEqual(len(events), 1)
        self.assertEqual(analyze(events, MAPPING, DEFAULT), [])

    def test_malformed_lines_skipped(self):
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as fh:
            fh.write("not json at all\n")
            fh.write('{"tool": "fs.read", "args": {}, "result_summary": "ok"}\n')
            path = fh.name
        try:
            events = load_events(path)
            self.assertEqual(len(events), 1)
        finally:
            os.unlink(path)

    def test_unknown_tool_uses_default(self):
        chains = analyze(
            [
                {"ts": "t", "tool": "mystery.tool", "args": {}, "result_summary": "x"},
                {"ts": "t", "tool": "db.write", "args": {"system": "warehouse"},
                 "result_summary": "y"},
            ],
            MAPPING,
            "read-low",
        )
        self.assertTrue(any(c["rule"] == "escalation" for c in chains))

    def test_tokens(self):
        self.assertIn("whsec_7HkP2mQx9vRt4YzA",
                      interesting_tokens("secret whsec_7HkP2mQx9vRt4YzA here"))
        self.assertEqual(interesting_tokens("short words only"), [])


if __name__ == "__main__":
    unittest.main()
