"""Versioned mapping lookup and draft-candidate safety."""
import json
import tempfile
import unittest
from pathlib import Path

from oci_iam_analyzer.mapping import (MappingError, build_candidate, load_mapping,
                                      load_required, operation_status, suggest)
from oci_iam_analyzer.parser import load_export, parse_statement

FIXTURES = Path(__file__).resolve().parents[1] / "examples"


def stmt(raw, index=1):
    return parse_statement(raw, index, "policy")


class MappingTests(unittest.TestCase):
    def test_packaged_mapping_has_version_source_and_resources(self):
        m = load_mapping()
        self.assertEqual(m.version, "2026-11-01.core.1")
        self.assertIn("docs.oracle.com", m.source["url"])
        self.assertTrue(m.source["checked"])
        self.assertLessEqual({"instances", "volume-attachments", "vnics"}, set(m.resources))

    def test_verified_narrowest_verb(self):
        m = load_mapping()
        self.assertEqual(operation_status(m, "instances", "INSTANCE_READ"), ("verified", "read"))
        self.assertEqual(operation_status(m, "instances", "INSTANCE_POWER_ACTIONS"), ("verified", "use"))
        self.assertEqual(operation_status(m, "instances", "INSTANCE_DELETE"), ("verified", "manage"))

    def test_unknown_operation_is_not_narrowed(self):
        m = load_mapping()
        self.assertEqual(operation_status(m, "instances", "INSTANCE_DO_TELEPORT")[0], "unknown-operation")
        c = build_candidate(m, stmt("Allow group Ops to manage instances in compartment Sandbox"),
                            "instances", ["INSTANCE_READ", "INSTANCE_DO_TELEPORT"])
        self.assertEqual(c["status"], "unknown-operation")
        self.assertIsNone(c["after"])  # no silent narrowing despite one verified op
        self.assertTrue(any("INSTANCE_DO_TELEPORT" in a for a in c["unresolved_assumptions"]))

    def test_missing_mapping_is_not_narrowed(self):
        m = load_mapping()
        self.assertEqual(operation_status(m, "buckets", "OBJECT_CREATE")[0], "missing-mapping")
        c = build_candidate(m, stmt("Allow group Ops to manage buckets in compartment Sandbox"),
                            "buckets", ["OBJECT_CREATE"])
        self.assertEqual(c["status"], "missing-mapping")
        self.assertIsNone(c["after"])

    def test_candidate_before_after_with_evidence(self):
        m = load_mapping()
        before = stmt("Allow group LabReaders to read instances in compartment Sandbox")
        c = build_candidate(m, before, "instances", ["INSTANCE_READ", "INSTANCE_POWER_ACTIONS"])
        self.assertEqual(c["status"], "verified")
        self.assertEqual(c["after"]["statement"],
                         "Allow group LabReaders to use instances in compartment sandbox")
        self.assertEqual(c["after"]["evidence"], [f"{m.version}:instances/use"])
        self.assertTrue(c["before"]["statement"].startswith("Allow group LabReaders"))
        self.assertTrue(any("workload owner" in a for a in c["unresolved_assumptions"]))

    def test_condition_preserved_and_flagged(self):
        m = load_mapping()
        before = stmt("Allow group ScopedOps to manage instances in compartment Sandbox "
                      "where request.permission='INSTANCE_CREATE'")
        c = build_candidate(m, before, "instances", ["INSTANCE_CREATE"])
        self.assertEqual(c["status"], "verified")
        self.assertIn("where request.permission='INSTANCE_CREATE'", c["after"]["statement"])
        self.assertTrue(any("condition" in a.lower() for a in c["unresolved_assumptions"]))

    def test_no_false_narrowing_for_any_verified_candidate(self):
        """Every required op of a verified candidate must sit inside its suggested verb."""
        m = load_mapping()
        statements = load_export(FIXTURES / "synthetic.json")
        report = suggest(m, statements, load_required(FIXTURES / "required-ops.json"))
        for c in report["candidates"]:
            if c["status"] != "verified":
                continue
            covering = set(m.resources[c["resource"]][c["after"]["verb"]])
            for op in c["operations"]:
                self.assertIn(op["operation"], covering)

    def test_suggest_example_pairs_requirements_and_reports_guidance(self):
        m = load_mapping()
        report = suggest(m, load_export(FIXTURES / "synthetic.json"),
                         load_required(FIXTURES / "required-ops.json"))
        self.assertTrue(report["draft"])
        self.assertTrue(report["human_approval_required"])
        self.assertEqual(report["mapping_version"], m.version)
        self.assertIn("real tenancy", report["validation_guidance"])
        self.assertEqual(report["summary"]["requirements"], 2)
        self.assertGreaterEqual(report["summary"]["verified"], 1)
        self.assertIn("volume-attachments", report["unmatched_requirements"])
        for c in report["candidates"]:
            self.assertTrue(c["before"]["citation"])

    def test_required_file_validation(self):
        with tempfile.TemporaryDirectory() as d:
            bad = Path(d) / "bad.json"
            bad.write_text('{"nope": true}')
            with self.assertRaises(MappingError):
                load_required(bad)
            with self.assertRaises(MappingError):
                load_required(Path(d) / "missing.json")

    def test_mapping_rejects_unknown_verb(self):
        with tempfile.TemporaryDirectory() as d:
            bad = Path(d) / "m.json"
            bad.write_text(json.dumps({"mapping_version": "x", "source": {"url": "u"},
                                       "resources": {"r": {"teleport": ["X"]}}}))
            with self.assertRaises(MappingError):
                load_mapping(bad)


if __name__ == "__main__":
    unittest.main()
