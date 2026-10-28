"""Condition/subject grammar tests: positive coverage plus mutation negatives."""
import unittest
from oci_iam_analyzer import analyze, parse_statement
from oci_iam_analyzer.conditions import (
    Comparison, ConditionError, SetExpr, describe, parse_condition, variables,
)


class ConditionParserTests(unittest.TestCase):
    def test_single_comparison(self):
        node = parse_condition("request.permission='INSTANCE_CREATE'")
        self.assertEqual(node, Comparison("request.permission", "=", "INSTANCE_CREATE"))
        self.assertEqual(variables(node), ["request.permission"])

    def test_any_and_all_sets(self):
        any_node = parse_condition("any { request.permission='A', request.permission='B' }")
        self.assertIsInstance(any_node, SetExpr)
        self.assertEqual(any_node.kind, "any")
        self.assertEqual(len(any_node.items), 2)
        all_node = parse_condition("all { request.operation='Create', target.compartment.id='ocid1.x' }")
        self.assertEqual(all_node.kind, "all")
        self.assertEqual(sorted(variables(all_node)), ["request.operation", "target.compartment.id"])

    def test_dotted_variable_references(self):
        node = parse_condition("target.resource.type='instance'")
        self.assertEqual(describe(node)["variable"], "target.resource.type")

    def test_not_equal_operator(self):
        node = parse_condition("request.operation!='DeleteInstance'")
        self.assertEqual(node.operator, "!=")

    def test_mutation_negatives_rejected(self):
        mutations = [
            'request.operation="X"',        # double quotes
            "request.operation=='X'",       # doubled operator
            "request.operation=X",          # unquoted value
            "any { }",                      # empty set
            "any { request.permission='X', }",  # trailing comma
            "all { any { request.permission='X' } }",  # nested set
            "request.permission='X",        # unterminated quote
            "request.permission='X' extra", # trailing content
            "any { request.permission='X' ",  # missing closing brace
            "request.permission",           # no operator/value
        ]
        for text in mutations:
            with self.subTest(text=text):
                with self.assertRaises(ConditionError):
                    parse_condition(text)

    def test_unknown_variable_rejected(self):
        with self.assertRaises(ConditionError):
            parse_condition("made.up.variable='X'")


class SubjectGrammarTests(unittest.TestCase):
    def test_any_user_supported_and_scored(self):
        f = analyze([parse_statement("Allow any-user to read instances in tenancy", 1)])["findings"][0]
        self.assertTrue(f["supported"])
        self.assertEqual(f["score"], 10 + 15 + 20)
        self.assertTrue(any(s["kind"] == "subject-breadth" for s in f["signals"]))

    def test_ocid_subjects_supported_with_limitation(self):
        for subj in ("group id ocid1.group.oc1..abc", "dynamic-group id ocid1.dynamicgroup.oc1..xyz"):
            with self.subTest(subj=subj):
                f = analyze([parse_statement(f"Allow {subj} to read instances in compartment Lab", 1)])["findings"][0]
                self.assertTrue(f["supported"])
                self.assertTrue(any("OCID subject" in l for l in f["limitations"]))

    def test_parsed_condition_keeps_score_and_describes(self):
        f = analyze([parse_statement(
            "Allow group ScopedOps to manage instances in compartment Sandbox where request.permission='INSTANCE_CREATE'", 4, "LabOperators")])["findings"][0]
        self.assertTrue(f["supported"])
        self.assertEqual(f["score"], 45)
        self.assertEqual(f["condition"]["variable"], "request.permission")
        self.assertTrue(any("not evaluated" in l for l in f["limitations"]))

    def test_unsupported_condition_stays_manual_review(self):
        for text in (
            'Allow group g to manage instances in tenancy where all {request.permission="X"}',
            "Allow group g to manage instances in tenancy where unknown.var='X'",
        ):
            with self.subTest(text=text):
                f = analyze([parse_statement(text, 1)])["findings"][0]
                self.assertFalse(f["supported"])
                self.assertEqual(f["review_priority"], "manual-review")
                self.assertNotIn("score", f)
                self.assertTrue(any("condition unsupported" in l for l in f["limitations"]))

    def test_raw_statement_and_citation_preserved(self):
        raw = "Allow group g to use instances in tenancy where any { request.permission='A', request.permission='B' }"
        f = analyze([parse_statement(raw, 3, "CondPolicy")])["findings"][0]
        self.assertEqual(f["statement"], raw)
        self.assertEqual(f["citation"], "CondPolicy#statement-3")


if __name__ == "__main__":
    unittest.main()
