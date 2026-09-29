import json
import tempfile
import unittest
from pathlib import Path
from oci_iam_analyzer import analyze, load_export, parse_statement
from oci_iam_analyzer.cli import main

ROOT = Path(__file__).resolve().parents[1]

class ParserTests(unittest.TestCase):
    def test_mixed_case_and_whitespace(self):
        s = parse_statement(' ALLOW   Group Analysts TO ReAd instances IN compartment A:B ', 2, 'p')
        self.assertTrue(s.supported)
        self.assertEqual((s.subject, s.verb, s.scope, s.citation), ('Analysts', 'read', 'compartment a:b', 'p#statement-2'))

    def test_unknown_not_safe(self):
        for text in ('Allow any-user to manage all-resources in tenancy',
                     'Allow group id ocid1.group.oc1..abc to manage all-resources in tenancy',
                     'Allow group g to manage instances in tenancy where all {request.permission="X"}',
                     'Deny group g to read objects in tenancy', ''):
            with self.subTest(text=text):
                f = analyze([parse_statement(text, 1)])["findings"][0]
                self.assertFalse(f['supported'])
                self.assertEqual(f['review_priority'], 'manual-review')
                self.assertNotIn('score', f)

    def test_cited_findings_and_no_auto_rewrite(self):
        r = analyze(load_export(ROOT/'examples/synthetic.json'))
        self.assertEqual(r['summary'], {'total': 5, 'supported': 4, 'manual_review': 1, 'high': 1})
        self.assertEqual([f['citation'] for f in r['findings']],
                         ['LabOperators#statement-1','LabOperators#statement-2',
                          'LabOperators#statement-3','LabOperators#statement-4','AuditReaders#statement-1'])
        self.assertEqual(r['findings'][0]['score'], 95)
        self.assertEqual(r['findings'][1]['score'], 10)
        self.assertEqual(r['findings'][2]['score'], 40)
        self.assertEqual(r['findings'][3]['review_priority'], 'manual-review')
        self.assertTrue(all('rewrite' not in f for f in r['findings']))

    def test_validation(self):
        for data in ({'policies': []}, {'policies':[{'name':'X','statements':[]}]},
                     {'policies':[{'name':'X','statements':['hi']},{'name':'X','statements':['hi']}]}):
            with tempfile.TemporaryDirectory() as d:
                p = Path(d)/'x.json'; p.write_text(json.dumps(data))
                with self.assertRaises(ValueError): load_export(p)

    def test_cli_gate(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d)/'report.json'
            self.assertEqual(main([str(ROOT/'examples/synthetic.json'), '--output', str(out)]), 0)
            self.assertEqual(main([str(ROOT/'examples/synthetic.json'), '--output', str(out), '--fail-on-manual-review']), 2)
            self.assertEqual(json.loads(out.read_text())['summary']['total'], 5)

    def test_clean_policy_gate(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/'clean.json'
            p.write_text(json.dumps({'policies':[{'name':'Clean','statements':['Allow group g to read instances in compartment Lab']}]}))
            self.assertEqual(main([str(p), '--output', str(Path(d)/'out.json'), '--fail-on-manual-review']), 0)

if __name__ == '__main__': unittest.main()
