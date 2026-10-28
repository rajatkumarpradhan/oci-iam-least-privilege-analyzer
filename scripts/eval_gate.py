"""Misclassification eval gate: every fixture case must classify as expected."""
import json
import sys
from pathlib import Path

from oci_iam_analyzer import analyze, parse_statement
from oci_iam_analyzer.conditions import variables

def main() -> int:
    fixture = json.loads((Path(__file__).resolve().parents[1] / "examples" / "conditions.json").read_text(encoding="utf-8"))
    failures = 0
    for i, case in enumerate(fixture["cases"], 1):
        stmt = parse_statement(case["statement"], i, "eval-fixture")
        finding = analyze([stmt])["findings"][0]
        got = "supported" if finding["supported"] else "manual-review"
        problems = []
        if got != case["expect"]:
            problems.append(f"classification: expected {case['expect']}, got {got}")
        if case.get("set") and finding.get("condition", {}).get("kind") != case["set"]:
            problems.append(f"set kind: expected {case['set']}, got {finding.get('condition', {}).get('kind')}")
        if case.get("variables"):
            want = sorted(case["variables"])
            have = sorted(finding.get("condition") and variables(stmt.condition_ast) or [])
            if have != want:
                problems.append(f"variables: expected {want}, got {have}")
        status = "FAIL" if problems else "PASS"
        failures += bool(problems)
        print(f"{status} case {i}: {case['statement'][:72]}..." if len(case["statement"]) > 72 else f"{status} case {i}: {case['statement']}")
        for p in problems:
            print(f"      {p}")
    print(f"eval gate: {len(fixture['cases']) - failures}/{len(fixture['cases'])} cases classified as expected")
    return 1 if failures else 0

if __name__ == "__main__":
    sys.exit(main())
