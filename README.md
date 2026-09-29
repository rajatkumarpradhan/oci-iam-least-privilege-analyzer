# oci-iam-least-privilege-analyzer

An **offline static review** of OCI IAM policy statements. It parses a conservative subset of `Allow group` and `Allow dynamic-group` statements from a JSON export, scores the breadth of verbs, resource types and scope, and returns review options tied to the exact policy/statement index. It **never edits policies**, guesses permission equivalence or claims effective-access analysis.

> **Portfolio project.** The included policies and groups are synthetic. No OCI account or live tenancy was connected or tested; scores are review priorities, not vulnerability counts or proof of least privilege. This is not a security certification.

## Quickstart

```bash
python -m pip install -e .
oci-iam-review examples/synthetic.json --output report.json
python -m unittest discover -s tests -v
```

Input: `{"policies":[{"name":"Name","statements":["Allow group G to read instances in compartment Lab"]}]}`. This is a **project-defined JSON interchange format**, not a claim that OCI exports policies in this precise shape. Convert your own export into it offline. Policy names must be unique to keep citations unambiguous.

Each finding carries its raw statement and a citation such as `LabOperators#statement-1`, a transparent risk score where supported, concrete breadth signals, and questions for a human reviewer. The example has five statements: four supported and one condition deliberately flagged `manual-review`. `--fail-on-manual-review` makes CI exit 2 for such statements; without it, reporting still succeeds. The test suite uses an asserted synthetic eval gate: one high-priority broad grant, a lower-priority narrow grant, a flagged condition and citations to all five source indices.

## Supported subset and conservative limits

- Simple `Allow group <name>` or `Allow dynamic-group <name>`; `inspect/read/use/manage`; resource token; `in tenancy` or `in compartment <name-or-path>`. Keywords are case-insensitive. Subject names and compartment paths are preserved for citation but are **not resolved**.
- Conditions, `any-user`, OCID subject syntax, permissions selector syntax and other complex statements return `manual-review` with **no numeric score**. This avoids silently marking unknown policy shapes safe. Conditions may narrow privileges; this tool intentionally does not evaluate them.
- Simple heuristic: `inspect/read/use/manage` contributes 0/10/25/45; `all-resources` +30, `*-family` +15, tenancy +20, capped at 100. 70+ high, 35+ medium, otherwise low. These weights are **our reviewer triage convention**, not an Oracle rule.
- Suggested reductions are questions, **not deployable rewritten policy statements**. The correct narrower verb, compartment and resource types depend on application operations, resource-specific permissions and tests. Actual effective access can include other policies and membership; a static statement cannot prove it.

## References

- Oracle, [Policy Syntax](https://docs.oracle.com/en-us/iaas/Content/Identity/Concepts/policysyntax.htm): `Allow <subject> to <verb> <resource-type> in <location> where <conditions>`, family types, tenancy/compartment scope.
- Oracle, [IAM Security Policies](https://docs.oracle.com/en-us/iaas/Content/Security/Reference/iam_security_topic-IAM_Security_Policies.htm): verb order and guidance to assign least-privilege access. The scoring weights above are not from Oracle.

## Roadmap

Support more OCI policy grammar without losing conservative failure behavior; add an opt-in permission mapping backed by versioned OCI service reference data and human approval before any proposed rewrite.
