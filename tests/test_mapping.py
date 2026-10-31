"""Versioned mapping lookup and draft-candidate safety."""
import json
from pathlib import Path

import pytest

from oci_iam_analyzer.mapping import (MappingError, build_candidate, load_mapping,
                                      load_required, operation_status, suggest)
from oci_iam_analyzer.parser import load_export, parse_statement

FIXTURES = Path(__file__).resolve().parents[1] / "examples"


def stmt(raw, index=1):
    return parse_statement(raw, index, "policy")


def test_packaged_mapping_has_version_source_and_resources():
    m = load_mapping()
    assert m.version == "2026-11-01.core.1"
    assert "docs.oracle.com" in m.source["url"]
    assert m.source["checked"]
    assert {"instances", "volume-attachments", "vnics"} <= set(m.resources)


def test_verified_narrowest_verb():
    m = load_mapping()
    assert operation_status(m, "instances", "INSTANCE_READ") == ("verified", "read")
    assert operation_status(m, "instances", "INSTANCE_POWER_ACTIONS") == ("verified", "use")
    assert operation_status(m, "instances", "INSTANCE_DELETE") == ("verified", "manage")


def test_unknown_operation_is_not_narrowed():
    m = load_mapping()
    assert operation_status(m, "instances", "INSTANCE_DO_TELEPORT")[0] == "unknown-operation"
    c = build_candidate(m, stmt("Allow group Ops to manage instances in compartment Sandbox"),
                        "instances", ["INSTANCE_READ", "INSTANCE_DO_TELEPORT"])
    assert c["status"] == "unknown-operation"
    assert c["after"] is None  # no silent narrowing despite one verified op
    assert any("INSTANCE_DO_TELEPORT" in a for a in c["unresolved_assumptions"])


def test_missing_mapping_is_not_narrowed():
    m = load_mapping()
    assert operation_status(m, "buckets", "OBJECT_CREATE")[0] == "missing-mapping"
    c = build_candidate(m, stmt("Allow group Ops to manage buckets in compartment Sandbox"),
                        "buckets", ["OBJECT_CREATE"])
    assert c["status"] == "missing-mapping"
    assert c["after"] is None


def test_candidate_before_after_with_evidence():
    m = load_mapping()
    before = stmt("Allow group LabReaders to read instances in compartment Sandbox")
    c = build_candidate(m, before, "instances", ["INSTANCE_READ", "INSTANCE_POWER_ACTIONS"])
    assert c["status"] == "verified"
    assert c["after"]["statement"] == (
        "Allow group LabReaders to use instances in compartment sandbox")
    assert c["after"]["evidence"] == [f"{m.version}:instances/use"]
    assert c["before"]["statement"].startswith("Allow group LabReaders")
    assert any("workload owner" in a for a in c["unresolved_assumptions"])


def test_condition_preserved_and_flagged():
    m = load_mapping()
    before = stmt("Allow group ScopedOps to manage instances in compartment Sandbox "
                  "where request.permission='INSTANCE_CREATE'")
    c = build_candidate(m, before, "instances", ["INSTANCE_CREATE"])
    assert c["status"] == "verified"
    assert "where request.permission='INSTANCE_CREATE'" in c["after"]["statement"]
    assert any("condition" in a.lower() for a in c["unresolved_assumptions"])


def test_no_false_narrowing_for_any_verified_candidate():
    """Every required op of a verified candidate must sit inside its suggested verb."""
    m = load_mapping()
    statements = load_export(FIXTURES / "synthetic.json")
    report = suggest(m, statements, load_required(FIXTURES / "required-ops.json"))
    for c in report["candidates"]:
        if c["status"] != "verified":
            continue
        covering = set(m.resources[c["resource"]][c["after"]["verb"]])
        for op in c["operations"]:
            assert op["operation"] in covering


def test_suggest_example_pairs_requirements_and_reports_guidance():
    m = load_mapping()
    report = suggest(m, load_export(FIXTURES / "synthetic.json"),
                     load_required(FIXTURES / "required-ops.json"))
    assert report["draft"] is True and report["human_approval_required"] is True
    assert report["mapping_version"] == m.version
    assert "real tenancy" in report["validation_guidance"]
    assert report["summary"]["requirements"] == 2
    assert report["summary"]["verified"] >= 1
    assert "volume-attachments" in report["unmatched_requirements"]  # no such statement in the export
    for c in report["candidates"]:
        assert c["before"]["citation"]


def test_required_file_validation(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"nope": true}')
    with pytest.raises(MappingError):
        load_required(bad)
    with pytest.raises(MappingError):
        load_required(tmp_path / "missing.json")


def test_mapping_rejects_unknown_verb(tmp_path):
    bad = tmp_path / "m.json"
    bad.write_text(json.dumps({"mapping_version": "x", "source": {"url": "u"},
                               "resources": {"r": {"teleport": ["X"]}}}))
    with pytest.raises(MappingError):
        load_mapping(bad)
