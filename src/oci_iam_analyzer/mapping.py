"""Versioned OCI resource-to-permission reference data and draft least-privilege candidates.

The mapping is opt-in reference data with a cited source and version. Three
distinct outcomes are possible per required operation and they are NEVER
merged silently:

- verified: the operation appears in the mapping for that resource; the
  narrowest verb covering it can be named, with the mapping entry as evidence.
- unknown-operation: the resource is mapped but this operation is not in it;
  nothing is narrowed for that requirement.
- missing-mapping: the resource is not in the reference data at all.

A draft candidate statement is produced only for a requirement whose every
operation is verified. Nothing here applies or rewrites a policy: the output
is a review artifact that needs human approval and real-tenant validation.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .parser import VERBS, Statement

_DEFAULT_DATA = Path(__file__).resolve().parent / "data" / "permissions.json"


class MappingError(ValueError):
    pass


@dataclass(frozen=True)
class Mapping:
    version: str
    source: dict
    resources: dict  # resource -> verb -> [permissions]


def load_mapping(path: str | Path | None = None) -> Mapping:
    p = Path(path) if path else _DEFAULT_DATA
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
        version = raw["mapping_version"]
        source = raw["source"]
        resources = raw["resources"]
        assert version and source.get("url") and isinstance(resources, dict)
        for res, verbs in resources.items():
            for v in verbs:
                if v not in VERBS:
                    raise MappingError(f"mapping {res}: unknown verb {v!r}")
    except (OSError, json.JSONDecodeError, KeyError, AssertionError) as e:
        raise MappingError(f"cannot load permission mapping {p}: {e}") from e
    return Mapping(version, source, resources)


def operation_status(mapping: Mapping, resource: str, operation: str) -> tuple[str, str | None]:
    """(status, narrowest verb covering the operation).

    status is "missing-mapping", "unknown-operation", or "verified".
    """
    if resource not in mapping.resources:
        return ("missing-mapping", None)
    for verb in VERBS:  # inspect < read < use < manage
        if operation in mapping.resources[resource].get(verb, []):
            return ("verified", verb)
    return ("unknown-operation", None)


def build_candidate(mapping: Mapping, stmt: Statement, resource: str,
                    operations: list[str]) -> dict:
    """One requirement vs one existing statement -> draft review artifact."""
    per_op = []
    narrowest_idx = -1
    unknown = []
    for op in operations:
        status, verb = operation_status(mapping, resource, op)
        per_op.append({"operation": op, "status": status,
                       "covered_by_verb": verb,
                       "evidence": f"{mapping.version}:{resource}/{verb}" if verb else None})
        if status == "verified":
            narrowest_idx = max(narrowest_idx, VERBS.index(verb))
        elif status == "unknown-operation":
            unknown.append(op)
    resource_status = ("missing-mapping" if resource not in mapping.resources
                       else "unknown-operation" if unknown else "verified")
    cand = {"resource": resource, "status": resource_status, "operations": per_op,
            "before": {"citation": stmt.citation, "statement": stmt.raw},
            "after": None, "unresolved_assumptions": []}
    if resource_status == "verified":
        verb = VERBS[narrowest_idx]
        after = (f"Allow {stmt.subject_type} {stmt.subject} to {verb} {resource} "
                 f"in {stmt.scope}")
        if stmt.condition:
            after += f" where {stmt.condition}"
            cand["unresolved_assumptions"].append(
                "Original condition preserved verbatim; its effect was not re-evaluated against the narrower verb.")
        cand["after"] = {"statement": after, "verb": verb,
                         "evidence": [f"{mapping.version}:{resource}/{verb}"]}
        cand["unresolved_assumptions"].append(
            "Required operations are the ones supplied by the workload owner; if the workload needs more, the draft under-covers it.")
    elif resource_status == "unknown-operation":
        cand["unresolved_assumptions"].append(
            f"Not narrowed: {len(unknown)} operation(s) not in mapping {mapping.version} for {resource}: {', '.join(unknown)}. "
            "Check the cited Oracle reference for a newer permission name before changing anything.")
    else:
        cand["unresolved_assumptions"].append(
            f"Not narrowed: no mapping for resource {resource!r} in {mapping.version}. Add verified reference data first.")
    return cand


def suggest(mapping: Mapping, statements: list[Statement], required: dict) -> dict:
    """Pair workload requirements with same-resource statements; draft candidates only."""
    supported = [s for s in statements if s.supported]
    candidates = []
    unmatched_requirements = []
    for req in required.get("requirements", []):
        resource, operations = req.get("resource"), list(req.get("operations", []))
        if not resource or not operations:
            raise MappingError(f"requirement needs resource and operations: {req!r}")
        partners = [s for s in supported if s.resource == resource]
        if not partners:
            unmatched_requirements.append(resource)
            continue
        for stmt in partners:
            candidates.append(build_candidate(mapping, stmt, resource, operations))
    narrowed = sum(1 for c in candidates if c["status"] == "verified")
    return {
        "draft": True,
        "human_approval_required": True,
        "validation_guidance": "Review every candidate with the workload owner, then validate on a real tenancy (apply to a test group first, watch for AccessDenied) before any production change. This tool never applies a policy.",
        "mapping_version": mapping.version,
        "mapping_source": mapping.source,
        "workload": required.get("workload", "unnamed"),
        "candidates": candidates,
        "unmatched_requirements": unmatched_requirements,
        "summary": {"requirements": len(required.get("requirements", [])),
                    "candidates": len(candidates), "verified": narrowed,
                    "unknown_operation": sum(1 for c in candidates if c["status"] == "unknown-operation"),
                    "missing_mapping": sum(1 for c in candidates if c["status"] == "missing-mapping")},
    }


def load_required(path: str | Path) -> dict:
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        assert isinstance(raw.get("requirements"), list)
        return raw
    except (OSError, json.JSONDecodeError, AssertionError) as e:
        raise MappingError(f"cannot load required operations {path}: {e}") from e
