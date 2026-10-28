"""Transparent *review priority* heuristic, not effective-permissions inference."""
from dataclasses import asdict
from .parser import Statement
from .conditions import describe, variables

WEIGHTS = {"inspect": 0, "read": 10, "use": 25, "manage": 45}


def analyze(statements: list[Statement]) -> dict:
    findings = []
    for stmt in statements:
        f = {"citation": stmt.citation, "statement": stmt.raw,
             "supported": stmt.supported, "review_priority": None,
             "signals": [], "review_options": [], "limitations": []}
        if not stmt.supported:
            f["limitations"].append(stmt.reason or "unsupported syntax")
            f["review_priority"] = "manual-review"
            findings.append(f)
            continue
        score = WEIGHTS[stmt.verb]
        f["signals"].append({"kind": "verb", "points": WEIGHTS[stmt.verb], "evidence": stmt.verb})
        if stmt.subject_type == "any-user":
            score += 15
            f["signals"].append({"kind": "subject-breadth", "points": 15, "evidence": "any-user"})
            f["review_options"].append("any-user covers every requester including unauthenticated ones; confirm a named group or dynamic-group is not intended before keeping it.")
        if stmt.subject and stmt.subject.startswith("ocid1."):
            f["limitations"].append("OCID subject is preserved for citation but not resolved to a name or membership.")
        if stmt.resource == "all-resources":
            score += 30
            f["signals"].append({"kind": "resource-breadth", "points": 30, "evidence": stmt.resource})
            f["review_options"].append("Ask the owner which named resource types the workload uses; replace all-resources only after mapping required permissions.")
        elif stmt.resource.endswith("-family"):
            score += 15
            f["signals"].append({"kind": "resource-family", "points": 15, "evidence": stmt.resource})
            f["review_options"].append("Check whether this family can be narrowed to specific OCI resource types without breaking workflows.")
        if stmt.scope == "tenancy":
            score += 20
            f["signals"].append({"kind": "scope", "points": 20, "evidence": stmt.scope})
            f["review_options"].append("Check whether a named compartment or compartment path can replace tenancy scope.")
        if stmt.verb in ("manage", "use"):
            f["review_options"].append(f"Review actual operations before changing {stmt.verb} to a narrower verb or a request.permission condition; no automatic rewrite.")
        if stmt.condition_ast is not None:
            cond_vars = variables(stmt.condition_ast)
            f["condition"] = describe(stmt.condition_ast)
            f["signals"].append({"kind": "condition", "points": 0,
                                 "evidence": "references " + ", ".join(cond_vars)})
            f["limitations"].append(
                "Condition is parsed structurally (variables/operators shown) but not evaluated "
                "against real requests; the breadth score reflects the statement as written. A "
                "condition can only narrow access - it never widens it - but this tool does not "
                "verify what the condition actually admits.")
        f["score"] = min(100, score)
        f["review_priority"] = "high" if score >= 70 else "medium" if score >= 35 else "low"
        f["limitations"].append("Static statement-level heuristic; does not infer effective privileges, group membership, inheritance, or resource-specific permissions.")
        findings.append(f)
    return {"schema_version": 1, "findings": findings,
            "summary": {"total": len(findings), "supported": sum(f["supported"] for f in findings),
                        "manual_review": sum(not f["supported"] for f in findings),
                        "high": sum(f["review_priority"] == "high" for f in findings)},
            "method": "Review-priority points: verb inspect/read/use/manage = 0/10/25/45; any-user +15; all-resources +30; *-family +15; tenancy +20; cap 100. Parsed conditions add 0 points and are described, not evaluated. Not a security certification."}
