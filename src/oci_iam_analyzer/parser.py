"""Conservative parser: never silently treat unsupported syntax as safe."""
from dataclasses import dataclass
import json
import re
from pathlib import Path

VERBS = ("inspect", "read", "use", "manage")
# Known simple OCI shape. Complex subjects, OCID names, conditions and
# permissions selectors are intentionally returned as unsupported.
_SIMPLE = re.compile(
    r"^allow\s+(group|dynamic-group)\s+([A-Za-z0-9_.:-]+)\s+"
    r"to\s+(inspect|read|use|manage)\s+([A-Za-z0-9-]+)\s+"
    r"in\s+(tenancy|compartment\s+[A-Za-z0-9_.:-]+)"
    r"(?:\s+where\s+(.+))?$", re.IGNORECASE | re.DOTALL
)

@dataclass(frozen=True)
class Statement:
    policy: str
    index: int
    raw: str
    subject_type: str | None = None
    subject: str | None = None
    verb: str | None = None
    resource: str | None = None
    scope: str | None = None
    condition: str | None = None
    supported: bool = False
    reason: str | None = None

    @property
    def citation(self):
        return f"{self.policy}#statement-{self.index}"


def parse_statement(raw: str, index: int, policy: str = "policy") -> Statement:
    if not isinstance(raw, str) or not raw.strip():
        return Statement(policy, index, str(raw), reason="empty or non-text statement")
    text = " ".join(raw.strip().split())
    match = _SIMPLE.fullmatch(text)
    if not match:
        return Statement(policy, index, raw, reason="unsupported OCI policy syntax")
    kind, subject, verb, resource, scope, condition = match.groups()
    if condition:
        # Condition semantics depend on variable and operators. Preserve the
        # text in report, but don't pretend to evaluate it or auto-rewrite it.
        return Statement(policy, index, raw, kind.lower(), subject, verb.lower(),
                         resource.lower(), scope.lower(), condition,
                         reason="condition present; effective scope not evaluated")
    return Statement(policy, index, raw, kind.lower(), subject, verb.lower(),
                     resource.lower(), scope.lower(), supported=True)


def load_export(path: str | Path) -> list[Statement]:
    """JSON {policies:[{name,statements:[str,...]}]} or direct list of policies.

    Reject missing/malformed fields rather than inventing empty policies.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    policies = data.get("policies") if isinstance(data, dict) else data
    if not isinstance(policies, list) or not policies:
        raise ValueError("expected a non-empty policies list")
    statements = []
    names = set()
    for p in policies:
        if not isinstance(p, dict) or not isinstance(p.get("name"), str) or not p["name"].strip():
            raise ValueError("every policy needs a non-empty name")
        if p["name"] in names:
            raise ValueError("duplicate policy name makes citations ambiguous")
        names.add(p["name"])
        if not isinstance(p.get("statements"), list) or not p["statements"]:
            raise ValueError("every policy needs a non-empty statements list")
        for i, raw in enumerate(p["statements"], 1):
            statements.append(parse_statement(raw, i, p["name"]))
    return statements
