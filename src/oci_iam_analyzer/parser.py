"""Conservative parser: never silently treat unsupported syntax as safe."""
from dataclasses import dataclass
import json
import re
from pathlib import Path

from .conditions import ConditionError, parse_condition

VERBS = ("inspect", "read", "use", "manage")
# Subjects per Oracle Policy Syntax: named group/dynamic-group, OCID forms
# (`group id ocid1...`), and `any-user`. OCID realm segment may be empty
# (e.g. ocid1.group.oc1..xyz).
_OCID = r"ocid1\.[a-z0-9-]+\.[a-z0-9-]*\.[a-z0-9-]*\..+"
_SIMPLE = re.compile(
    r"^allow\s+("
    r"(?P<kind>group|dynamic-group)\s+(?:id\s+(?P<ocid>" + _OCID + r")|(?P<name>[A-Za-z0-9_.:-]+))"
    r"|(?P<anyuser>any-user)"
    r")\s+to\s+(?P<verb>inspect|read|use|manage)\s+(?P<resource>[A-Za-z0-9-]+)\s+"
    r"in\s+(?P<scope>tenancy|compartment\s+[A-Za-z0-9_.:-]+)"
    r"(?:\s+where\s+(?P<condition>.+))?$", re.IGNORECASE | re.DOTALL
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
    condition_ast: object | None = None
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
    g = match.groupdict()
    condition = g["condition"]
    condition_ast = None
    if condition:
        # A parsed condition is described structurally, never "evaluated"; an
        # unparseable one keeps the whole statement manual-review rather than
        # guessing at its effect.
        try:
            condition_ast = parse_condition(condition)
        except ConditionError as exc:
            return Statement(policy, index, raw, g["kind"].lower() if g["kind"] else "any-user",
                             _subject(g), g["verb"].lower(), g["resource"].lower(),
                             g["scope"].lower(), condition,
                             reason=f"condition unsupported: {exc}")
    return Statement(policy, index, raw,
                     g["kind"].lower() if g["kind"] else "any-user",
                     _subject(g), g["verb"].lower(), g["resource"].lower(),
                     g["scope"].lower(), condition, condition_ast, supported=True)


def _subject(groups: dict) -> str:
    if groups.get("anyuser"):
        return "any-user"
    if groups.get("ocid"):
        return groups["ocid"]
    return groups["name"]


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
