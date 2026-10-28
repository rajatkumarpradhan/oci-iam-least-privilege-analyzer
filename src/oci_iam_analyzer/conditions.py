"""Strict parser for a documented subset of OCI IAM condition syntax.

Oracle documents conditions as ``where <condition>`` where a condition is a
comparison or an ``any``/``all`` set of comparisons (Policy Syntax doc:
https://docs.oracle.com/en-us/iaas/Content/Identity/Concepts/policysyntax.htm).
Supported here: single-quoted string values, ``=`` / ``!=`` operators, dotted
variable names from the documented list, and one level of ``any { }`` /
``all { }`` sets. Anything else raises ConditionError so the caller keeps the
statement manual-review; nothing here is ever silently treated as safe.
"""
from dataclasses import dataclass, field

# Documented condition variables (Oracle Policy Syntax + common variable
# references). Unknown variables are rejected, not ignored.
DOCUMENTED_VARIABLES = frozenset({
    "request.operation",
    "request.permission",
    "request.user.id",
    "request.principal.id",
    "request.groups.id",
    "request.networksource.name",
    "request.utc-timestamp",
    "target.resource.type",
    "target.resource.id",
    "target.compartment.id",
    "target.compartment.name",
    "target.group.id",
    "target.bucket.name",
    "target.instance.id",
    "target.db.id",
})

OPERATORS = ("=", "!=")


class ConditionError(ValueError):
    """Raised for any condition shape outside the supported subset."""


@dataclass(frozen=True)
class Comparison:
    variable: str
    operator: str
    value: str


@dataclass(frozen=True)
class SetExpr:
    kind: str  # "any" or "all"
    items: tuple = field(default_factory=tuple)


def _tokenize(text: str) -> list[str]:
    """Split into tokens: quoted strings, braces, commas, operators, words.

    Rejects double quotes outright: Oracle's documented examples use single
    quotes, and accepting other quoting styles invites silent misreads.
    """
    tokens = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch.isspace():
            i += 1
            continue
        if ch == '"':
            raise ConditionError("double quotes are not supported; use single quotes")
        if ch == "'":
            end = text.find("'", i + 1)
            if end == -1:
                raise ConditionError("unterminated quoted value")
            tokens.append("'" + text[i + 1:end] + "'")
            i = end + 1
            continue
        if ch in "{},":
            tokens.append(ch)
            i += 1
            continue
        if text.startswith("!=", i):
            tokens.append("!=")
            i += 2
            continue
        if ch == "=":
            if text.startswith("==", i):
                raise ConditionError("'==' is not an OCI operator; use '='")
            tokens.append("=")
            i += 1
            continue
        j = i
        while j < n and (text[j].isalnum() or text[j] in "._-"):
            j += 1
        if j == i:
            raise ConditionError(f"unexpected character {ch!r}")
        tokens.append(text[i:j])
        i = j
    return tokens


def _is_quoted(token: str) -> bool:
    return len(token) >= 2 and token.startswith("'") and token.endswith("'")


class _Cursor:
    def __init__(self, tokens: list[str]):
        self.tokens = tokens
        self.pos = 0

    def peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def next(self) -> str:
        tok = self.peek()
        if tok is None:
            raise ConditionError("unexpected end of condition")
        self.pos += 1
        return tok

    def expect(self, want: str) -> None:
        got = self.next()
        if got != want:
            raise ConditionError(f"expected {want!r}, found {got!r}")

    def at_end(self) -> bool:
        return self.pos >= len(self.tokens)


def _parse_comparison(cur: _Cursor) -> Comparison:
    variable = cur.next()
    if variable in ("any", "all"):
        raise ConditionError("nested any/all sets are not supported")
    if not cur.peek() in OPERATORS:
        raise ConditionError(f"expected '=' or '!=' after variable {variable!r}")
    operator = cur.next()
    value = cur.next()
    if not _is_quoted(value):
        raise ConditionError("comparison values must be single-quoted strings")
    if variable not in DOCUMENTED_VARIABLES:
        raise ConditionError(f"unknown condition variable {variable!r}")
    return Comparison(variable=variable, operator=operator, value=value[1:-1])


def parse_condition(text: str) -> Comparison | SetExpr:
    """Parse a condition string into an AST, or raise ConditionError."""
    if not isinstance(text, str) or not text.strip():
        raise ConditionError("empty condition")
    tokens = _tokenize(text.strip())
    cur = _Cursor(tokens)
    first = cur.peek()
    if first in ("any", "all"):
        kind = cur.next()
        cur.expect("{")
        items = []
        if cur.peek() == "}":
            raise ConditionError(f"empty {kind} set")
        while True:
            items.append(_parse_comparison(cur))
            nxt = cur.next()
            if nxt == "}":
                break
            if nxt != ",":
                raise ConditionError(f"expected ',' or '}}' in {kind} set, found {nxt!r}")
            if cur.peek() == "}":
                raise ConditionError("trailing comma in set")
        result = SetExpr(kind=kind, items=tuple(items))
    else:
        result = _parse_comparison(cur)
    if not cur.at_end():
        raise ConditionError(f"trailing content after condition: {cur.peek()!r}")
    return result


def describe(node: Comparison | SetExpr) -> dict:
    """Stable JSON-friendly description for reports and tests."""
    if isinstance(node, Comparison):
        return {"type": "comparison", "variable": node.variable,
                "operator": node.operator, "value": node.value}
    return {"type": "set", "kind": node.kind,
            "items": [describe(i) for i in node.items]}


def variables(node: Comparison | SetExpr) -> list[str]:
    if isinstance(node, Comparison):
        return [node.variable]
    seen = []
    for item in node.items:
        for v in variables(item):
            if v not in seen:
                seen.append(v)
    return seen
