"""
FHIR dot-path resolver.

Resolves a dot-separated path against a FHIR resource dict, descending through
both dicts and arrays at each segment so callers never need to know whether a
FHIR field is singular or repeated.

Example paths::

    "name"                 →  Patient.name  (array of HumanName)
    "name.family"          →  family in each HumanName in name[]
    "identifier.value"     →  value in each Identifier in identifier[]
    "telecom.value"        →  value in each ContactPoint in telecom[]
    "address.line"         →  line (array of str) in each Address in address[]
"""
from __future__ import annotations

from typing import Any, Callable


def resolve_path(obj: Any, path: str) -> list[tuple[dict, str]]:
    """
    Return a list of ``(parent_dict, key)`` pairs for every leaf location that
    matches *path* inside *obj*, descending through any intermediate arrays.

    - If a path segment is absent, that branch is silently skipped.
    - If an intermediate value is a primitive (not dict/list), the path
      cannot be descended further and that branch is skipped.

    :param obj: Dict to resolve against (typically a FHIR resource).
    :param path: Dot-separated field path relative to *obj*.
    :returns: Possibly-empty list of ``(parent, key)`` tuples.
    """
    parts = path.split(".", 1)
    head = parts[0]
    rest = parts[1] if len(parts) > 1 else None

    if not isinstance(obj, dict) or head not in obj:
        return []

    if rest is None:
        return [(obj, head)]

    child = obj[head]
    if isinstance(child, list):
        results: list[tuple[dict, str]] = []
        for item in child:
            results.extend(resolve_path(item, rest))
        return results
    if isinstance(child, dict):
        return resolve_path(child, rest)
    # Primitive with remaining path — cannot descend
    return []


def set_at_path(obj: Any, path: str, transform: Callable[[Any], Any]) -> bool:
    """
    Apply *transform* to every value at *path* within *obj*, mutating in place.

    - If *transform* returns ``None``, the key is **deleted** (used by suppress).
    - Returns ``True`` if at least one location was found and modified.

    :param obj: Root dict to mutate.
    :param path: Dot-separated path; see :func:`resolve_path`.
    :param transform: ``value -> new_value | None`` callable.
    :returns: Whether any mutation occurred.
    """
    locations = resolve_path(obj, path)
    if not locations:
        return False
    for parent, key in locations:
        new_val = transform(parent[key])
        if new_val is None:
            del parent[key]
        else:
            parent[key] = new_val
    return True
