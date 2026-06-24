"""
Policy definitions for FHIR bundle anonymization.

A policy is a list of rules, each mapping a FHIR resource type + dot-separated
field path to one anonymization operation.  Load from JSON or build in code.

Example JSON schema::

    {
      "tokenize_resource_ids": true,
      "rules": [
        {"path": "Patient.name",       "operation": "suppress"},
        {"path": "Patient.birthDate",  "operation": "date_generalize",
         "params": {"granularity": "year"}},
        {"path": "Patient.identifier.value", "operation": "tokenize"}
      ]
    }
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

SUPPORTED_OPERATIONS = {
    "suppress",
    "mask",
    "hash",
    "tokenize",
    "encrypt",
    "date_generalize",
}


@dataclass
class AnonymizationRule:
    """One rule: apply ``operation`` to ``field_path`` on every ``resource_type`` resource."""

    resource_type: str  # e.g. "Patient", "Practitioner", or "*" for all
    field_path: str     # dot-separated path relative to the resource root, e.g. "name.family"
    operation: str      # one of SUPPORTED_OPERATIONS
    params: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.operation not in SUPPORTED_OPERATIONS:
            raise ValueError(
                f"Unsupported operation '{self.operation}'. "
                f"Must be one of: {sorted(SUPPORTED_OPERATIONS)}"
            )


@dataclass
class AnonymizationPolicy:
    """
    Collection of rules applied during bundle anonymization.

    :param rules: Ordered list of :class:`AnonymizationRule`.
    :param tokenize_resource_ids: When True (default), resource-level ``id``
        fields are tokenized in a dedicated first pass and all intra-bundle
        ``reference`` fields are rewritten to match.  Set to False only when
        IDs are already pseudonymous or managed externally.
    """

    rules: list[AnonymizationRule]
    tokenize_resource_ids: bool = True

    # ── query helpers ────────────────────────────────────────────────────────

    def rules_for(self, resource_type: str) -> list[AnonymizationRule]:
        """Return rules that apply to *resource_type* (including wildcard rules)."""
        return [r for r in self.rules if r.resource_type in (resource_type, "*")]

    # ── constructors ─────────────────────────────────────────────────────────

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AnonymizationPolicy:
        """Build a policy from a plain dict (as parsed from JSON)."""
        rules: list[AnonymizationRule] = []
        for entry in data.get("rules", []):
            path: str = entry["path"]
            if "." not in path:
                raise ValueError(
                    f"Rule path '{path}' must be 'ResourceType.field[.subfield...]'"
                )
            resource_type, field_path = path.split(".", 1)
            rules.append(
                AnonymizationRule(
                    resource_type=resource_type,
                    field_path=field_path,
                    operation=entry["operation"],
                    params=entry.get("params", {}),
                )
            )
        return cls(
            rules=rules,
            tokenize_resource_ids=data.get("tokenize_resource_ids", True),
        )

    @classmethod
    def from_json(cls, path: str) -> AnonymizationPolicy:
        """Load a policy from a JSON file on disk."""
        with open(path) as fh:
            return cls.from_dict(json.load(fh))
