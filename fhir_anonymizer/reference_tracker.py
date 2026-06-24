"""
Reference integrity tracker for FHIR bundle anonymization.

FHIR resources reference each other via ``"reference"`` string fields in the
form ``"ResourceType/id"``.  When resource IDs are tokenized the tracker:

1. Collects ``old_id → new_id`` mappings per resource type (Pass 1).
2. Rewrites every ``"reference"`` field and ``entry.fullUrl`` in the bundle
   so the graph remains consistent (Pass 3).

Supported reference forms:
    ``Patient/abc123``              →  relative reference  (handled)
    ``https://host/fhir/Patient/abc123``  →  absolute URL   (handled — last segment)
    ``urn:uuid:…``                  →  UUID reference    (not handled — IDs stored
                                                           under urn:uuid are not
                                                           remapped by this tracker)
"""
from __future__ import annotations

from typing import Any


class ReferenceTracker:
    def __init__(self) -> None:
        # "ResourceType/oldId" → "ResourceType/newId"
        self._map: dict[str, str] = {}

    # ── registration ─────────────────────────────────────────────────────────

    def register(self, resource_type: str, old_id: str, new_id: str) -> None:
        """Record that *resource_type*/*old_id* was renamed to *new_id*."""
        if old_id == new_id:
            return
        self._map[f"{resource_type}/{old_id}"] = f"{resource_type}/{new_id}"

    # ── rewrite a single reference string ────────────────────────────────────

    def rewrite(self, ref: str) -> str:
        """
        Rewrite *ref* if it points to a resource whose ID was tokenized.

        Handles both relative (``Patient/id``) and absolute URL forms.
        """
        # Direct match (relative reference)
        if ref in self._map:
            return self._map[ref]

        # Absolute URL: try to match the trailing ResourceType/id segment
        for old, new in self._map.items():
            if ref.endswith("/" + old.replace("/", "/")):
                return ref[: len(ref) - len(old)] + new

        return ref

    # ── full bundle walk ──────────────────────────────────────────────────────

    def rewrite_all(self, obj: Any) -> Any:
        """
        Recursively walk *obj* (the entire bundle dict) and rewrite every
        ``"reference"`` string value and ``"fullUrl"`` entry-level field.

        Mutates *obj* in place and returns it.
        """
        if isinstance(obj, dict):
            for key, val in list(obj.items()):
                if isinstance(val, str) and key in ("reference", "fullUrl"):
                    obj[key] = self.rewrite(val)
                else:
                    self.rewrite_all(val)
        elif isinstance(obj, list):
            for item in obj:
                self.rewrite_all(item)
        return obj
