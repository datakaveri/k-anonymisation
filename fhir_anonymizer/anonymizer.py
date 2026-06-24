"""
FHIR R4 Bundle anonymizer — main entry point.

Applies a configurable :class:`~fhir_anonymizer.policy.AnonymizationPolicy`
to a FHIR R4 Bundle dict in three passes:

Pass 1 — Resource ID tokenization
    Every resource's ``id`` field is replaced with a stable pseudonym.
    The old→new mapping is fed to :class:`~fhir_anonymizer.reference_tracker.ReferenceTracker`.

Pass 2 — Field-level anonymization
    Each rule in the policy is applied to the matching resource type using the
    FHIR dot-path resolver.  ``tokenize`` operations share the same vault as
    Pass 1 so that, e.g., Patient.identifier.value tokenized to the same token
    as the resource ID.

Pass 3 — Reference rewriting
    All ``"reference"`` and ``"fullUrl"`` strings in the bundle are rewritten
    using the mappings collected in Pass 1, preserving the resource graph.

Usage::

    from fhir_anonymizer import FHIRBundleAnonymizer, AnonymizationPolicy

    policy = AnonymizationPolicy.from_json("fhir_anonymizer/config/nha_policy.json")
    anon   = FHIRBundleAnonymizer(policy)

    with open("bundle.json") as f:
        bundle = json.load(f)

    result = anon.anonymize(bundle)
"""
from __future__ import annotations

import copy
import secrets
from typing import Any

from .operations import OPERATION_MAP
from .path_resolver import set_at_path
from .policy import AnonymizationPolicy
from .reference_tracker import ReferenceTracker


def _new_token(value: str, vault: dict[str, str], prefix: str = "") -> str:
    """Return a stable token for *value* within this bundle call's *vault*."""
    if value not in vault:
        vault[value] = prefix + secrets.token_urlsafe(8)
    return vault[value]


class FHIRBundleAnonymizer:
    """
    Anonymizes a FHIR R4 Bundle according to a
    :class:`~fhir_anonymizer.policy.AnonymizationPolicy`.

    The anonymizer is **stateless between calls** — each :meth:`anonymize`
    invocation creates a fresh token vault and reference tracker, so two calls
    on the same bundle produce independently pseudonymized outputs.

    :param policy: Anonymization rules and ID-tokenization flag.
    """

    def __init__(self, policy: AnonymizationPolicy) -> None:
        self.policy = policy

    # ── public API ────────────────────────────────────────────────────────────

    def anonymize(self, bundle: dict[str, Any]) -> dict[str, Any]:
        """
        Return an anonymized deep copy of *bundle*.

        :param bundle: A parsed FHIR R4 Bundle (``resourceType == "Bundle"``).
        :raises ValueError: If *bundle* is not a FHIR Bundle.
        :returns: New dict with the same structure but anonymized field values
                  and consistent intra-bundle references.
        """
        if bundle.get("resourceType") != "Bundle":
            raise ValueError(
                "Input must be a FHIR R4 Bundle (resourceType == 'Bundle')"
            )

        bundle = copy.deepcopy(bundle)
        entries = bundle.get("entry", [])

        # Shared token vault: same string → same token within this call
        vault: dict[str, str] = {}
        tracker = ReferenceTracker()

        # ── Pass 1: tokenize resource IDs ─────────────────────────────────
        if self.policy.tokenize_resource_ids:
            for entry in entries:
                resource = entry.get("resource")
                if not isinstance(resource, dict):
                    continue
                resource_type: str = resource.get("resourceType", "")
                old_id: str = resource.get("id", "")
                if not old_id:
                    continue

                new_id = _new_token(old_id, vault)
                resource["id"] = new_id
                tracker.register(resource_type, old_id, new_id)

                # Keep entry.fullUrl consistent
                full_url: str = entry.get("fullUrl", "")
                if full_url:
                    entry["fullUrl"] = _rewrite_url_segment(full_url, old_id, new_id)

        # ── Pass 2: field-level anonymization ─────────────────────────────
        for entry in entries:
            resource = entry.get("resource")
            if not isinstance(resource, dict):
                continue
            resource_type = resource.get("resourceType", "")
            for rule in self.policy.rules_for(resource_type):
                # Skip id — already handled in Pass 1
                if rule.field_path == "id" and self.policy.tokenize_resource_ids:
                    continue
                op_fn = OPERATION_MAP.get(rule.operation)
                if op_fn is None:
                    continue
                set_at_path(
                    resource,
                    rule.field_path,
                    lambda val, _op=op_fn, _p=rule.params, _v=vault: _op(val, _p, _v),
                )

        # ── Pass 3: rewrite all intra-bundle references ───────────────────
        tracker.rewrite_all(bundle)

        return bundle

    # ── convenience: anonymize a list of independent bundles ─────────────────

    def anonymize_many(
        self, bundles: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """
        Anonymize each bundle independently (separate vaults per bundle).

        Useful for batch processing where cross-bundle linkage is not desired.
        """
        return [self.anonymize(b) for b in bundles]


# ── private helpers ───────────────────────────────────────────────────────────

def _rewrite_url_segment(url: str, old_id: str, new_id: str) -> str:
    """
    Replace the last ``/old_id`` segment in *url* with ``/new_id``.

    Handles both relative (``Patient/id``) and absolute URL forms.
    """
    if url.endswith(f"/{old_id}"):
        return url[: -len(old_id)] + new_id
    return url
