"""
FHIR R4 Bundle anonymization library.

Quick start::

    from fhir_anonymizer import FHIRBundleAnonymizer, AnonymizationPolicy

    policy = AnonymizationPolicy.from_json("fhir_anonymizer/config/nha_policy.json")
    anon   = FHIRBundleAnonymizer(policy)
    result = anon.anonymize(bundle_dict)
"""
from .anonymizer import FHIRBundleAnonymizer
from .policy import AnonymizationPolicy, AnonymizationRule

__all__ = ["FHIRBundleAnonymizer", "AnonymizationPolicy", "AnonymizationRule"]
