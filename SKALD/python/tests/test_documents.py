"""FhirPlan / NestedPlan: one document in, the bytes SKALD's command line writes out, from keys passed in.

The command-line side of the equality is in the Rust tests (src/batch/documents.rs); here the Python surface:
required keys, errors with codes, the free-text redactor, and that a document needs nothing from any other.
"""

import json
from pathlib import Path

import pytest
import skald_core as sk

DOCS = Path(__file__).resolve().parents[2] / "conformance" / "documents"
HEX = {"hmac_salt": 32, "aes_key": 16, "fpe_key": 16}


def plan(cls, path):
    return cls((DOCS / path).read_text())


def keys_for(p):
    out = {}
    for kind, name in p.required_keys():
        out.setdefault(kind, {})[name] = bytes((hash((kind, name)) + i) % 256 for i in range(HEX[kind]))
    return out


def doc(path):
    return (DOCS / path).read_bytes()


def test_required_keys_are_named_as_skald_files_them():
    f = plan(sk.FhirPlan, "fhir/config.json")
    assert sorted(f.required_keys()) == sorted(
        [("hmac_salt", n) for n in ("<resource id>", "**.meta.source", "Claim.identifier[].value", "code:*uhid*")])
    assert ("hmac_salt", "<output name>") in plan(sk.FhirPlan, "fhir/config_pseudonym.json").required_keys()
    n = plan(sk.NestedPlan, "nested/config.json")
    assert sorted(n.required_keys()) == [("aes_key", "**.aadhaar_number"), ("fpe_key", "**.ration_card"), ("hmac_salt", "hash_salt")]


def test_same_document_same_keys_same_bytes_and_other_keys_other_bytes():
    p = plan(sk.FhirPlan, "fhir/config.json")
    d = doc("fhir/docs/TESTCASE_ST_2025_R0_1000000000.fhir.json")
    k = keys_for(p)
    a, audit = p.apply(k, d)
    assert p.apply(k, d)[0] == a and json.loads(a)["resourceType"] == "Bundle"
    k2 = {kind: {n: bytes(reversed(b)) for n, b in cols.items()} for kind, cols in k.items()}
    assert p.apply(k2, d)[0] != a
    assert audit["leaves"] > 0 and "by_action" in audit and "example" not in json.dumps(audit)


def test_output_names():
    p = plan(sk.FhirPlan, "fhir/config.json")
    assert p.output_name(keys_for(p), "x/A1.fhir.json") == "A1_anonymised.fhir.json"
    q = plan(sk.FhirPlan, "fhir/config_pseudonym.json")
    name = q.output_name(keys_for(q), "A1.fhir.json")
    assert name.endswith("_anonymised.fhir.json") and "A1" not in name
    assert plan(sk.NestedPlan, "nested/config.json").output_name({}, "d/case_1.json") == "case_1.json"


def test_errors_carry_codes_and_a_missing_key_names_only_the_key():
    p = plan(sk.FhirPlan, "fhir/config.json")
    d = doc("fhir/docs/TESTCASE_ST_2025_R0_1000000000.fhir.json")
    with pytest.raises(sk.SkaldError) as e:
        p.apply({"hmac_salt": {"<resource id>": bytes(32)}}, d)
    assert e.value.code == "KEY_MATERIAL_MISSING" and "Claim.identifier[].value" in str(e.value)
    with pytest.raises(sk.SkaldError) as e:
        p.apply(keys_for(p), b"{broken")
    assert e.value.code == "DATA_INVALID_JSON" and "broken" not in str(e.value)
    with pytest.raises(sk.SkaldError) as e:
        p.apply(keys_for(p), b'{"resourceType": "Patient"}')
    assert e.value.code == "DATA_NOT_FHIR_BUNDLE"
    with pytest.raises(sk.SkaldError):
        sk.FhirPlan((DOCS / "nested/config.json").read_text())  # the other flow's config


def test_redactor_gets_the_free_text_once_in_walk_order():
    p = plan(sk.NestedPlan, "nested/config.json")
    seen = []

    def redact(texts):
        seen.append(list(texts))
        return ["[X]"] * len(texts)

    out, audit = p.apply(keys_for(p), doc("nested/docs/case_1.json"), redact)
    assert len(seen) == 1 and len(seen[0]) == 3 and out.decode().count("[X]") == 3
    with pytest.raises(sk.SkaldError) as e:
        p.apply(keys_for(p), doc("nested/docs/case_1.json"), lambda t: [])
    assert e.value.code == "NER_FAILED"
