"""Every vector in vectors.json, byte for byte, plus the control-plane copy if it is next door."""

import base64
import hashlib
import json
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from anamika_spark import bundle

HERE = Path(__file__).parent
V = json.loads((HERE / "fixtures" / "vectors.json").read_text())
b = base64.b64decode


def test_matches_control_plane_copy_when_present():
    cp = Path(os.environ.get("ANAMIKA_CONTROL_PLANE", HERE.parents[1] / "anamika-control-plane")) / "contracts/bundle/vectors.json"
    if not cp.exists():
        pytest.skip("control-plane repo not checked out beside this one")
    assert json.loads(cp.read_text()) == V, "fixture drifted from contracts/bundle/vectors.json: re-copy it and re-run"


def test_derived_keys():
    k = b(V["k_user_b64"])
    for label, expected in V["derived_keys_b64"].items():
        assert bundle.derive(k, label) == b(expected)
    keys = bundle.Keys.from_user_key(k)
    assert keys.input == b(V["derived_keys_b64"]["input"])
    assert "redacted" in repr(keys) and keys.input.hex() not in repr(keys)


def test_k_user_length():
    with pytest.raises(bundle.BundleError):
        bundle.derive(b"short", "input")


@pytest.mark.parametrize("i", range(len(V["parts"])))
def test_input_parts(i):
    p, job = V["parts"][i], V["job_id"]
    keys = bundle.Keys.from_user_key(b(V["k_user_b64"]))
    assert bundle.aad_input(job, i, len(V["parts"])) == p["aad"]
    sealed = bundle.seal(keys.input, b(p["plaintext_b64"]), p["aad"], b(p["nonce_b64"]))
    assert sealed == b(p["object_b64"])
    assert hashlib.sha256(sealed).hexdigest() == p["object_sha256"]
    plain = bundle.open_(keys.input, b(p["object_b64"]), p["aad"])
    assert plain == b(p["plaintext_b64"]) and hashlib.sha256(plain).hexdigest() == p["plaintext_sha256"]
    assert bundle.part_name(i) + ".enc" == p["name"]


def test_manifest_output_summary_aads():
    job = V["job_id"]
    keys = bundle.Keys.from_user_key(b(V["k_user_b64"]))
    m = V["manifest"]
    assert bundle.aad_manifest(job) == m["aad"]
    assert bundle.seal(keys.manifest, b(m["plaintext_b64"]), m["aad"], b(m["nonce_b64"])) == b(m["object_b64"])
    assert bundle.open_(keys.manifest, b(m["object_b64"]), m["aad"]) == b(m["plaintext_b64"])
    o = V["output_part"]
    assert bundle.aad_output(job, 0, 1) == o["aad"]
    assert bundle.seal(keys.output, b(o["plaintext_b64"]), o["aad"], b(o["nonce_b64"])) == b(o["object_b64"])
    assert bundle.open_(keys.output, b(o["object_b64"]), o["aad"]) == b(o["plaintext_b64"])
    ex = V["aad_examples"]
    assert bundle.aad_summary(job, "measure", "histogram") == ex["measure_histogram"]
    assert bundle.aad_summary(job, "measure", "summary") == ex["measure_summary"]
    assert bundle.aad_summary(job, "apply", "summary") == ex["apply_summary"]


def test_vault():
    v = V["vault"]
    assert bundle.vault_key(b(v["vault_master_b64"])) == b(v["k_vault_b64"])
    assert bundle.aad_vault("v-regno", 3) == v["aad"]
    kv = b(v["k_vault_b64"])
    assert bundle.seal(kv, b(v["plaintext_b64"]), v["aad"], b(v["nonce_b64"])) == b(v["object_b64"])
    assert bundle.open_(kv, b(v["object_b64"]), v["aad"]) == b(v["plaintext_b64"])


def test_rsa_oaep_unwraps():
    r = V["rsa_oaep"]
    priv = serialization.load_pem_private_key(r["private_key_pem"].encode(), password=None)
    assert bundle.unwrap(priv, b(r["wrapped_k_user_b64"]), r["job_label"]) == b(V["k_user_b64"])
    assert bundle.unwrap(priv, b(r["wrapped_vault_master_b64"]), r["registry_label"]) == b(V["vault"]["vault_master_b64"])
    with pytest.raises(Exception):  # the label pins the wrap to its job
        bundle.unwrap(priv, b(r["wrapped_k_user_b64"]), "another-job")
    round_trip = bundle.wrap(priv.public_key(), b"k" * 32, "lbl")
    assert bundle.unwrap(priv, round_trip, "lbl") == b"k" * 32


def test_tamper_cases_rejected():
    keys = bundle.Keys.from_user_key(b(V["k_user_b64"]))
    p0, t = V["parts"][0], V["tamper_cases"]
    with pytest.raises(bundle.BundleError):  # part 0 presented as part 1
        bundle.open_(keys.input, b(p0["object_b64"]), t["part_0_with_part_1_aad"])
    with pytest.raises(bundle.BundleError, match="not an Anamika"):
        bundle.open_(keys.input, b(t["wrong_magic_object_b64"]), p0["aad"])
    with pytest.raises(bundle.BundleError, match="unsupported version"):
        bundle.open_(keys.input, b(t["version_2_object_b64"]), p0["aad"])
    with pytest.raises(bundle.BundleError):  # an input part where an output part is expected
        bundle.open_(keys.output, b(p0["object_b64"]), p0["aad"])
    with pytest.raises(bundle.BundleError):  # truncated
        bundle.open_(keys.input, b(p0["object_b64"])[:20], p0["aad"])
    flipped = bytearray(b(p0["object_b64"])); flipped[-1] ^= 1
    with pytest.raises(bundle.BundleError):
        bundle.open_(keys.input, bytes(flipped), p0["aad"])


def test_random_nonces_differ():
    k = b"k" * 32
    assert bundle.seal(k, b"x", "a") != bundle.seal(k, b"x", "a")
