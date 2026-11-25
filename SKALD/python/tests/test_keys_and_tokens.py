import json
import pickle

import pyarrow as pa
import pytest
import skald_core as sk

CONFIG = {
    "data_type": "t",
    "t": {
        "suppress": ["name"],
        "hashing_with_salt": ["id"],
        "encrypt": ["email", {"phone": {"format_preserving": True}}],
        "tokenization": [{"column": "mrn", "prefix": "T-", "digits": 6}],
    },
}


def batch(rows):
    return pa.RecordBatch.from_pylist(rows, schema=pa.schema([(c, pa.string()) for c in
                                                                ["id", "name", "email", "phone", "mrn"]]))


ROWS = [
    {"id": "1", "name": "A", "email": "a@x.org", "phone": "9876543210", "mrn": "M1"},
    {"id": "2", "name": "B", "email": "b@x.org", "phone": "9876543211", "mrn": "M2"},
    {"id": "3", "name": "C", "email": "c@x.org", "phone": "", "mrn": "M1"},
    {"id": "1", "name": "D", "email": "a@x.org", "phone": "9876543210", "mrn": "M3"},
]


@pytest.fixture
def plan():
    return sk.Plan(json.dumps(CONFIG))


def test_generate_keys_returns_what_the_config_needs(plan):
    keys = sk.generate_keys(plan)
    assert sorted(plan.required_keys()) == [("aes_key", "email"), ("fpe_key", "phone"), ("hmac_salt", "id")]
    assert len(keys["hmac_salt"]["id"]) == 32 and len(keys["aes_key"]["email"]) == 16
    # Existing keys are kept, only missing ones are made.
    again = sk.generate_keys(plan, {"hmac_salt": {"id": b"\x07" * 32}})
    assert again["hmac_salt"]["id"] == b"\x07" * 32
    assert again["aes_key"]["email"] != keys["aes_key"]["email"]


def test_an_executor_without_keys_fails_instead_of_generating(plan):
    pre = sk.Preprocessor(plan, {})
    with pytest.raises(sk.SkaldError) as e:
        pre.apply(batch(ROWS))
    assert e.value.code == "KEY_MISSING"


def test_wrong_key_length_is_refused(plan):
    with pytest.raises(sk.SkaldError) as e:
        sk.Preprocessor(plan, {"hmac_salt": {"id": b"short"}})
    assert e.value.code == "KEY_MATERIAL_INVALID"


def test_one_key_gives_one_pseudonym_across_batches_and_processes(plan):
    keys = sk.generate_keys(plan)
    vault = {}
    driver = sk.Preprocessor(plan, keys, generate_missing=False, issue_tokens=True)
    values = {}
    for part in (ROWS[:2], ROWS[2:]):
        for col, vs in driver.token_values(batch(part)).items():
            values.setdefault(col, set()).update(vs)
    driver.issue_tokens({c: sorted(v) for c, v in values.items()})
    vault = driver.vault()
    assert set(vault["mrn"]) == {"M1", "M2", "M3"}

    # Two "executors", each with its own copy of keys and vault, as unpickled.
    outs = []
    for part in (ROWS[:2], ROWS[2:]):
        ex = pickle.loads(pickle.dumps((keys, vault)))
        pre = sk.Preprocessor(plan, ex[0], ex[1])
        outs += pre.apply(batch(part)).to_pylist()
    assert outs[0]["id"] == outs[3]["id"], "same id, same hash, in different batches"
    assert outs[0]["mrn"] == outs[2]["mrn"] == vault["mrn"]["M1"]
    assert outs[0]["mrn"] != outs[1]["mrn"]
    assert "name" not in outs[0]
    assert outs[2]["phone"] == "", "a missing value stays missing"

    # An executor that meets a value with no token refuses rather than minting.
    lone = sk.Preprocessor(plan, keys, {"mrn": {"M1": "T-000001"}})
    with pytest.raises(sk.SkaldError) as e:
        lone.apply(batch(ROWS))
    assert e.value.code == "TOKEN_MISSING"


def test_a_saved_vault_is_reused_by_the_next_job(plan):
    keys = sk.generate_keys(plan)
    first = sk.Preprocessor(plan, keys, generate_missing=True, issue_tokens=True)
    out1 = first.apply(batch(ROWS)).to_pylist()
    second = sk.Preprocessor(plan, keys, first.vault(), issue_tokens=True)
    out2 = second.apply(batch(ROWS)).to_pylist()
    assert out1 == out2, "same keys and vault, same output"


def test_generation_stays_the_default_for_a_single_process(plan):
    pre = sk.Preprocessor(plan, generate_missing=True, issue_tokens=True)
    pre.apply(batch(ROWS))
    assert sorted(pre.generated_keys()) == sorted(plan.required_keys())
    assert pre.counts()["hashing_with_salt:id"] == 4
