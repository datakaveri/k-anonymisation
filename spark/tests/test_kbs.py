import base64
import urllib.error

import pytest

from anamika_spark import bundle, kbs

JOB = "a3f9c2d17e04"


def http_error(code):
    return urllib.error.HTTPError("u", code, "m", {}, None)


def test_cdh_url_and_retry_then_success():
    seen, sleeps, answers = [], [], [http_error(404), urllib.error.URLError("refused"), http_error(503), b"k" * 32]

    def opener(url, timeout):
        seen.append(url)
        a = answers.pop(0)
        if isinstance(a, Exception):
            raise a
        return a

    c = kbs.CdhClient(opener=opener, sleep=sleeps.append, backoff_s=1, max_backoff_s=3)
    assert c.get(JOB, "user-key") == b"k" * 32
    assert seen[0] == f"http://127.0.0.1:8006/cdh/resource/anamika/{JOB}/user-key" and len(seen) == 4
    assert sleeps == [1, 2, 3]  # exponential, capped


def test_cdh_refusal_is_not_retried():
    calls = []

    def opener(url, timeout):
        calls.append(1)
        raise http_error(403)

    with pytest.raises(kbs.KeyUnavailable, match="403"):
        kbs.CdhClient(opener=opener, sleep=lambda s: None).get(JOB, "key-00")
    assert len(calls) == 1


def test_cdh_gives_up():
    def opener(url, timeout):
        raise TimeoutError

    with pytest.raises(kbs.KeyUnavailable, match="3 attempts"):
        kbs.CdhClient(opener=opener, sleep=lambda s: None, retries=2).get(JOB, "key-01")


@pytest.mark.parametrize("job,name", [("../etc", "user-key"), (JOB, "user-key/../x"), (JOB, "key-1"), ("A" * 8, "key-00")])
def test_names_are_validated(job, name):
    with pytest.raises(kbs.KeyUnavailable, match="invalid"):
        kbs.CdhClient(opener=lambda u, t: b"x").get(job, name)


def test_keystore_derives_and_caches():
    k_user = bytes(range(32))
    fake = kbs.FakeKbs({(JOB, "user-key"): k_user, (JOB, "key-00"): b"s" * 32})
    ks = kbs.KeyStore(fake, JOB)
    assert ks.keys == bundle.Keys.from_user_key(k_user)
    assert ks.slot("key-00") == b"s" * 32
    ks.keys, ks.slot("key-00")
    assert fake.calls == 2  # cached
    assert "redacted" in repr(ks)
    ks.forget()
    ks.keys
    assert fake.calls == 3


def test_keystore_accepts_base64_and_rejects_wrong_length():
    k = bytes(range(32))
    ks = kbs.KeyStore(kbs.FakeKbs({(JOB, "user-key"): base64.b64encode(k)}), JOB)
    assert ks.keys == bundle.Keys.from_user_key(k)
    with pytest.raises(kbs.KeyUnavailable, match="32-byte"):
        kbs.KeyStore(kbs.FakeKbs({(JOB, "user-key"): b"short"}), JOB).keys
    with pytest.raises(kbs.KeyUnavailable):
        kbs.KeyStore(kbs.FakeKbs(), JOB).slot("key-00")


def test_dir_key_source(tmp_path):
    (tmp_path / "user-key").write_bytes(b"k" * 32)
    src = kbs.DirKeySource(str(tmp_path))
    assert src.get(JOB, "user-key") == b"k" * 32
    with pytest.raises(kbs.KeyUnavailable):
        src.get(JOB, "key-00")


def test_spark_secret_is_a_known_resource_name():
    assert kbs.FakeKbs({(JOB, 'spark-secret'): b'x'}).get(JOB, 'spark-secret') == b'x'
