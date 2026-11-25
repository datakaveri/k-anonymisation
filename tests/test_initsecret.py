import os
import stat

import pytest

from anamika_spark import initsecret
from anamika_spark.kbs import FakeKbs, KeyUnavailable

JOB = "j-init-secret"


def test_secret_is_written_hex_0600_on_the_given_path(tmp_path):
    path = tmp_path / "run" / "spark-secret"
    initsecret.write_secret(FakeKbs({(JOB, "spark-secret"): bytes(range(40))}), JOB, str(path))
    assert path.read_text() == bytes(range(40)).hex()
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert not os.path.exists(f"{path}.tmp")


def test_short_or_missing_secret_fails_without_a_file(tmp_path):
    path = tmp_path / "s"
    with pytest.raises(KeyUnavailable):
        initsecret.write_secret(FakeKbs({(JOB, "spark-secret"): b"short"}), JOB, str(path))
    with pytest.raises(KeyUnavailable):
        initsecret.write_secret(FakeKbs(), JOB, str(path))
    assert not path.exists()


def test_main_exit_codes_and_no_value_on_stderr(tmp_path, capsys):
    env = {"ANAMIKA_JOB": JOB, "ANAMIKA_SECRET_FILE": str(tmp_path / "s")}
    assert initsecret.main(env, FakeKbs({(JOB, "spark-secret"): b"\x01" * 32})) == 0
    assert initsecret.main(env, FakeKbs()) == 1
    assert "01" * 16 not in capsys.readouterr().err
