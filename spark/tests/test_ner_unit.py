"""NER settings and column selection, and redaction of one batch with a model-free engine (no Spark)."""

import pyarrow as pa
import pytest

pytest.importorskip("anamika_ner")

from anamika_spark.errors import JobError
from anamika_spark.ner import NerSettings, ner_columns, redact_batch, settings_from_env
from fake_ner import FakeEngine, make_models


def manifest(required=True, enabled=True, cols=("note",)):
    return {"ner": {"required": required}, "config": {"data_type": "tabular", "tabular": {
        "free_text_anonymization": {"enabled": enabled, "columns": list(cols)}}}}


def test_columns_need_both_the_manifest_and_the_config():
    assert ner_columns(manifest()) == ["note"]
    assert ner_columns(manifest(required=False)) == []
    assert ner_columns(manifest(enabled=False)) == []
    assert ner_columns({"config": {"data_type": "tabular", "tabular": {}}, "ner": {"required": True}}) == []


def test_settings_need_a_pinned_model(monkeypatch):
    assert settings_from_env({}) is None
    with pytest.raises(JobError):
        settings_from_env({"ANAMIKA_NER_MODEL_REF": "https://x/y/"})  # no pin
    s = settings_from_env({"ANAMIKA_NER_MODEL_REF": "https://x/y/", "ANAMIKA_NER_SHA256": "a" * 64})
    assert s.model_ref == "https://x/y/" and s.sha256 == "a" * 64


def test_redact_replaces_the_column_and_keeps_the_schema(tmp_path):
    d, pin = make_models(tmp_path)
    batch = pa.RecordBatch.from_pydict({"id": ["1", "2"], "note": ["call Alice today", "nothing here"]})
    out = redact_batch(batch, ["note"], NerSettings(str(d), pin, engine_factory=FakeEngine))
    assert out.schema.names == ["id", "note"]
    assert out.column("note").to_pylist() == ["call [PERSON] today", "nothing here"]
    assert out.column("id").to_pylist() == ["1", "2"]


def test_unknown_column_is_invalid_input(tmp_path):
    d, pin = make_models(tmp_path)
    batch = pa.RecordBatch.from_pydict({"id": ["1"]})
    with pytest.raises(JobError) as e:
        redact_batch(batch, ["note"], NerSettings(str(d), pin, engine_factory=FakeEngine))
    assert e.value.code == "INVALID_INPUT"
