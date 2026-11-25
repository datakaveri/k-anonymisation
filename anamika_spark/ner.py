"""Optional NER stage: redact free-text columns before anything else sees them.

Runs only when manifest.ner.required is true (the manifest, not the AO's word, decides) and the SKALD
config enables free_text_anonymization for some columns. The model is NOT in the image: it is a pinned
Blob folder that anamika_ner fetches and verifies by hash before loading (R4); this module only passes
the reference and the pin through. `anamika_ner.spark.ner_map_in_arrow` does the per-batch work, so
the same engine cache (one per Python worker) applies.

The redacted text REPLACES the original column and the span list is dropped, because the output
schema must stay the manifest's header (and spans hold offsets of personal data).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

import pyarrow as pa

from .errors import JobError


@dataclass(frozen=True)
class NerSettings:
    model_ref: str                          # local dir or https Blob folder
    sha256: str                             # pin of the model manifest
    cache_dir: Optional[str] = None
    engine_factory: Optional[Callable] = None   # tests only; production loads the real engine


def settings_from_env(env=os.environ) -> Optional[NerSettings]:
    if not env.get("ANAMIKA_NER_MODEL_REF"):
        return None
    sha = env.get("ANAMIKA_NER_SHA256", "")
    if len(sha) != 64:
        raise JobError("INVALID_INPUT")  # an unpinned model would defeat hash verification
    return NerSettings(env["ANAMIKA_NER_MODEL_REF"], sha, env.get("ANAMIKA_NER_CACHE"))


def ner_columns(manifest: Dict[str, Any]) -> List[str]:
    """Free-text columns to redact: [] unless the manifest asks for NER AND the config enables it."""
    if not (manifest.get("ner") or {}).get("required"):
        return []
    cfg = manifest["config"]
    section = cfg.get(cfg.get("data_type", ""), {}) if isinstance(cfg.get("data_type"), str) else {}
    block = section.get("free_text_anonymization") or {}
    if not block.get("enabled"):
        return []
    return [c for c in block.get("columns", []) if isinstance(c, str)]


def redact_batch(batch: pa.RecordBatch, columns: List[str], settings: NerSettings) -> pa.RecordBatch:
    """Executor side: replace each free-text column by its redacted text."""
    from anamika_ner.spark import ner_map_in_arrow  # noqa: PLC0415 - optional dependency, imported on the worker
    from anamika_ner.types import Policy  # noqa: PLC0415

    for col in columns:
        if col not in batch.schema.names:
            raise JobError("INVALID_INPUT")
        fn = ner_map_in_arrow(settings.model_ref, settings.sha256, col, policy=Policy(),
                              engine_factory=settings.engine_factory, cache_dir=settings.cache_dir)
        out = next(iter(fn(iter([batch]))))
        idx = batch.schema.get_field_index(col)
        redacted = out.column(f"redacted_{col}").fill_null("")
        batch = batch.set_column(idx, pa.field(col, pa.string()), redacted)
    return batch
