"""A model-free NER engine for tests: finds every 'Alice' and 'Bob'. Importable, so executors can unpickle it."""

from anamika_ner.types import Span


class FakeEngine:
    def __init__(self, model_dir=None):
        self.model_dir = model_dir

    def detect(self, texts, min_confidence=0.0):
        out = []
        for t in texts:
            found = []
            for name in ("Alice", "Bob"):
                i = t.find(name)
                while i >= 0:
                    found.append(Span(i, i + len(name), "PERSON", "fake", 0.9))
                    i = t.find(name, i + 1)
            out.append(sorted(found, key=lambda s: s.start))
        return out


def make_models(root):
    """A pinned fake model folder: (path, sha256 of its manifest)."""
    import hashlib

    from anamika_ner import modelstore

    d = root / "models"
    (d / "IndicNER").mkdir(parents=True)
    (d / "IndicNER" / "config.json").write_text('{"synthetic": true}')
    (d / "IndicNER" / "weights.bin").write_bytes(b"\x00\x01synthetic")
    return d, hashlib.sha256(modelstore.build_manifest(d)).hexdigest()
