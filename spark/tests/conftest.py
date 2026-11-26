"""One local[2] Spark session for the whole run, 1 GB driver: RAM on the dev box is tight."""

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).parent))
# Python workers must find this package and the same interpreter (skald_core lives in that venv).
# anamika_ner (the NER library) lives in the Grievance repo; tests that need it skip when it is absent.
NER_SRC = Path(os.environ.get("ANAMIKA_NER_SRC", ROOT.parent / "Grievance-data-anonymization" / "app"))
os.environ["PYTHONPATH"] = os.pathsep.join(filter(None, [str(ROOT), str(Path(__file__).parent), str(NER_SRC),
                                                         os.environ.get("PYTHONPATH")]))
sys.path.insert(0, str(NER_SRC))
os.environ.setdefault("PYSPARK_PYTHON", sys.executable)
os.environ.setdefault("PYSPARK_DRIVER_PYTHON", sys.executable)

SKALD = Path(os.environ.get("SKALD_DIR", ROOT.parent / "k-anonymisation" / "SKALD"))
CORPUS = SKALD / "conformance"


@pytest.fixture(scope="session")
def spark(tmp_path_factory):
    from anamika_spark.session import build_session

    s = build_session({"ANAMIKA_DRIVER_MEMORY": "1g", "ANAMIKA_LOCAL_DIR": str(tmp_path_factory.mktemp("sparklocal"))},
                      master="local[2]")
    yield s
    s.stop()
