"""Entrypoint of the Spark driver: `python -m anamika_spark.run` (also deploy/main.py).

Environment (see deploy/README.md):
  ANAMIKA_JOB            job id (required)
  ANAMIKA_PHASE          all | measure | apply (also read from PHASE); default all
  ANAMIKA_CHOICE         the approved grid cell id (apply after explore_k)
  ANAMIKA_STORE_URL      https://<account>.blob.core.windows.net/<container>
  ANAMIKA_STORE_DIR      a local directory instead (local runs and tests)
  ANAMIKA_INPUT_URL      flow B: https://<account>.blob.core.windows.net/<container>/<prefix>/ holding manifest.enc + parts
  ANAMIKA_INPUT_ANONYMOUS 1 = read that URL with no credential (the only mode implemented); ANAMIKA_INPUT_DIR/_PREFIX locally
  ANAMIKA_KEY_MODE       cdh (default, inside the kata pod) | dir (files in ANAMIKA_KEY_DIR, NOT confidential)
  ANAMIKA_SPARK_MASTER   local[*] for the single-VM path; unset on Kubernetes (spark-submit supplies it)
  ANAMIKA_DRIVER_MEMORY  local mode only (default 1g)
  ANAMIKA_LOCAL_DIR      spark.local.dir for local mode (put it on tmpfs)
  ANAMIKA_VAULT_PREFIX   where vaults/{id}/v{n}.enc live (default: the container root)
  ANAMIKA_NER_MODEL_REF, ANAMIKA_NER_SHA256, ANAMIKA_NER_CACHE   NER model (used only if the manifest asks)

Exit code 0 only when status.json says ok; the code itself is in status.json, never on stderr.
"""

from __future__ import annotations

import logging
import os
import sys

from . import logscrub
from .job import PHASES, run_job
from .io import with_input
from .kbs import CdhClient, DirKeySource
from .ner import settings_from_env


def main(env=os.environ) -> int:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")
    logscrub.install()
    phase = env.get("ANAMIKA_PHASE") or env.get("PHASE") or "all"
    if phase not in PHASES or not env.get("ANAMIKA_JOB"):
        print("anamika-spark: ANAMIKA_JOB and a valid ANAMIKA_PHASE are required", file=sys.stderr)
        return 2
    store = {"kind": "local", "root": env["ANAMIKA_STORE_DIR"]} if env.get("ANAMIKA_STORE_DIR") else {"kind": "azure", "url": env["ANAMIKA_STORE_URL"]}
    # Flow B: ANAMIKA_INPUT_URL (+ ANAMIKA_INPUT_ANONYMOUS=1) moves only the INPUT to the owner's container.
    store = with_input(store, env)
    kbs = DirKeySource(env.get("ANAMIKA_KEY_DIR", "/keys")) if env.get("ANAMIKA_KEY_MODE") == "dir" else CdhClient()
    result = run_job(env["ANAMIKA_JOB"], phase, store, kbs, choice=env.get("ANAMIKA_CHOICE") or None,
                     ner=settings_from_env(env), vault_prefix=env.get("ANAMIKA_VAULT_PREFIX", ""))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
