"""Init step of every Spark pod: put the job's RPC secret on tmpfs for spark.authenticate (review item R1).

The driver and the executors authenticate each other with a shared secret. Spark's default on Kubernetes
puts it in an environment variable of the pod spec, which anyone with cluster access can read, so it is
instead released by KBS to attested guests only and written to a file on a memory-backed emptyDir, which
spark.authenticate.secret.file then points at.

    python -m anamika_spark.initsecret            # env: ANAMIKA_JOB, ANAMIKA_SECRET_FILE (default below)

The file holds the secret hex-encoded (Spark reads it as text and raw bytes need not be UTF-8), mode 0600,
and is written atomically so Spark never sees half of it. Never log the value.
"""

from __future__ import annotations

import os
import sys
from typing import Optional

from .kbs import CdhClient, KeySource, KeyUnavailable

DEFAULT_PATH = "/run/anamika/spark-secret"
MIN_BYTES = 32  # anything shorter is not a secret worth authenticating with


def write_secret(source: KeySource, job: str, path: str = DEFAULT_PATH) -> None:
    raw = source.get(job, "spark-secret")
    if len(raw) < MIN_BYTES:
        raise KeyUnavailable("spark-secret is too short")
    os.makedirs(os.path.dirname(path) or ".", mode=0o700, exist_ok=True)
    tmp = f"{path}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(raw.hex())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def main(env=os.environ, source: Optional[KeySource] = None) -> int:
    job = env.get("ANAMIKA_JOB", "")
    try:
        write_secret(source or CdhClient(), job, env.get("ANAMIKA_SECRET_FILE", DEFAULT_PATH))
    except KeyUnavailable as e:
        print(f"anamika-spark init: {e}", file=sys.stderr)  # names the resource, never a value
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
