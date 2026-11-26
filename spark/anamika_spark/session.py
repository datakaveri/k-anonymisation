"""The SparkSession, configured for confidential data (review items R1, R2).

On Kubernetes the Spark Operator's spark-submit supplies the master, executor sizing and the R1
authentication settings (deploy/spark-defaults.conf); this module then only adds what must hold
everywhere. Local mode (`local[*]`, a small job) is the same code path with the master set here.

  * UI off, event log off (R2): both put task and SQL text on a web page or on disk.
  * spark.io.encryption.enabled: spill, shuffle, cached blocks and broadcasts are encrypted with an
    ephemeral per-application key. Keys and rows reach executors by broadcast and cache, and Spark
    would otherwise write them to local disk in clear. (Local dirs should also be tmpfs; see deploy/.)
  * log level WARN: INFO lines name tasks and partitions, and a WARN-level library may still quote
    data, which is what logscrub is for.
"""

from __future__ import annotations

import logging
import os
from typing import Mapping, Optional

from . import logscrub


def build_session(env: Mapping[str, str] = os.environ, master: Optional[str] = None):
    from pyspark.sql import SparkSession  # noqa: PLC0415

    b = (SparkSession.builder.appName("anamika-spark")
         .config("spark.ui.enabled", "false")
         .config("spark.eventLog.enabled", "false")
         .config("spark.ui.showConsoleProgress", "false")
         .config("spark.io.encryption.enabled", "true")
         .config("spark.sql.shuffle.partitions", "8")
         .config("spark.python.worker.reuse", "true"))
    master = master or env.get("ANAMIKA_SPARK_MASTER")
    if master:  # on Kubernetes spark-submit already set it
        b = b.master(master)
    if master and master.startswith("local"):
        b = b.config("spark.driver.memory", env.get("ANAMIKA_DRIVER_MEMORY", "1g"))
        if env.get("ANAMIKA_LOCAL_DIR"):
            b = b.config("spark.local.dir", env["ANAMIKA_LOCAL_DIR"])
    spark = b.getOrCreate()
    spark.sparkContext.setLogLevel("WARN")
    logging.getLogger("py4j").setLevel(logging.WARNING)
    logscrub.install()
    return spark
