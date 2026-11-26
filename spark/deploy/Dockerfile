# spark/ (anamika_spark): the driver and executor image (one image, both roles).
#
# Target: < 1 GB, no model weights (review item R4: NER models are a pinned Blob folder fetched at run
# time and verified by hash, so the image digest in the init data stays the same when a model changes).
# Estimated, not yet built here: python:3.12-slim ~125 MB + JRE ~190 MB + pruned pyspark ~325 MB
# + pyarrow ~170 MB + skald_core (release) ~30 MB + the rest ~30 MB = ~870 MB uncompressed.
#
# Build the skald_core wheel first, from the SKALD repo, inside the same Debian release:
#     maturin build --release -m k-anonymisation/SKALD/python/Cargo.toml -o k-anonymisation/spark/wheels
# and add the NER library only if jobs will use it:   --build-arg WITH_NER=1  (copy anamika_ner next to this file)
#
#     (run from k-anonymisation/spark)  docker build -f deploy/Dockerfile -t anamika-spark:dev .
# The Co-ordinator pins the DIGEST of the pushed image (not the tag) in the init data.

FROM python:3.12-slim-bookworm@sha256:44cf1793efa7c7a476bb0f2cff81443f4a072c90c1cb127e2924933daa3e8c64

ARG WITH_NER=0
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PYSPARK_PYTHON=python3

# A headless JRE only: Spark needs Java, nothing else. tini reaps Python worker processes.
RUN apt-get update \
 && apt-get install -y --no-install-recommends openjdk-17-jre-headless tini \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/anamika
COPY wheels/ /tmp/wheels/
COPY pyproject.toml ./
COPY anamika_spark ./anamika_spark
COPY deploy/main.py ./main.py

# Pinned runtime deps (pyspark minor == the SPARK_HOME the Operator expects).
RUN pip install /tmp/wheels/skald_core-*.whl "pyspark==4.3.0" "pyarrow>=14" "cryptography>=41" \
        "azure-storage-blob>=12.19" "azure-identity>=1.15" \
 && pip install --no-deps . \
 && rm -rf /tmp/wheels

# Drop what a k-anonymity job never loads: MLlib and its linear algebra, GraphX, Streaming, Spark Connect,
# Hive and its metastore, RocksDB (UI state store; the UI is off). Kubernetes jars stay. Verified by running
# the test suite against a pruned copy (see README).
RUN SP=$(python -c "import pyspark,os;print(os.path.dirname(pyspark.__file__))") \
 && cd "$SP/jars" \
 && rm -f rocksdbjni-*.jar spark-mllib*.jar spark-graphx*.jar spark-streaming*.jar spark-connect*.jar \
          spark-hive*.jar hive-*.jar breeze*.jar spire*.jar cats-kernel*.jar arpack*.jar lapack*.jar blas*.jar \
          datanucleus-*.jar derby*.jar javolution*.jar jdo-api*.jar spark-repl*.jar scala-compiler*.jar opencsv*.jar \
 && rm -rf "$SP/examples" "$SP/data"

COPY deploy/spark-defaults.conf deploy/log4j2.properties /tmp/conf/
RUN SP=$(python -c "import pyspark,os;print(os.path.dirname(pyspark.__file__))") \
 && mkdir -p "$SP/conf" && cp /tmp/conf/* "$SP/conf/" && rm -rf /tmp/conf

# Not root. /run/anamika is where the Pod mounts memory-backed emptyDirs (RPC secret, Spark local dir).
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin spark \
 && mkdir -p /run/anamika && chown -R spark /run/anamika /opt/anamika
USER 10001
ENV PYTHONPATH=/opt/anamika

ENTRYPOINT ["/usr/bin/tini", "--"]
# The Operator overrides the command (spark-submit); run by hand for the local single-VM path:
#   docker run -e ANAMIKA_JOB=... -e ANAMIKA_PHASE=all -e ANAMIKA_SPARK_MASTER='local[*]' ... anamika-spark
CMD ["python", "-m", "anamika_spark.run"]
