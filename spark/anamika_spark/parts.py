"""Row parts as Arrow: decrypt + verify + parse on the way in, serialise on the way out.

Plaintext of a part (contracts/bundle/README.md): RFC 4180 CSV, UTF-8, no header (the header is in the
manifest), cut at row boundaries. Every column is read as a string and nothing is "null": SKALD's
batch API expects exactly that (the conformance corpus is read the same way), and it keeps "007"
from becoming 7.
"""

from __future__ import annotations

import csv
import hashlib
import io
from typing import Any, Dict, List

import pyarrow as pa
import pyarrow.csv as pacsv

from .errors import JobError


def parse_csv(data: bytes, header: List[str]) -> pa.RecordBatch:
    """A headerless CSV part as one RecordBatch of string columns."""
    if not data:
        return pa.RecordBatch.from_arrays([pa.array([], pa.string()) for _ in header], names=header)
    table = pacsv.read_csv(
        io.BytesIO(data),
        read_options=pacsv.ReadOptions(column_names=header, use_threads=False, block_size=max(1 << 20, len(data) + 1)),
        parse_options=pacsv.ParseOptions(newlines_in_values=True),
        convert_options=pacsv.ConvertOptions(column_types={c: pa.string() for c in header}, strings_can_be_null=False),
    )
    batches = table.combine_chunks().to_batches()
    return batches[0] if batches else pa.RecordBatch.from_arrays([pa.array([], pa.string()) for _ in header], names=header)


def verify_part(data: bytes, entry: Dict[str, Any]) -> None:
    """The manifest's length and digest for this part; a mismatch is a part that is not the one uploaded."""
    if len(data) != entry["plaintext_bytes"] or hashlib.sha256(data).hexdigest() != entry["plaintext_sha256"]:
        raise JobError("PARTS_MISMATCH")


def write_csv(batch: pa.RecordBatch) -> bytes:
    """A batch as headerless RFC 4180 CSV with \\n line ends, quoting only where needed.

    Python's csv module rather than pyarrow's writer: pyarrow quotes EVERY string even with
    quoting_style="needed", and SKALD's CLI (Rust csv, "necessary") quotes only fields that contain a
    comma, quote or newline. Matching it keeps the output byte-identical to the CLI's.
    """
    if batch.num_rows == 0:
        return b""
    sink = io.StringIO(newline="")
    csv.writer(sink, lineterminator="\n").writerows(zip(*[c.to_pylist() for c in batch.columns]))
    return sink.getvalue().encode("utf-8")


def to_ipc(batch: pa.RecordBatch) -> bytes:
    """Arrow IPC stream bytes: how a batch is held in Spark's cache between phases."""
    sink = pa.BufferOutputStream()
    with pa.ipc.new_stream(sink, batch.schema) as w:
        w.write_batch(batch)
    return sink.getvalue().to_pybytes()


def from_ipc(data: bytes) -> pa.RecordBatch:
    reader = pa.ipc.open_stream(data)
    batches = list(reader)
    return batches[0] if batches else pa.RecordBatch.from_arrays([], names=[])
