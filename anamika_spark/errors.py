"""One error vocabulary for the driver and the executors.

A job ends with a short code in status.json (never a message: messages can quote rows). Executors
run in other processes, and Spark wraps their exceptions into a Py4J error whose text is the worker's
whole traceback. So an executor converts every exception to `RuntimeError("ANAMIKA_CODE=<CODE>")`
(coded()), and the driver reads the code back out of whatever Spark raised (code_of()). Nothing
else from the original exception survives, which is the point: a library error such as a CSV parse
failure can quote the offending row.
"""

from __future__ import annotations

import functools
import re

from .io import IoError

CODE_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,39}$")
_MARK = re.compile(r"ANAMIKA_CODE=([A-Z][A-Z0-9_]{0,39})")


class JobError(Exception):
    """A failure with a contract code. The message, if any, must never contain data."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def normalise(code: str) -> str:
    """Map a library code to the contract's vocabulary (anything unmappable is JOB_FAILED)."""
    if code.startswith("CONFIG_"):
        return "INVALID_INPUT"  # the SKALD config failed validation
    return code if CODE_RE.match(code) else "JOB_FAILED"


def code_of(exc: BaseException) -> str:
    """The contract code for any exception, using the class and code only, never the message."""
    if isinstance(exc, (JobError, IoError)):
        return normalise(exc.code)
    code = getattr(exc, "code", None)  # skald_core.SkaldError carries one
    if isinstance(code, str):
        return normalise(code)
    found = _MARK.search(str(exc))  # an executor failure that Spark re-raised
    if found:
        return found.group(1)
    return "JOB_FAILED"


def coded(fn):
    """Decorator for functions that run on executors: any failure becomes a message holding only a code."""

    @functools.wraps(fn)
    def inner(*a, **kw):
        try:
            return fn(*a, **kw)
        except BaseException as e:  # noqa: BLE001 - nothing may escape with a message
            if isinstance(e, (KeyboardInterrupt, SystemExit, GeneratorExit)):
                raise
            raise RuntimeError(f"ANAMIKA_CODE={code_of(e)}") from None

    return inner


def coded_iter(fn):
    """coded() for mapPartitions functions: they are generators, so the failure surfaces while iterating."""

    @functools.wraps(fn)
    def inner(it):
        try:
            yield from fn(it)
        except BaseException as e:  # noqa: BLE001
            if isinstance(e, (KeyboardInterrupt, SystemExit, GeneratorExit)):
                raise
            raise RuntimeError(f"ANAMIKA_CODE={code_of(e)}") from None

    return inner
