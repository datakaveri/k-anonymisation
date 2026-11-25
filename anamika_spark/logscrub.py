"""Keep payloads out of logs.

Defence in depth, not the primary control: the code never logs payloads, and the
pods run with log streaming denied. This filter covers the case where a library
or a stack trace does it anyway.

Before a batch is processed the runner registers needles taken from it (file
paths, and windows of the file bytes). Any log record whose message, arguments
or traceback contains a needle is dropped, and tracebacks are reduced to the
exception class (a traceback's message can quote the data it choked on).
"""

from __future__ import annotations

import logging
import threading
from typing import Iterable, Set

_MIN = 4
_lock = threading.Lock()
_needles: Set[str] = set()


def protect(*values) -> None:
    """Register strings or bytes that must never appear in a log record."""
    with _lock:
        for v in values:
            s = v.decode("latin-1") if isinstance(v, (bytes, bytearray)) else str(v)
            if len(s) >= _MIN:
                _needles.add(s)


def protect_bytes(data: bytes, window: int = 16, samples: int = 8) -> None:
    """Register evenly spaced windows of a payload (cheap, and enough to catch an echo of it)."""
    if len(data) < window:
        protect(data)
        return
    step = max(1, (len(data) - window) // max(1, samples - 1))
    protect(*(data[i : i + window] for i in range(0, len(data) - window + 1, step)))


def clear() -> None:
    with _lock:
        _needles.clear()


class ScrubFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            text = record.getMessage()
        except Exception:  # a broken format string may itself hold data
            return False
        if record.exc_info:
            record.exc_text = f"<{record.exc_info[0].__name__ if record.exc_info[0] else 'error'}: message withheld>"
            record.exc_info = None
        with _lock:
            hay = [text, record.exc_text or ""]
            return not any(n in h for n in _needles for h in hay)


def install(logger: logging.Logger | None = None) -> ScrubFilter:
    """Attach to the root logger's handlers and the logger itself (idempotent)."""
    f = ScrubFilter()
    target = logger or logging.getLogger()
    if not any(isinstance(x, ScrubFilter) for x in target.filters):
        target.addFilter(f)
    for h in target.handlers:
        if not any(isinstance(x, ScrubFilter) for x in h.filters):
            h.addFilter(f)
    return f
