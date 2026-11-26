"""Fetch a job's keys inside the confidential pod (the Spark DRIVER only).

Vendored from anamika-ray (same vector tests); both should later move to one shared
`anamika-bundle` Python package so the three copies cannot drift.

Inside a kata pod the Confidential Data Hub (CDH) listens on 127.0.0.1:8006 and
hands out KBS resources to the attested guest only:

    GET http://127.0.0.1:8006/cdh/resource/anamika/{job}/user-key      K_user
    GET http://127.0.0.1:8006/cdh/resource/anamika/{job}/key-NN        saved keys / vault keys
    GET http://127.0.0.1:8006/cdh/resource/anamika/{job}/spark-secret  shared RPC secret (R1; every pod's init step)

The AO writes these to Trustee after it has verified the job; nothing here ever
talks to Trustee directly, so there is no credential in the image.

Keys live in memory only: KeyStore never writes them anywhere, caches them in
plain attributes of one object, and hides them from repr(). A key can be
dropped with forget() once the job no longer needs it.
"""

from __future__ import annotations

import base64
import re
import time
import urllib.error
import urllib.request
from typing import Callable, Dict, Mapping, Optional, Protocol


from .bundle import Keys, job_key

CDH_BASE = "http://127.0.0.1:8006/cdh/resource"
_JOB = re.compile(r"^[a-z0-9-]{6,64}$")
_NAME = re.compile(r"^(user-key|key-[0-9]{2}|spark-secret)$")


class KeyUnavailable(RuntimeError):
    """The key could not be fetched. The message names the resource, never key bytes."""


class KeySource(Protocol):
    def get(self, job: str, name: str) -> bytes: ...


class CdhClient:
    """GET resources from the local CDH with retries.

    Retries cover the window in which the pod is up before the AO has released
    the keys (404) and transient hub errors (5xx, refused connection). Anything
    else (403: attestation refused) fails at once: retrying cannot help and
    would only delay the error code the AO is waiting for.
    """

    def __init__(
        self,
        base_url: str = CDH_BASE,
        retries: int = 8,
        backoff_s: float = 0.5,
        max_backoff_s: float = 10.0,
        timeout_s: float = 5.0,
        opener: Optional[Callable[[str, float], bytes]] = None,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.base_url = base_url.rstrip("/")
        self.retries, self.backoff_s, self.max_backoff_s, self.timeout_s = retries, backoff_s, max_backoff_s, timeout_s
        self._open = opener or self._http_get
        self._sleep = sleep

    @staticmethod
    def _http_get(url: str, timeout: float) -> bytes:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 - fixed loopback URL
            return resp.read()

    def get(self, job: str, name: str) -> bytes:
        _check(job, name)
        url = f"{self.base_url}/anamika/{job}/{name}"
        delay = self.backoff_s
        last = "no attempt"
        for attempt in range(self.retries + 1):
            try:
                return self._open(url, self.timeout_s)
            except urllib.error.HTTPError as e:
                if e.code not in (404, 408, 425, 429) and e.code < 500:
                    raise KeyUnavailable(f"CDH refused {name} (HTTP {e.code})") from None
                last = f"HTTP {e.code}"
            except (urllib.error.URLError, ConnectionError, TimeoutError, OSError) as e:
                last = type(e).__name__
            if attempt < self.retries:
                self._sleep(delay)
                delay = min(delay * 2, self.max_backoff_s)
        raise KeyUnavailable(f"{name} not available after {self.retries + 1} attempts ({last})")


class FakeKbs:
    """In-memory stand-in for tests and local runs. Not for production use."""

    def __init__(self, resources: Mapping[tuple, bytes] | None = None):
        self.resources: Dict[tuple, bytes] = dict(resources or {})
        self.calls = 0

    def put(self, job: str, name: str, value: bytes) -> None:
        self.resources[(job, name)] = value

    def get(self, job: str, name: str) -> bytes:
        _check(job, name)
        self.calls += 1
        try:
            return self.resources[(job, name)]
        except KeyError:
            raise KeyUnavailable(f"{name} not available") from None


class DirKeySource:
    """Keys as files in a directory (a mounted Secret): ONLY for non-confidential runs without a
    CDH (local development). A cluster admin can read such a Secret, so never use it for real data."""

    def __init__(self, root: str = "/keys"):
        self.root = root

    def get(self, job: str, name: str) -> bytes:
        _check(job, name)
        try:
            with open(f"{self.root}/{name}", "rb") as fh:
                return fh.read()
        except OSError:
            raise KeyUnavailable(f"{name} not available") from None


def _check(job: str, name: str) -> None:
    # The job id goes into a URL path: refuse anything that could change the route.
    if not _JOB.match(job) or not _NAME.match(name):
        raise KeyUnavailable("invalid job id or key name")


def _as_32(raw: bytes, what: str) -> bytes:
    """KBS resources are raw bytes; accept base64 text too, since a resource written by hand often is."""
    if len(raw) == 32:
        return raw
    try:
        decoded = base64.b64decode(raw.strip(), validate=True)
        if len(decoded) == 32:
            return decoded
    except ValueError:
        pass
    raise KeyUnavailable(f"{what} is not a 32-byte key")


class KeyStore:
    """A job's keys, fetched on first use and kept in memory."""

    def __init__(self, source: KeySource, job: str):
        self._source, self.job = source, job
        self._user: Optional[bytes] = None
        self._derived: Optional[Keys] = None
        self._slots: Dict[str, bytes] = {}

    def __repr__(self) -> str:
        return f"KeyStore(job={self.job!r}, <keys redacted>)"

    @property
    def keys(self) -> Keys:
        """input/manifest/output/summary keys derived from K_user."""
        if self._derived is None:
            self._user = _as_32(self._source.get(self.job, "user-key"), "user-key")
            self._derived = Keys.from_user_key(self._user)
        return self._derived

    def job_key(self, kind: str, name: str) -> bytes:
        """The contract's per-job key for (kind, name), derived from K_user; 32 bytes."""
        self.keys  # fetches and caches K_user
        return job_key(self._user, kind, name)

    def slot(self, slot: str) -> bytes:
        """A saved key or vault key released at key-NN (32 bytes for HMAC salts, AES and vault keys)."""
        if slot not in self._slots:
            self._slots[slot] = _as_32(self._source.get(self.job, slot), slot)
        return self._slots[slot]

    def forget(self) -> None:
        self._user = self._derived = None
        self._slots.clear()
