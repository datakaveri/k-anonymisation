import logging

from anamika_spark import logscrub


def make():
    logscrub.clear()
    log = logging.getLogger("logscrub-test")
    log.handlers.clear(); log.propagate = False; log.setLevel(logging.DEBUG)
    records = []

    class H(logging.Handler):
        def emit(self, r):
            records.append(r.getMessage() + (r.exc_text or ""))

    h = H(); log.addHandler(h)
    logscrub.install(log); h.addFilter(logscrub.ScrubFilter())
    return log, records


def test_blocks_batch_content_everywhere():
    log, out = make()
    logscrub.protect("patients/synthetic-name.dcm")
    logscrub.protect_bytes(b"SYNTHETIC-PAYLOAD-0123456789-abcdefghij")
    log.info("done %s", "patients/synthetic-name.dcm")
    log.info("echo SYNTHETIC-PAYLOAD-0123")
    log.info("fine, 3 files processed")
    assert out == ["fine, 3 files processed"]


def test_traceback_message_withheld():
    log, out = make()
    try:
        raise ValueError("secret-value-xyz")
    except ValueError:
        log.exception("failed")
    assert out and "secret-value-xyz" not in out[0] and "ValueError" in out[0]


def test_short_needles_ignored_and_clear():
    log, out = make()
    logscrub.protect("ab")
    log.info("ab")
    logscrub.protect("longneedle")
    logscrub.clear()
    log.info("longneedle")
    assert out == ["ab", "longneedle"]
