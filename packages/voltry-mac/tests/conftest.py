"""Shared setup for the package's tests.

tests/reports.py, the complete report fixtures and their edits, is registered once as
``voltry_mac_test_reports``, and tests/pdf_goldens.py, the golden PDFs and their images, as
``voltry_mac_test_pdf_goldens``, and tests/pdf_pages.py, the PDF read back, as
``voltry_mac_test_pdf_pages``, and tests/write_spy.py, the runtime half of the one-writer
rule, as ``voltry_mac_test_write_spy``, and tests/fake_mac.py, the fake M5 that the run's
tests and the copy goldens share, as ``voltry_mac_test_fake_mac``, and tests/copy_golden.py,
every message around the report as golden text, as ``voltry_mac_test_copy_golden``, and
tests/character_table.py, which writes the character table, as
``voltry_mac_test_character_table``: the package's own pytest run and the repository's root
run (import mode importlib) use different configs, and neither puts tests/ on the import
path. The spy is installed once. A test fails if package code other than the writer wrote a
file while it ran, or before it began (at import, or late from an earlier test's thread),
and the session fails if one did after the last test. Every test starts with SIGINT,
SIGTERM and SIGHUP as Python sets them when it starts from a terminal.
"""

from __future__ import annotations

import importlib.util
import signal
import sys
from pathlib import Path

import pytest

for _name, _file in (
    ("voltry_mac_test_reports", "reports.py"),
    ("voltry_mac_test_pdf_goldens", "pdf_goldens.py"),
    ("voltry_mac_test_pdf_pages", "pdf_pages.py"),
    ("voltry_mac_test_write_spy", "write_spy.py"),
    ("voltry_mac_test_fake_mac", "fake_mac.py"),
    ("voltry_mac_test_copy_golden", "copy_golden.py"),
    ("voltry_mac_test_character_table", "character_table.py"),
):
    if _name not in sys.modules:
        _spec = importlib.util.spec_from_file_location(
            _name, Path(__file__).resolve().parent / _file
        )
        assert _spec is not None and _spec.loader is not None
        _module = importlib.util.module_from_spec(_spec)
        sys.modules[_name] = _module
        _spec.loader.exec_module(_module)

sys.modules["voltry_mac_test_write_spy"].install()


@pytest.fixture(autouse=True)
def _one_writer():  # type: ignore[no-untyped-def]
    """No test may see package code other than the writer write a file, nor begin after
    one did (the #354 review, rounds 3 and 4: the runtime half of the write scan)."""
    spy = sys.modules["voltry_mac_test_write_spy"]
    spy.check("before this test began, at import or from an earlier test's thread")
    yield
    spy.check("while this test ran")


@pytest.fixture(autouse=True, scope="session")
def _one_writer_to_the_end():  # type: ignore[no-untyped-def]
    """Nor after the last test (the #354 review, round 4)."""
    yield
    sys.modules["voltry_mac_test_write_spy"].check("after the last test")


@pytest.fixture(autouse=True)
def _signals():  # type: ignore[no-untyped-def]
    """SIGINT, SIGTERM and SIGHUP as Python sets them when it starts from a terminal, and
    back as they were after. The run keeps a signal that was ignored when it started (the
    run's review, round 1, n8), and a test run started in the background by a script
    inherits SIGINT ignored, so no test may depend on how pytest itself was started."""
    signals = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
    before = {signum: signal.getsignal(signum) for signum in signals}
    signal.signal(signal.SIGINT, signal.default_int_handler)
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    signal.signal(signal.SIGHUP, signal.SIG_DFL)
    yield
    for signum, handler in before.items():
        if handler is not None:  # None: set outside Python, which cannot take it back
            signal.signal(signum, handler)
