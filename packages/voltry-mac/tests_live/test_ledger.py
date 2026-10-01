"""The ledger fixtures on the macOS runner (docs/VOLTRY_MAC_SPEC.md, Test strategy part 1,
its ledger fixtures bullet; board item MAC 4.1, issue #323).

S3 reads Apple's memory-error store with /usr/bin/sqlite3, -readonly and the readonly_shm=1
URI parameter, inside the no-write sandbox profile. Here the runner's own sqlite3 reads
real SQLite files in the test's temporary folder with S3's flags and query, in the
bullet's five states, each with and without the profile, as the runner user and without
sudo. The results must be the 2026-09-24 ones: the first two read every committed row,
the rest fail closed, and no file is ever made or changed beside the store.

1. A rollback-journal store.
2. A WAL store held open by a writer, every row still in the -wal.
3. A WAL store at rest: every connection closed, so no -wal or -shm is left.
4. A WAL store with a missing -shm: the -wal a writer left, in a folder closed to writes.
5. A store whose folder is writable: the fourth in a folder its reader can write, as the
   real store's folder is its owner's (drwxr-x---). It is the one state where a plain
   read-only open makes the -shm; a control shows that it does, so the state is the
   hazard, and that under the profile the same open fails closed with nothing made
   (Decision 2).

These run sandbox-exec, so they sit behind the live tests' gate (conftest.py), and run in
the live job alone.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import re
import shutil
import sqlite3
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest
import voltry_mac_live as live

STORE = "memory_errors.db"
SCHEMA = "CREATE TABLE ecc_errors_v2 (ID INTEGER PRIMARY KEY, correctable INTEGER, count INTEGER)"
INSERT = "INSERT INTO ecc_errors_v2 (correctable, count) VALUES (?, ?)"
ROWS = ((1, 3), (1, 4), (1, 5), (0, 1), (0, 2))
# What the aggregate query gives for ROWS: every committed row counted.
READ = [
    {"class": "correctable", "event_rows": 3, "reported_count": 12},
    {"class": "uncorrectable", "event_rows": 2, "reported_count": 3},
]
ROLLBACK = "1 rollback-journal"
HELD_OPEN = "2 WAL held open by a writer"
AT_REST = "3 WAL at rest"
MISSING_SHM = "4 WAL with a missing -shm"
WRITABLE = "5 a store whose folder is writable"
STATES = (ROLLBACK, HELD_OPEN, AT_REST, MISSING_SHM, WRITABLE)
PROFILES = pytest.mark.parametrize("profile", [False, True], ids=["bare", "in the profile"])


def _writer(folder: Path, journal: str) -> sqlite3.Connection:
    """A connection that made the store in ``folder`` and committed ROWS in ``journal`` mode.
    With autocheckpoint off, WAL mode keeps every row in the -wal until the last
    connection closes."""
    connection = sqlite3.connect(folder / STORE, isolation_level=None)
    try:
        connection.execute(f"PRAGMA journal_mode={journal}")
        connection.execute("PRAGMA wal_autocheckpoint=0")
        connection.execute(SCHEMA)
        connection.executemany(INSERT, ROWS)
    except BaseException:
        connection.close()
        raise
    return connection


@contextlib.contextmanager
def _store(state: str, root: Path) -> Iterator[Path]:
    """The store in ``state``, in a folder of its own under ``root`` that its reader owns."""
    folder = root / "store"
    folder.mkdir()
    folder.chmod(0o750)
    with contextlib.ExitStack() as stack:
        if state == ROLLBACK:
            _writer(folder, "DELETE").close()
        elif state == HELD_OPEN:
            stack.enter_context(contextlib.closing(_writer(folder, "WAL")))
        elif state == AT_REST:
            _writer(folder, "WAL").close()
        else:  # the store and its -wal as a writer left them, with no -shm
            source = root / "writer"
            source.mkdir()
            with contextlib.closing(_writer(source, "WAL")):
                for name in (STORE, f"{STORE}-wal"):
                    shutil.copyfile(source / name, folder / name)
        if state == MISSING_SHM:
            folder.chmod(0o550)
            stack.callback(folder.chmod, 0o750)
        yield folder / STORE


def _read(
    store: Path, *, profile: bool, readonly_shm: bool = True
) -> subprocess.CompletedProcess[str]:
    """S3's sqlite3, flags and query, on ``store``: inside the profile, or bare."""
    assert re.fullmatch(r"[A-Za-z0-9/._-]+", str(store)), "expected a path a URI names as it is"
    uri = f"file:{store}?readonly_shm=1" if readonly_shm else f"file:{store}"
    argv = [*live.SQLITE3, uri, live.LEDGER_QUERY]
    if profile:
        argv = ["/usr/bin/sandbox-exec", "-p", live.PROFILE, *argv]
    return subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        errors="replace",
        env=live.ENVIRONMENT,
        timeout=60,
    )


def _files(folder: Path) -> dict[str, str]:
    """Each name beside the store, with the SHA-256 of its bytes."""
    return {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in folder.iterdir()}


def _rows(printed: str) -> object:
    try:
        return json.loads(printed) if printed.strip() else None
    except json.JSONDecodeError:
        return "not JSON"


@PROFILES
@pytest.mark.parametrize("state", STATES)
def test_the_ledger_read_reads_or_fails_closed_and_makes_nothing(tmp_path, state, profile):
    """The bullet's assertions, state by state, in the profile and bare: the first two read
    every committed row, the rest fail closed with nothing read, and no name beside the
    store is made, and no byte of one changed."""
    with _store(state, tmp_path.resolve()) as store:
        before = _files(store.parent)
        read = _read(store, profile=profile)
        after = _files(store.parent)
    rows = _rows(read.stdout)
    made = sorted(set(after) - set(before))
    changed = sorted(name for name in before if after.get(name, before[name]) != before[name])
    print(
        f"{state}, {'in the profile' if profile else 'bare'}: exit {read.returncode}, "
        f"{len(rows) if isinstance(rows, list) else rows} class rows, {len(made)} names "
        f"made, {len(changed)} changed"
    )
    if state in (ROLLBACK, HELD_OPEN):
        assert (read.returncode, rows) == (0, READ), "expected every committed row read"
    else:
        assert read.returncode != 0, "expected the read to fail closed"
        assert read.stdout == "", "expected nothing read"
    assert after == before, "expected no file made or changed beside the store"


@PROFILES
def test_the_fifth_state_is_where_a_plain_read_only_open_makes_the_shm(tmp_path, profile):
    """The control: the same open without readonly_shm=1. Bare, it reads and makes the -shm
    in the writable folder, so the fifth state is the hazard; in the profile it fails
    closed with nothing made."""
    with _store(WRITABLE, tmp_path.resolve()) as store:
        before = _files(store.parent)
        read = _read(store, profile=profile, readonly_shm=False)
        after = _files(store.parent)
    rows = _rows(read.stdout)
    made = sorted(set(after) - set(before))
    print(
        f"a plain read-only open, {'in the profile' if profile else 'bare'}: exit "
        f"{read.returncode}, names made {made}"
    )
    if profile:
        assert read.returncode != 0 and read.stdout == "", "expected it to fail closed"
        assert after == before, "expected nothing made or changed in the profile"
    else:
        assert (read.returncode, rows) == (0, READ), "expected the bare open to read"
        assert made == [f"{STORE}-shm"], "expected the bare open to make the -shm"
