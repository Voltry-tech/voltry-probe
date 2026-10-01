"""The output writer (docs/VOLTRY_MAC_SPEC.md, Decision 5, the Architecture's output writer
row, Failure modes, the Threat model's partial files, and transcripts 4 and 5).

The only component that creates application output files. It picks the first base name
free for both the PDF and the JSON, `Voltry Mac Report 2026-09-23 14.05` from the report's
local time with a suffix `(2)` to `(99)` when the name is taken, and publishes one file at
a time, the JSON first when asked for and the PDF last: a same-directory temporary created
with O_CREAT, O_EXCL and O_NOFOLLOW and set to mode 0600 whatever the umask, written,
flushed to disk, hard-linked to its final name, which fails if the name is taken, and
unlinked. No temporary is made while one of this run's is still there, so at most one
exists at any moment. A hard kill leaves at most it and a JSON without its PDF, besides a
file an earlier refused removal left (change record 21). It removes this run's JSON if its
PDF cannot be published; checks each file's owner; falls back to the top of the home
folder when macOS refuses the default Desktop; opens an explicit folder exactly as given
and never relocates it; names every file by the folder it actually opened; and never
overwrites or follows a symlink at a name it creates. It holds each file open until the
save ends and removes a name only while the name still leads to that file, or, for a name
its link made when another file had taken the temporary's place, while that name and the
temporary's still lead to one file. Each check comes just before its unlink, so a process
that moves its own file onto the name between the two can lose it. A failure, or a
cancellation through the run's flag, raises NotSaved or Cancelled naming any file of this
run it could not remove, and a failure met by a cancellation is Cancelled. An error that
is not the file system's is raised as it is after the same cleanup, and a
KeyboardInterrupt raised anywhere else is cleaned up as far as it can be. The home folder
comes from the account database, not $HOME. The guard that only the writer writes is in
test_static_guards.py.
"""

from __future__ import annotations

import ast
import errno
import fcntl
import os
import signal
import stat
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from voltry_mac import writer

LOCAL = "2026-09-23T14:05:31-07:00"
BASE = "Voltry Mac Report 2026-09-23 14.05"
PDF = b"%PDF-1.4\n% a report\n"
JSON = b'{"schema":"voltry-mac-report/0"}\n'


def never() -> bool:
    return False


def save(folder: Path | None, *, json: bytes | None = None, **options):
    options.setdefault("cancelled", never)
    return writer.save(
        PDF, json, local=LOCAL, folder=None if folder is None else str(folder), **options
    )


def names(folder: Path) -> list[str]:
    return sorted(os.listdir(folder))


def temporaries(folder: Path) -> list[str]:
    return [name for name in names(folder) if name.endswith(".tmp")]


@pytest.fixture
def home(tmp_path, monkeypatch):
    """A home folder with a Desktop, named by the account database's stand-in."""
    root = tmp_path / "home"
    (root / "Desktop").mkdir(parents=True)
    monkeypatch.setattr(writer, "home", lambda: str(root))
    return root


def _refusing(monkeypatch, seam: str, when) -> None:
    """Make one file system seam raise EPERM whenever ``when(args)`` holds."""
    real = getattr(writer, seam)

    def refused(*args):
        if when(*args):
            raise PermissionError(errno.EPERM, os.strerror(errno.EPERM))
        return real(*args)

    monkeypatch.setattr(writer, seam, refused)


def _in(folder: Path):
    """Whether a seam's first argument, a folder descriptor, is ``folder``."""
    return lambda folder_fd, *rest: os.path.samestat(os.fstat(folder_fd), os.stat(folder))


# --- names ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("local", "base"),
    [
        ("2026-09-23T14:05:31-07:00", "Voltry Mac Report 2026-09-23 14.05"),
        ("2026-01-02T03:04:59+05:30", "Voltry Mac Report 2026-01-02 03.04"),
        ("2027-12-31T23:59:59+00:00", "Voltry Mac Report 2027-12-31 23.59"),
    ],
)
def test_the_base_name_is_the_local_time_with_a_period_not_a_colon(local, base):
    assert writer.base_name(local) == base


@pytest.mark.parametrize(
    "local",
    ["2026-09-23T14:05:31", "2026-09-23T14:05:31Z", "2026-09-23/14:05:31-07:00", "", "../x"],
)
def test_a_local_time_not_in_the_reports_shape_names_nothing(local):
    with pytest.raises(ValueError):
        writer.base_name(local)


def test_the_home_folder_comes_from_the_account_database_not_home(monkeypatch):
    import pwd

    monkeypatch.setenv("HOME", "/somewhere/else")
    assert writer.home() == pwd.getpwuid(os.getuid()).pw_dir


def test_an_account_with_no_home_folder_saves_nothing(monkeypatch):
    def missing(uid):
        raise KeyError(uid)

    monkeypatch.setattr(writer.pwd, "getpwuid", missing)
    with pytest.raises(writer.NotSaved):
        writer.home()


def test_a_home_folder_that_is_not_an_absolute_path_saves_nothing(monkeypatch):
    class Entry:
        pw_dir = "relative/home"

    monkeypatch.setattr(writer.pwd, "getpwuid", lambda uid: Entry())
    with pytest.raises(writer.NotSaved):
        writer.home()


# --- the default location -------------------------------------------------------------------


def test_the_pdf_goes_to_the_desktop_by_default(home):
    saved = save(None)
    assert saved.pdf == f"{home}/Desktop/{BASE}.pdf"
    assert saved.json is None and not saved.fallback and not saved.renamed
    assert saved.left == ()
    assert Path(saved.pdf).read_bytes() == PDF
    assert names(home / "Desktop") == [f"{BASE}.pdf"]


def test_the_json_shares_the_base_name_and_is_published_first(home, monkeypatch):
    order = []
    real = writer._publish

    def publish(folder_fd, temporary, final):
        order.append(final)
        return real(folder_fd, temporary, final)

    monkeypatch.setattr(writer, "_publish", publish)
    saved = save(None, json=JSON)
    assert order == [f"{BASE}.json", f"{BASE}.pdf"]
    assert saved.json == f"{home}/Desktop/{BASE}.json"
    assert Path(saved.json).read_bytes() == JSON
    assert names(home / "Desktop") == [f"{BASE}.json", f"{BASE}.pdf"]


def test_the_files_are_the_users_mode_0600_one_name_each(home):
    saved = save(None, json=JSON)
    for path in (saved.pdf, saved.json):
        info = os.lstat(path)
        assert stat.S_ISREG(info.st_mode)
        assert stat.S_IMODE(info.st_mode) == 0o600
        assert info.st_uid == os.getuid() and info.st_nlink == 1


@pytest.mark.parametrize("mask", [0o277, 0o477, 0o777, 0o000])
def test_the_mode_is_0600_whatever_the_umask(home, mask):
    before = os.umask(mask)
    try:
        saved = save(None, json=JSON)
    finally:
        os.umask(before)
    for path in (saved.pdf, saved.json):
        assert stat.S_IMODE(os.lstat(path).st_mode) == 0o600, oct(mask)


def test_no_temporary_is_left(home):
    save(None, json=JSON)
    assert temporaries(home / "Desktop") == []


def test_the_desktop_prompt_is_announced_before_the_first_write(home, monkeypatch):
    events = []
    real_open, real_create = writer._open_folder, writer._create

    def open_folder(path):
        events.append("open")
        return real_open(path)

    def create(folder_fd, name):
        events.append("create")
        return real_create(folder_fd, name)

    monkeypatch.setattr(writer, "_open_folder", open_folder)
    monkeypatch.setattr(writer, "_create", create)
    save(None, before_desktop=lambda: events.append("announce"))
    assert events[:2] == ["announce", "open"] and "create" in events


def test_an_explicit_folder_is_not_announced(home, tmp_path):
    folder = tmp_path / "reports"
    folder.mkdir()
    announced = []
    save(folder, before_desktop=lambda: announced.append(True))
    assert announced == []


def test_a_cancelled_run_announces_nothing_and_opens_no_folder(home, monkeypatch):
    events = []
    monkeypatch.setattr(writer, "_open_folder", lambda path: events.append("open"))
    with pytest.raises(writer.Cancelled):
        save(None, cancelled=lambda: True, before_desktop=lambda: events.append("announce"))
    assert events == []


# --- one file at a time -----------------------------------------------------------------------


def test_at_most_one_temporary_exists_at_any_moment(home, monkeypatch):
    desktop = home / "Desktop"
    seen = []
    for seam in ("_create", "_write_all", "_sync", "_publish", "_unlink"):
        real = getattr(writer, seam)

        def spy(*args, real=real):
            seen.append(len(temporaries(desktop)))
            result = real(*args)
            seen.append(len(temporaries(desktop)))
            return result

        monkeypatch.setattr(writer, seam, spy)
    save(None, json=JSON)
    assert seen and max(seen) == 1


def test_each_file_is_flushed_before_its_link_and_its_temporary_goes_right_after(home, monkeypatch):
    events = []
    for seam in ("_create", "_sync", "_publish", "_unlink"):
        real = getattr(writer, seam)

        def spy(*args, real=real, seam=seam):
            name = args[2] if seam == "_publish" else ""
            events.append(f"{seam}{' ' + name if name else ''}")
            return real(*args)

        monkeypatch.setattr(writer, seam, spy)
    save(None, json=JSON)
    assert events == [
        "_create",
        "_sync",
        f"_publish {BASE}.json",
        "_unlink",
        "_create",
        "_sync",
        f"_publish {BASE}.pdf",
        "_unlink",
        "_sync",  # the folder, once both names exist
    ]


# A child that kills itself with SIGKILL at the Nth cancellation check: 1 before anything,
# 2 once the JSON is published, 3 once the PDF's temporary is written.
_KILLED = """
import os, signal, sys
from voltry_mac import writer
folder, step = sys.argv[1], sys.argv[2]
base = "Voltry Mac Report 2026-09-23 14.05"
def reached():
    names = os.listdir(folder)
    json, pdf = f"{base}.json" in names, f"{base}.pdf" in names
    temporary = any(name.endswith(".tmp") for name in names)
    return {
        "before anything": True,
        "once the JSON is published": json and not temporary,
        "once the PDF's temporary is written": json and temporary,
        "once the PDF is published": pdf,
    }[step]
def cancelled():
    if reached():
        os.kill(os.getpid(), signal.SIGKILL)
    return False
writer.save(b"%PDF", b"{}", local="2026-09-23T14:05:31-07:00", folder=folder, cancelled=cancelled)
"""


# A kill at the first cancellation check each step reaches, told by what is in the folder
# (the #354 review, round 3), and what it leaves.
@pytest.mark.parametrize(
    ("step", "left"),
    [
        ("before anything", []),
        ("once the JSON is published", [f"{BASE}.json"]),  # the JSON alone
        ("once the PDF's temporary is written", [f"{BASE}.json", "one temporary"]),
        ("once the PDF is published", [f"{BASE}.json", f"{BASE}.pdf"]),  # the whole report
    ],
)
def test_a_hard_kill_leaves_at_most_one_temporary_and_a_json_without_its_pdf(tmp_path, step, left):
    folder = tmp_path / "reports"
    folder.mkdir()
    killed = subprocess.run(
        [sys.executable, "-c", _KILLED, str(folder), step], timeout=60, check=False
    )
    assert killed.returncode == -signal.SIGKILL
    found = [name if not name.endswith(".tmp") else "one temporary" for name in names(folder)]
    assert sorted(found) == sorted(left)


# --- a taken name ---------------------------------------------------------------------------


def test_a_taken_name_takes_the_next_suffix_and_touches_nothing(home):
    desktop = home / "Desktop"
    (desktop / f"{BASE}.pdf").write_bytes(b"theirs")
    saved = save(None)
    assert saved.pdf == f"{desktop}/{BASE} (2).pdf" and saved.renamed
    assert (desktop / f"{BASE}.pdf").read_bytes() == b"theirs"


@pytest.mark.parametrize("json", [None, JSON], ids=["the PDF alone", "with the JSON"])
def test_a_name_is_free_only_when_both_files_are(home, json):
    desktop = home / "Desktop"
    (desktop / f"{BASE}.json").write_bytes(b"theirs")
    saved = save(None, json=json)
    assert saved.pdf == f"{desktop}/{BASE} (2).pdf"
    assert (desktop / f"{BASE}.json").read_bytes() == b"theirs"
    if json is not None:
        assert saved.json == f"{desktop}/{BASE} (2).json"


def test_a_symlink_takes_its_name_and_is_never_followed(home, tmp_path):
    desktop = home / "Desktop"
    target = tmp_path / "elsewhere.pdf"
    target.write_bytes(b"theirs")
    (desktop / f"{BASE}.pdf").symlink_to(target)
    (desktop / f"{BASE} (2).pdf").symlink_to(tmp_path / "dangling.pdf")
    saved = save(None)
    assert saved.pdf == f"{desktop}/{BASE} (3).pdf"
    assert target.read_bytes() == b"theirs"
    assert not (tmp_path / "dangling.pdf").exists()


def test_the_ninety_ninth_name_is_the_last(home):
    desktop = home / "Desktop"
    (desktop / f"{BASE}.pdf").write_bytes(b"x")
    for number in range(2, 99):
        (desktop / f"{BASE} ({number}).pdf").write_bytes(b"x")
    assert save(None).pdf == f"{desktop}/{BASE} (99).pdf"
    with pytest.raises(writer.NotSaved, match="99"):
        save(None)


def test_a_name_taken_between_the_check_and_the_publish_moves_both_files_on(home, monkeypatch):
    desktop = home / "Desktop"
    real = writer._publish
    raced = []

    def publish(folder_fd, temporary, final):
        if final == f"{BASE}.pdf" and not raced:
            raced.append(True)
            (desktop / final).write_bytes(b"theirs")  # another process wins the name
        return real(folder_fd, temporary, final)

    monkeypatch.setattr(writer, "_publish", publish)
    saved = save(None, json=JSON)
    assert (saved.json, saved.pdf) == (f"{desktop}/{BASE} (2).json", f"{desktop}/{BASE} (2).pdf")
    assert (desktop / f"{BASE}.pdf").read_bytes() == b"theirs"
    assert not (desktop / f"{BASE}.json").exists(), "this run's first JSON is removed"
    assert names(desktop) == [f"{BASE} (2).json", f"{BASE} (2).pdf", f"{BASE}.pdf"]


def test_a_json_name_taken_before_its_publish_moves_both_files_on(home, monkeypatch):
    desktop = home / "Desktop"
    real = writer._publish
    raced = []

    def publish(folder_fd, temporary, final):
        if final == f"{BASE}.json" and not raced:
            raced.append(True)
            (desktop / final).write_bytes(b"theirs")
        return real(folder_fd, temporary, final)

    monkeypatch.setattr(writer, "_publish", publish)
    saved = save(None, json=JSON)
    assert saved.json == f"{desktop}/{BASE} (2).json"
    assert (desktop / f"{BASE}.json").read_bytes() == b"theirs"
    assert temporaries(desktop) == []


def test_a_temporary_name_already_there_is_never_opened(home, monkeypatch, tmp_path):
    desktop = home / "Desktop"
    tokens = iter(["aaaa", "bbbb"])
    monkeypatch.setattr(writer, "_token", lambda: next(tokens))
    target = tmp_path / "victim"
    target.write_bytes(b"theirs")
    (desktop / ".voltry-mac-aaaa.tmp").symlink_to(target)
    saved = save(None)
    assert target.read_bytes() == b"theirs"
    assert Path(saved.pdf).read_bytes() == PDF
    assert (desktop / ".voltry-mac-aaaa.tmp").is_symlink(), "not this run's: left alone"


def test_the_temporaries_are_created_exclusively_without_following_a_link(home, monkeypatch):
    flags = []
    real = os.open

    def spy(path, flag, *args, **kwargs):
        if str(path).startswith(".voltry-mac-"):
            flags.append(flag)
        return real(path, flag, *args, **kwargs)

    monkeypatch.setattr(os, "open", spy)
    save(None, json=JSON)
    assert len(flags) == 2
    for flag in flags:
        assert flag & os.O_CREAT and flag & os.O_EXCL and flag & os.O_NOFOLLOW
        assert flag & os.O_WRONLY and not flag & os.O_TRUNC


# --- the privacy fallback and an explicit folder --------------------------------------------


def test_a_refused_desktop_saves_at_the_top_of_the_home_folder(home, monkeypatch):
    _refusing(monkeypatch, "_create", _in(home / "Desktop"))
    saved = save(None, json=JSON)
    assert saved.fallback
    assert (saved.json, saved.pdf) == (f"{home}/{BASE}.json", f"{home}/{BASE}.pdf")
    assert names(home / "Desktop") == []


def test_only_operation_not_permitted_falls_back(home, monkeypatch):
    real = writer._create
    desktop = home / "Desktop"

    def create(folder_fd, name):
        if _in(desktop)(folder_fd):
            raise PermissionError(errno.EACCES, os.strerror(errno.EACCES))
        return real(folder_fd, name)

    monkeypatch.setattr(writer, "_create", create)
    with pytest.raises(writer.NotSaved):
        save(None)
    assert not [name for name in names(home) if name.endswith(".pdf")]


def test_an_explicit_folder_is_used_as_given(home, tmp_path):
    folder = tmp_path / "reports"
    folder.mkdir()
    saved = save(folder)
    assert saved.pdf == f"{folder}/{BASE}.pdf" and not saved.fallback


def test_a_relative_folder_is_made_absolute_and_normal(home, tmp_path, monkeypatch):
    (tmp_path / "reports").mkdir()
    monkeypatch.chdir(tmp_path)
    saved = writer.save(PDF, None, local=LOCAL, folder="./reports/../reports", cancelled=never)
    assert saved.pdf == os.path.join(os.getcwd(), "reports", f"{BASE}.pdf")
    assert os.path.normpath(saved.pdf) == saved.pdf and os.path.isabs(saved.pdf)


@pytest.mark.parametrize("folder", ["", "missing/..", "afile/.."])
def test_an_explicit_folder_is_opened_exactly_as_given(home, tmp_path, monkeypatch, folder):
    # The kernel resolves the path, not text: missing/.. and afile/.. name nothing.
    monkeypatch.chdir(tmp_path)
    (tmp_path / "afile").write_bytes(b"x")
    with pytest.raises(writer.NotSaved) as refused:
        writer.save(PDF, None, local=LOCAL, folder=folder, cancelled=never)
    assert refused.value.folder == folder
    assert not [name for name in names(tmp_path) if name.endswith((".pdf", ".tmp"))]


@pytest.mark.skipif(
    not hasattr(fcntl, "F_GETPATH") and not os.path.isdir("/proc/self/fd"),
    reason="needs the path the system keeps for an open folder",
)
def test_a_folder_reached_through_a_link_and_dot_dot_is_named_where_it_is(
    home, tmp_path, monkeypatch
):
    elsewhere = tmp_path / "elsewhere"
    (elsewhere / "inner").mkdir(parents=True)
    (tmp_path / "link").symlink_to(elsewhere / "inner")
    monkeypatch.chdir(tmp_path)
    saved = writer.save(PDF, None, local=LOCAL, folder="link/..", cancelled=never)
    assert (elsewhere / f"{BASE}.pdf").read_bytes() == PDF
    assert os.path.samefile(saved.pdf, elsewhere / f"{BASE}.pdf")
    assert os.path.normpath(saved.pdf) == saved.pdf
    assert not (tmp_path / f"{BASE}.pdf").exists()


def test_a_folder_it_cannot_name_takes_no_report(home, tmp_path, monkeypatch):
    elsewhere = tmp_path / "elsewhere"
    (elsewhere / "inner").mkdir(parents=True)
    (tmp_path / "link").symlink_to(elsewhere / "inner")
    monkeypatch.chdir(tmp_path)

    def unnamed(folder_fd):
        raise OSError(errno.EINVAL, os.strerror(errno.EINVAL))

    monkeypatch.setattr(writer, "_kernel_path", unnamed)
    with pytest.raises(writer.NotSaved) as refused:
        writer.save(PDF, None, local=LOCAL, folder="link/..", cancelled=never)
    assert refused.value.folder == "link/.."
    assert names(elsewhere) == ["inner"] and not (tmp_path / f"{BASE}.pdf").exists()


def test_a_folder_given_with_a_leading_double_slash_is_named_in_normal_form(home, tmp_path):
    folder = tmp_path / "reports"
    folder.mkdir()
    saved = writer.save(PDF, None, local=LOCAL, folder=f"/{folder}", cancelled=never)
    assert not saved.pdf.startswith("//") and os.path.normpath(saved.pdf) == saved.pdf
    assert os.path.samefile(saved.pdf, folder / f"{BASE}.pdf")


def test_a_folder_whose_path_leaves_no_room_for_the_name_takes_no_report(home, tmp_path):
    # PATH_MAX counts the NUL: a folder path of 1,000 bytes opens, and the report's paths
    # would pass the limit, so nothing is written.
    folder = tmp_path
    while len(os.fsencode(str(folder))) < 1000 - 60:
        folder = folder / ("d" * 50)
    folder = folder / ("e" * (1000 - len(os.fsencode(str(folder))) - 1))
    folder.mkdir(parents=True)
    assert len(os.fsencode(str(folder))) == 1000
    with pytest.raises(writer.NotSaved, match="too long"):
        save(folder)
    assert names(folder) == []


@pytest.mark.parametrize("kind", ["missing", "a file", "not writable"])
def test_an_explicit_folder_that_cannot_take_the_report_is_never_relocated(home, tmp_path, kind):
    folder = tmp_path / "reports"
    if kind == "a file":
        folder.write_bytes(b"x")
    elif kind == "not writable":
        folder.mkdir()
        folder.chmod(0o500)
    try:
        with pytest.raises(writer.NotSaved) as refused:
            save(folder)
    finally:
        if kind == "not writable":
            folder.chmod(0o700)
    assert refused.value.folder == str(folder)
    assert names(home / "Desktop") == [] and not [n for n in names(home) if n.endswith(".pdf")]


def test_a_fifo_given_as_the_folder_is_refused_without_blocking(home, tmp_path):
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    outcome = []

    def attempt() -> None:
        try:
            save(fifo)
        except writer.NotSaved as refused:
            outcome.append(refused)

    worker = threading.Thread(target=attempt, daemon=True)
    worker.start()
    worker.join(10)
    assert not worker.is_alive(), "the open blocked on a FIFO"
    assert outcome and outcome[0].folder == str(fifo)


def test_an_explicit_folder_refused_by_macos_is_never_relocated(home, monkeypatch, tmp_path):
    folder = tmp_path / "reports"
    folder.mkdir()

    def create(folder_fd, name):
        raise OSError(errno.EPERM, os.strerror(errno.EPERM))

    monkeypatch.setattr(writer, "_create", create)
    with pytest.raises(writer.NotSaved) as refused:
        save(folder)
    assert refused.value.folder == str(folder)
    assert names(home) == ["Desktop"] and names(home / "Desktop") == []


def test_not_saved_names_the_folder_as_given_for_every_reason(home, tmp_path, monkeypatch):
    folder = tmp_path / "reports"
    folder.mkdir()
    monkeypatch.chdir(tmp_path)
    for number in range(1, 100):
        stem = BASE if number == 1 else f"{BASE} ({number})"
        (folder / f"{stem}.pdf").write_bytes(b"x")
    with pytest.raises(writer.NotSaved) as every_name:
        writer.save(PDF, None, local=LOCAL, folder="reports", cancelled=never)
    assert every_name.value.folder == "reports"
    (folder / f"{BASE}.pdf").unlink()
    monkeypatch.setattr(writer, "_uid", lambda: os.getuid() + 1)
    with pytest.raises(writer.NotSaved) as owner:
        writer.save(PDF, None, local=LOCAL, folder="reports", cancelled=never)
    assert owner.value.folder == "reports"


def test_a_disk_without_hard_links_is_named_plainly(home, monkeypatch):
    def publish(folder_fd, temporary, final):
        raise OSError(errno.ENOTSUP, os.strerror(errno.ENOTSUP))

    monkeypatch.setattr(writer, "_publish", publish)
    with pytest.raises(writer.NotSaved, match="hard links"):
        save(None, json=JSON)
    assert names(home / "Desktop") == []


# --- failures and cancellation --------------------------------------------------------------


def test_a_pdf_that_cannot_be_published_takes_this_runs_json_with_it(home, monkeypatch):
    real = writer._publish

    def publish(folder_fd, temporary, final):
        if final.endswith(".pdf"):
            raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))
        return real(folder_fd, temporary, final)

    monkeypatch.setattr(writer, "_publish", publish)
    with pytest.raises(writer.NotSaved, match="No space left"):
        save(None, json=JSON)
    assert names(home / "Desktop") == []


def test_a_write_that_fails_leaves_no_temporary(home, monkeypatch):
    def write_all(descriptor, data):
        raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))

    monkeypatch.setattr(writer, "_write_all", write_all)
    with pytest.raises(writer.NotSaved):
        save(None, json=JSON)
    assert names(home / "Desktop") == []


def test_a_file_that_is_not_the_users_is_deleted_and_not_saved(home, monkeypatch):
    monkeypatch.setattr(writer, "_uid", lambda: os.getuid() + 1)
    with pytest.raises(writer.NotSaved, match="owner"):
        save(None, json=JSON)
    assert names(home / "Desktop") == []


def test_as_root_nothing_is_created(home, monkeypatch):
    # The preflight refuses root first; this catches a regression past it.
    created = []
    monkeypatch.setattr(writer, "_uid", lambda: 0)
    monkeypatch.setattr(writer, "_create", lambda *args: created.append(args))
    with pytest.raises(writer.NotSaved, match="root"):
        save(None)
    assert created == [] and names(home / "Desktop") == []


# The steps a cancellation can meet, told by what is on the Desktop when the flag is read,
# never by how often it was read (the #354 review, round 3, m-1).
STEPS = {
    "before anything": lambda desktop: True,
    "once the JSON is published": lambda desktop: (desktop / f"{BASE}.json").exists(),
    "once the PDF's temporary is written": lambda desktop: (
        (desktop / f"{BASE}.json").exists() and bool(temporaries(desktop))
    ),
    # A signal just before the PDF's link sets the flag as the link is made: the writer
    # still reads the flag once more before the save is done (the GPT audit, G1-09).
    "once the PDF is published": lambda desktop: (desktop / f"{BASE}.pdf").exists(),
}


@pytest.mark.parametrize("step", list(STEPS))
def test_a_cancellation_at_any_step_leaves_nothing_of_this_run(home, step):
    desktop = home / "Desktop"
    reached: list[bool] = []

    def cancelled() -> bool:
        if STEPS[step](desktop):
            reached.append(True)
            return True
        return False

    with pytest.raises(writer.Cancelled) as stopped:
        save(None, json=JSON, cancelled=cancelled)
    assert reached, "the step was reached"
    assert names(desktop) == [] and stopped.value.left == ()


def test_a_signal_just_before_the_pdfs_link_undoes_the_whole_save(home, monkeypatch):
    # The flag turns true between the last check before the link and the link itself: the
    # PDF is published, then removed with the JSON (the GPT audit, G1-09).
    flag: list[bool] = []
    real = writer._publish

    def publish(folder_fd, temporary, final):  # type: ignore[no-untyped-def]
        if final.endswith(".pdf"):
            flag.append(True)
        return real(folder_fd, temporary, final)

    monkeypatch.setattr(writer, "_publish", publish)
    with pytest.raises(writer.Cancelled) as stopped:
        save(None, json=JSON, cancelled=lambda: bool(flag))
    assert names(home / "Desktop") == [] and stopped.value.left == ()


def test_a_cancellation_never_deletes_a_file_it_did_not_create(home):
    desktop = home / "Desktop"
    (desktop / f"{BASE}.pdf").write_bytes(b"theirs")
    with pytest.raises(writer.Cancelled):
        save(None, json=JSON, cancelled=lambda: True)
    assert names(desktop) == [f"{BASE}.pdf"]


def test_cleanup_never_removes_a_file_that_took_this_runs_name(home, tmp_path):
    # Another process moves its own file onto this run's published JSON, then the run is
    # cancelled: the name no longer leads to this run's file, so it stays.
    desktop = home / "Desktop"
    theirs = tmp_path / "theirs.json"
    theirs.write_bytes(b"theirs")

    def cancelled() -> bool:
        if (desktop / f"{BASE}.json").exists() and theirs.exists():  # this run's JSON is out
            os.replace(theirs, desktop / f"{BASE}.json")
            return True
        return False

    with pytest.raises(writer.Cancelled) as stopped:
        save(None, json=JSON, cancelled=cancelled)
    assert names(desktop) == [f"{BASE}.json"]
    assert (desktop / f"{BASE}.json").read_bytes() == b"theirs"
    assert stopped.value.left == ()  # not this run's, so not named as safe to delete


def test_a_ctrl_c_inside_the_save_is_a_cancellation_and_leaves_nothing(home):
    json = home / "Desktop" / f"{BASE}.json"

    def cancelled() -> bool:
        if json.exists():
            raise KeyboardInterrupt
        return False

    try:
        with pytest.raises(writer.Cancelled):
            save(None, json=JSON, cancelled=cancelled)
    except KeyboardInterrupt:  # escaping, it would stop the whole test run
        pytest.fail("the Ctrl-C left the save as it was")
    assert names(home / "Desktop") == []


def test_an_error_from_the_cancellation_check_is_raised_as_it_is_and_leaves_nothing(home):
    json = home / "Desktop" / f"{BASE}.json"

    def cancelled() -> bool:
        if json.exists():
            raise RuntimeError("the flag broke")
        return False

    with pytest.raises(RuntimeError, match="the flag broke"):
        save(None, json=JSON, cancelled=cancelled)
    assert names(home / "Desktop") == []


def test_a_bug_inside_the_save_is_raised_as_it_is_and_leaves_nothing(home):
    with pytest.raises(TypeError):
        writer.save("not bytes", JSON, local=LOCAL, folder=None, cancelled=never)  # type: ignore[arg-type]
    assert names(home / "Desktop") == []


def test_a_removal_that_fails_is_named_and_every_other_name_is_still_tried(home, monkeypatch):
    # Cancelled once the PDF's temporary is written: the JSON cannot be removed, and the
    # temporary still is.
    desktop = home / "Desktop"
    _refusing(monkeypatch, "_unlink", lambda folder_fd, name: name == f"{BASE}.json")

    def cancelled() -> bool:
        return STEPS["once the PDF's temporary is written"](desktop)

    with pytest.raises(writer.Cancelled) as stopped:
        save(None, json=JSON, cancelled=cancelled)
    assert stopped.value.left == (f"{desktop}/{BASE}.json",)
    assert names(desktop) == [f"{BASE}.json"]


def test_a_temporary_that_will_not_go_is_named_and_the_save_still_fails_plainly(home, monkeypatch):
    desktop = home / "Desktop"
    _refusing(monkeypatch, "_unlink", lambda folder_fd, name: name.endswith(".tmp"))

    def publish(folder_fd, temporary, final):
        raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))

    monkeypatch.setattr(writer, "_publish", publish)
    with pytest.raises(writer.NotSaved, match="No space left") as refused:
        save(None, json=JSON)
    (left,) = refused.value.left
    assert left.startswith(f"{desktop}/.voltry-mac-") and left.endswith(".tmp")


def test_a_json_temporary_that_will_not_go_stops_the_save_before_a_second_one(home, monkeypatch):
    # At most one temporary at any time: the PDF's is never made while the JSON's is still
    # there, so the save fails, its JSON goes, and the one temporary is named (the GPT
    # audit, G1-06).
    desktop = home / "Desktop"
    _refusing(monkeypatch, "_unlink", lambda folder_fd, name: name.endswith(".tmp"))
    most: list[int] = []
    real = writer._create
    monkeypatch.setattr(
        writer,
        "_create",
        lambda folder_fd, name: most.append(len(temporaries(desktop))) or real(folder_fd, name),
    )
    with pytest.raises(writer.NotSaved, match="temporary") as refused:
        save(None, json=JSON)
    (left,) = refused.value.left
    assert left.startswith(f"{desktop}/.voltry-mac-") and left.endswith(".tmp")
    assert names(desktop) == [os.path.basename(left)]
    assert most == [0], "no temporary was made while another was there"


def test_once_the_pdf_is_published_its_temporary_that_will_not_go_is_named(home, monkeypatch):
    # The last file: the report is saved, and its one temporary is named as safe to delete.
    desktop = home / "Desktop"
    _refusing(monkeypatch, "_unlink", lambda folder_fd, name: name.endswith(".tmp"))
    saved = save(None)
    assert Path(saved.pdf).read_bytes() == PDF
    (left,) = saved.left
    assert left.startswith(f"{desktop}/.voltry-mac-")


def test_a_desktop_that_keeps_a_temporary_does_not_move_the_save_home(home, monkeypatch):
    # macOS refuses the Desktop from the moment the JSON is published there, removals
    # included: its temporary cannot go, so the save stops there rather than make a second
    # temporary at home, and names what is left (the GPT audit, G1-06).
    desktop = home / "Desktop"
    refusing = []
    real = writer._publish

    def publish(folder_fd, temporary, final):
        real(folder_fd, temporary, final)
        if _in(desktop)(folder_fd):
            refusing.append(True)

    monkeypatch.setattr(writer, "_publish", publish)
    for seam in ("_create", "_unlink"):
        _refusing(monkeypatch, seam, lambda folder_fd, *rest: refusing and _in(desktop)(folder_fd))
    with pytest.raises(writer.NotSaved) as refused:
        save(None, json=JSON)
    assert names(home) == ["Desktop"], "nothing was made at home"
    assert sorted(refused.value.left) == sorted(f"{desktop}/{name}" for name in names(desktop))
    assert f"{desktop}/{BASE}.json" in refused.value.left and len(temporaries(desktop)) == 1


def test_the_folder_is_fixed_once_opened_and_named_where_it_went(home, monkeypatch, tmp_path):
    # A folder swapped for a symlink mid-run does not redirect the write, and the paths
    # returned name where the files are.
    desktop = home / "Desktop"
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    real = writer._create
    swapped = []

    def create(folder_fd, name):
        if not swapped:
            swapped.append(True)
            desktop.rename(home / "Desktop.old")
            desktop.symlink_to(elsewhere)
        return real(folder_fd, name)

    monkeypatch.setattr(writer, "_create", create)
    saved = save(None)
    assert names(elsewhere) == []
    assert names(home / "Desktop.old") == [f"{BASE}.pdf"]
    assert os.path.samefile(saved.pdf, home / "Desktop.old" / f"{BASE}.pdf")


def test_a_folder_that_will_not_close_does_not_undo_the_save(home, monkeypatch):
    real = writer._close_folder

    def close_folder(folder_fd):
        real(folder_fd)
        raise OSError(errno.EIO, os.strerror(errno.EIO))

    monkeypatch.setattr(writer, "_close_folder", close_folder)
    saved = save(None, json=JSON)
    assert Path(saved.pdf).read_bytes() == PDF


def test_every_descriptor_the_save_opens_is_closed(home, monkeypatch):
    def open_descriptors() -> int:
        return len(os.listdir("/dev/fd"))

    before = open_descriptors()
    save(None, json=JSON)
    with pytest.raises(writer.NotSaved):
        save(home / "missing", json=JSON)

    def publish(folder_fd, temporary, final):
        raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))

    monkeypatch.setattr(writer, "_publish", publish)
    with pytest.raises(writer.NotSaved):
        save(None, json=JSON)
    assert open_descriptors() == before


@pytest.mark.skipif(not hasattr(fcntl, "F_FULLFSYNC"), reason="F_FULLFSYNC is macOS's")
def test_each_file_and_the_folder_are_flushed_to_the_disk_not_only_its_cache(home, monkeypatch):
    full = []
    real = fcntl.fcntl

    def spy(descriptor, command, *args):
        if command == fcntl.F_FULLFSYNC:
            full.append(descriptor)
        return real(descriptor, command, *args)

    monkeypatch.setattr(fcntl, "fcntl", spy)
    save(None, json=JSON)
    assert len(full) == 3  # the JSON, the PDF and the folder


@pytest.mark.parametrize("code", [errno.ENOTSUP, errno.ENOTTY, errno.EINVAL])
def test_a_file_system_without_a_full_flush_falls_back_to_fsync(home, monkeypatch, code):
    synced = []
    real = os.fsync

    def fcntl_refused(descriptor, command, *args):
        raise OSError(code, os.strerror(code))

    monkeypatch.setattr(writer.fcntl, "F_FULLFSYNC", 51, raising=False)
    monkeypatch.setattr(writer.fcntl, "fcntl", fcntl_refused)
    monkeypatch.setattr(
        os, "fsync", lambda descriptor: synced.append(descriptor) or real(descriptor)
    )
    save(None, json=JSON)
    assert len(synced) >= 2


# --- every path out of the save -----------------------------------------------------------------


def test_a_desktop_macos_refuses_to_open_saves_at_the_top_of_the_home_folder(home, monkeypatch):
    real = writer._open_folder
    desktop = str(home / "Desktop")

    def open_folder(path: str) -> int:
        if path == desktop:
            raise PermissionError(errno.EPERM, os.strerror(errno.EPERM))
        return real(path)

    monkeypatch.setattr(writer, "_open_folder", open_folder)
    saved = save(None, json=JSON)
    assert saved.fallback
    assert (saved.json, saved.pdf) == (f"{home}/{BASE}.json", f"{home}/{BASE}.pdf")


def test_a_desktop_refusal_after_the_json_is_published_moves_the_whole_save_home(home, monkeypatch):
    real = writer._publish

    def publish(folder_fd: int, temporary: str, final: str) -> None:
        if final.endswith(".pdf") and _in(home / "Desktop")(folder_fd):
            raise PermissionError(errno.EPERM, os.strerror(errno.EPERM))
        real(folder_fd, temporary, final)

    monkeypatch.setattr(writer, "_publish", publish)
    saved = save(None, json=JSON)
    assert saved.fallback
    assert names(home / "Desktop") == [], "the JSON published there first is gone"
    assert Path(saved.json).read_bytes() == JSON and Path(saved.pdf).read_bytes() == PDF


def test_every_temporary_name_taken_leaves_the_report_unsaved(home, monkeypatch):
    desktop = home / "Desktop"
    monkeypatch.setattr(writer, "_token", lambda: "aaaa")
    (desktop / ".voltry-mac-aaaa.tmp").write_bytes(b"theirs")
    with pytest.raises(writer.NotSaved, match="no temporary name was free"):
        save(None)
    assert names(desktop) == [".voltry-mac-aaaa.tmp"]
    assert (desktop / ".voltry-mac-aaaa.tmp").read_bytes() == b"theirs"


# --- the remaining paths ---------------------------------------------------------------------


def test_a_temporary_whose_file_cannot_be_read_is_named_not_removed_unchecked(home, monkeypatch):
    # Nothing then shows that the name still leads to this run's file, so it is named in
    # ``left`` and never removed unchecked (the #354 review, round 4, m-3; until then it was
    # removed).
    created = []
    real_create, real_fstat = writer._create, os.fstat

    def create(folder_fd, name):
        descriptor = real_create(folder_fd, name)
        created.append(descriptor)
        return descriptor

    def fstat(descriptor):
        if descriptor in created:
            raise OSError(errno.EIO, os.strerror(errno.EIO))
        return real_fstat(descriptor)

    monkeypatch.setattr(writer, "_create", create)
    monkeypatch.setattr(os, "fstat", fstat)
    with pytest.raises(writer.NotSaved, match="Input/output error") as refused:
        save(None)
    assert [os.path.basename(path) for path in refused.value.left] == names(home / "Desktop")
    assert temporaries(home / "Desktop"), "the temporary is left and named, not removed"


def test_a_name_already_gone_at_cleanup_is_not_an_error(home):
    desktop = home / "Desktop"
    calls = []

    def cancelled() -> bool:
        calls.append(True)
        if (desktop / f"{BASE}.json").exists():
            (desktop / f"{BASE}.json").unlink()  # removed by someone else first
            return True
        return False

    with pytest.raises(writer.Cancelled) as stopped:
        save(None, json=JSON, cancelled=cancelled)
    assert stopped.value.left == () and names(desktop) == []


def test_as_root_nothing_is_created_in_an_explicit_folder_either(home, tmp_path, monkeypatch):
    folder = tmp_path / "reports"
    folder.mkdir()
    monkeypatch.setattr(writer, "_uid", lambda: 0)
    with pytest.raises(writer.NotSaved, match="root") as refused:
        save(folder)
    assert refused.value.folder == str(folder) and names(folder) == []


def test_a_refused_desktop_whose_home_folder_fails_too_is_not_saved(home, monkeypatch):
    _refusing(monkeypatch, "_create", _in(home / "Desktop"))

    def publish(folder_fd, temporary, final):
        raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))

    monkeypatch.setattr(writer, "_publish", publish)
    with pytest.raises(writer.NotSaved, match="No space left") as refused:
        save(None, json=JSON)
    assert refused.value.folder == str(home) and refused.value.left == ()
    assert names(home) == ["Desktop"] and names(home / "Desktop") == []


def test_a_cancellation_during_the_move_home_leaves_nothing(home, monkeypatch):
    _refusing(monkeypatch, "_create", _in(home / "Desktop"))

    def cancelled() -> bool:
        return (home / f"{BASE}.json").exists()  # once the JSON is published at home

    with pytest.raises(writer.Cancelled) as stopped:
        save(None, json=JSON, cancelled=cancelled)
    assert stopped.value.left == ()
    assert names(home) == ["Desktop"] and names(home / "Desktop") == []


def test_only_an_absolute_path_in_normal_form_that_is_text_is_normal():
    assert writer._normal("/Users/x/Desktop")
    for path in ("Users/x", "//Users/x", "/Users/../x", "/Users/x/", "/Users/\udcff", "/a\x00b"):
        assert not writer._normal(path), path


def test_a_folder_moved_away_mid_save_is_named_where_it_went(home, monkeypatch):
    desktop = home / "Desktop"
    real = writer._create
    moved = []

    def create(folder_fd, name):
        if not moved:
            moved.append(True)
            desktop.rename(home / "Desktop.old")  # nothing takes its place
        return real(folder_fd, name)

    monkeypatch.setattr(writer, "_create", create)
    saved = save(None)
    assert os.path.samefile(saved.pdf, home / "Desktop.old" / f"{BASE}.pdf")


def test_a_pdf_name_taken_before_its_publish_moves_the_pdf_on_alone(home, monkeypatch):
    desktop = home / "Desktop"
    real = writer._publish
    raced = []

    def publish(folder_fd, temporary, final):
        if not raced:
            raced.append(True)
            (desktop / final).write_bytes(b"theirs")
        return real(folder_fd, temporary, final)

    monkeypatch.setattr(writer, "_publish", publish)
    saved = save(None)
    assert saved.pdf == f"{desktop}/{BASE} (2).pdf" and saved.renamed
    assert names(desktop) == [f"{BASE} (2).pdf", f"{BASE}.pdf"]


def test_a_saved_file_replaced_before_the_check_is_not_saved_and_left_alone(
    home, tmp_path, monkeypatch
):
    desktop = home / "Desktop"
    theirs = tmp_path / "theirs.json"
    theirs.write_bytes(b"theirs")
    real = writer._publish

    def publish(folder_fd, temporary, final):
        real(folder_fd, temporary, final)
        if final.endswith(".pdf"):
            os.replace(theirs, desktop / f"{BASE}.json")  # this run's JSON name, theirs now

    monkeypatch.setattr(writer, "_publish", publish)
    with pytest.raises(writer.NotSaved, match="replaced"):
        save(None, json=JSON)
    assert names(desktop) == [f"{BASE}.json"]
    assert (desktop / f"{BASE}.json").read_bytes() == b"theirs"


@pytest.mark.parametrize(
    ("full", "refused", "expected"),
    [
        (True, False, [(7, 51)]),
        (True, True, [(7, 51), (7, "fsync")]),
        (False, False, [(7, "fsync")]),
    ],
    ids=["the full flush", "the full flush refused", "no full flush"],
)
def test_a_flush_uses_the_full_flush_where_the_system_has_it(monkeypatch, full, refused, expected):
    calls = []

    def flush(descriptor, command, *args):
        calls.append((descriptor, command))
        if refused:
            raise OSError(errno.ENOTSUP, os.strerror(errno.ENOTSUP))

    if full:
        monkeypatch.setattr(fcntl, "F_FULLFSYNC", 51, raising=False)
    else:
        monkeypatch.delattr(fcntl, "F_FULLFSYNC", raising=False)
    monkeypatch.setattr(fcntl, "fcntl", flush)
    monkeypatch.setattr(os, "fsync", lambda descriptor: calls.append((descriptor, "fsync")))
    writer._sync(7)
    assert calls == expected


def test_the_open_folders_path_comes_from_the_system(monkeypatch):
    monkeypatch.setattr(fcntl, "F_GETPATH", 50, raising=False)
    monkeypatch.setattr(
        fcntl, "fcntl", lambda descriptor, command, buffer: b"/Users/x/Desktop\0" + bytes(100)
    )
    assert writer._kernel_path(7) == "/Users/x/Desktop"
    monkeypatch.delattr(fcntl, "F_GETPATH")
    asked = []
    monkeypatch.setattr(os, "readlink", lambda path: asked.append(path) or "/home/x/Desktop")
    assert writer._kernel_path(7) == "/home/x/Desktop" and asked == ["/proc/self/fd/7"]


# --- purity of purpose ----------------------------------------------------------------------


def test_the_writer_spawns_nothing_and_reads_no_network():
    tree = ast.parse(Path(writer.__file__).read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
    assert not imported & {"subprocess", "socket", "urllib", "http", "shutil", "tempfile"}
    assert imported <= {
        "__future__",
        "collections.abc",
        "contextlib",
        "dataclasses",
        "errno",
        "fcntl",
        "os",
        "posixpath",
        "pwd",
        "re",
        "secrets",
        "stat",
        "typing",
    }


# --- the #354 review, round 2 ------------------------------------------------------------------


def _numbered_once_written(monkeypatch) -> None:
    """FAT and exFAT on macOS: an empty new file's number changes on fchmod and again on its
    first write, and only then settles (the #354 review, round 2)."""
    real = os.fstat

    def fstat(descriptor):  # type: ignore[no-untyped-def]
        found = real(descriptor)
        if stat.S_ISREG(found.st_mode) and found.st_size == 0:
            values = list(found)[:10]
            values[1] += 1
            return os.stat_result(values)
        return found

    monkeypatch.setattr(os, "fstat", fstat)


@pytest.mark.parametrize("json", [None, JSON], ids=["PDF", "PDF and JSON"])
def test_a_disk_whose_file_numbers_settle_once_written_is_left_clean(home, monkeypatch, json):
    _numbered_once_written(monkeypatch)

    def publish(folder_fd, temporary, final):  # type: ignore[no-untyped-def]
        raise OSError(errno.ENOTSUP, os.strerror(errno.ENOTSUP))

    monkeypatch.setattr(writer, "_publish", publish)
    with pytest.raises(writer.NotSaved, match="hard links") as refused:
        save(None, json=json)
    assert refused.value.left == ()
    assert names(home / "Desktop") == []


def test_a_disk_whose_file_numbers_settle_once_written_saves(home, monkeypatch):
    _numbered_once_written(monkeypatch)
    saved = save(None, json=JSON)
    assert names(home / "Desktop") == [f"{BASE}.json", f"{BASE}.pdf"]
    assert saved.left == ()


def test_output_dot_from_a_deleted_working_folder_is_not_saved(home, tmp_path, monkeypatch):
    gone = tmp_path / "gone"
    gone.mkdir()
    monkeypatch.chdir(gone)
    gone.rmdir()
    before = len(os.listdir("/dev/fd"))
    with pytest.raises(writer.NotSaved) as refused:
        writer.save(PDF, None, local=LOCAL, folder=".", cancelled=never)
    assert (refused.value.folder, refused.value.left) == (".", ())
    assert len(os.listdir("/dev/fd")) == before, "the folder's descriptor is closed"


@pytest.mark.parametrize("then", ["not saved", "cancelled"])
def test_the_desktops_leftovers_are_named_when_the_move_home_fails_too(home, monkeypatch, then):
    desktop = home / "Desktop"
    refused: list[bool] = []
    real_publish, real_create = writer._publish, writer._create

    def publish(folder_fd, temporary, final):  # type: ignore[no-untyped-def]
        if _in(desktop)(folder_fd):
            refused.append(True)
            raise PermissionError(errno.EPERM, os.strerror(errno.EPERM))
        return real_publish(folder_fd, temporary, final)

    def create(folder_fd, name):  # type: ignore[no-untyped-def]
        if _in(home)(folder_fd):
            raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))
        return real_create(folder_fd, name)

    monkeypatch.setattr(writer, "_publish", publish)
    _refusing(monkeypatch, "_unlink", lambda folder_fd, *rest: _in(desktop)(folder_fd))
    if then == "not saved":
        monkeypatch.setattr(writer, "_create", create)
        expected: type[Exception] = writer.NotSaved
    else:
        expected = writer.Cancelled
    with pytest.raises(expected) as stopped:
        save(None, cancelled=lambda: then == "cancelled" and bool(refused))
    left = stopped.value.left  # type: ignore[attr-defined]
    assert left and sorted(left) == sorted(f"{desktop}/{name}" for name in names(desktop))


def test_a_kernel_path_that_leads_elsewhere_is_not_used(home, tmp_path, monkeypatch):
    folder, other = tmp_path / "reports", tmp_path / "other"
    folder.mkdir()
    other.mkdir()
    real = writer._open_folder

    def open_folder(path):  # type: ignore[no-untyped-def]
        descriptor = real(path)
        os.rename(folder, tmp_path / "moved")  # the path as typed no longer leads there
        return descriptor

    monkeypatch.setattr(writer, "_open_folder", open_folder)
    monkeypatch.setattr(writer, "_kernel_path", lambda folder_fd: str(other))
    with pytest.raises(writer.NotSaved, match="path could not be read"):
        writer.save(PDF, None, local=LOCAL, folder=str(folder), cancelled=never)
    assert names(other) == [] and names(tmp_path / "moved") == []


def _folder_of_length(tmp_path: Path, length: int) -> Path:
    folder = tmp_path
    while len(os.fsencode(str(folder))) < length - 60:
        folder = folder / ("d" * 50)
    folder = folder / ("e" * (length - len(os.fsencode(str(folder))) - 1))
    folder.mkdir(parents=True)
    assert len(os.fsencode(str(folder))) == length
    return folder


@pytest.mark.parametrize("json", [None, JSON], ids=["PDF", "PDF and JSON"])
@pytest.mark.parametrize("room", [1023, 1024], ids=["1,023 bytes", "1,024 bytes"])
def test_the_longer_name_decides_at_path_max(home, tmp_path, json, room):
    # PATH_MAX counts the NUL: a path of 1,023 bytes fits and one of 1,024 does not, and
    # with the JSON its name, one byte longer than the PDF's, is the one that decides.
    name = f"{BASE}.json" if json is not None else f"{BASE}.pdf"
    folder = _folder_of_length(tmp_path, room - 1 - len(os.fsencode(name)))
    if room < writer.PATH_MAX:
        saved = save(folder, json=json)
        assert os.path.exists(saved.pdf)
    else:
        with pytest.raises(writer.NotSaved, match="too long"):
            save(folder, json=json)
        assert names(folder) == []


def test_files_left_in_a_relative_folder_are_named_by_absolute_paths(home, tmp_path, monkeypatch):
    (tmp_path / "rel").mkdir()
    monkeypatch.chdir(tmp_path)
    _refusing(monkeypatch, "_unlink", lambda folder_fd, *rest: True)
    saved = writer.save(PDF, None, local=LOCAL, folder="rel", cancelled=never)
    assert saved.left and all(os.path.isabs(path) for path in saved.left)
    assert all(os.path.exists(path) for path in saved.left)


def test_a_temporary_swapped_for_a_symlink_is_not_followed_by_the_publish(
    home, tmp_path, monkeypatch
):
    # The symlink is made under another name and renamed over the temporary, so the
    # temporary's file number is still in use when it is made, on any disk (the #354
    # review, round 3, M-1: ext4 on Linux gave the unlinked number straight back).
    outside = tmp_path / "outside.pdf"
    outside.write_bytes(b"not ours")
    real = writer._publish

    def publish(folder_fd, temporary, final):  # type: ignore[no-untyped-def]
        os.symlink(str(outside), "swap", dir_fd=folder_fd)
        os.rename("swap", temporary, src_dir_fd=folder_fd, dst_dir_fd=folder_fd)
        return real(folder_fd, temporary, final)

    monkeypatch.setattr(writer, "_publish", publish)
    with pytest.raises(writer.NotSaved):
        save(None)
    assert outside.stat().st_nlink == 1 and outside.read_bytes() == b"not ours"


def test_a_symlink_with_the_temporarys_reused_file_number_is_not_this_runs(
    home, tmp_path, monkeypatch
):
    # Where a disk hands a freed file number straight to the next file, a symlink made at
    # the temporary's name carries the recorded identity. Only a regular file is this
    # run's: the save refuses it, and the cleanup leaves the symlink alone (the #354
    # review, round 3, M-1, replayed on a disk that never reuses a number).
    desktop = home / "Desktop"
    outside = tmp_path / "outside.pdf"
    outside.write_bytes(b"not ours")
    recorded: dict[str, tuple[int, int]] = {}
    real_publish, real_identity = writer._publish, writer._identity

    def publish(folder_fd, temporary, final):  # type: ignore[no-untyped-def]
        found = os.stat(temporary, dir_fd=folder_fd, follow_symlinks=False)
        recorded["identity"] = (found.st_dev, found.st_ino)
        os.unlink(temporary, dir_fd=folder_fd)
        os.symlink(str(outside), temporary, dir_fd=folder_fd)
        return real_publish(folder_fd, temporary, final)

    def identity(folder_fd, name):  # type: ignore[no-untyped-def]
        found = real_identity(folder_fd, name)
        if stat.S_ISLNK(found.st_mode) and "identity" in recorded:
            values = list(found)[:10]
            values[2], values[1] = recorded["identity"]  # st_dev and st_ino, as reused
            return os.stat_result(values)
        return found

    monkeypatch.setattr(writer, "_publish", publish)
    monkeypatch.setattr(writer, "_identity", identity)
    with pytest.raises(writer.NotSaved, match="replaced") as refused:
        save(None)
    assert refused.value.left == ()
    assert any(os.path.islink(desktop / name) for name in temporaries(desktop))
    assert outside.read_bytes() == b"not ours"


def test_a_folder_that_cannot_be_named_after_the_save_keeps_the_report(home, monkeypatch):
    real = writer._named
    calls: list[int] = []

    def named(folder_fd, path, *rest):  # type: ignore[no-untyped-def]
        calls.append(1)
        if len(calls) > 1:
            raise OSError(errno.EIO, os.strerror(errno.EIO))
        return real(folder_fd, path, *rest)

    monkeypatch.setattr(writer, "_named", named)
    saved = save(None, json=JSON)
    assert saved.pdf == f"{home}/Desktop/{BASE}.pdf" and os.path.exists(saved.pdf)
    assert names(home / "Desktop") == [f"{BASE}.json", f"{BASE}.pdf"]


def test_a_full_flush_that_fails_is_not_saved(home, monkeypatch):
    # Only a file system that does not offer the full flush falls back to fsync; a flush
    # that fails is a failed save.
    def fcntl_failed(descriptor, command, *args):  # type: ignore[no-untyped-def]
        raise OSError(errno.EIO, os.strerror(errno.EIO))

    monkeypatch.setattr(writer.fcntl, "F_FULLFSYNC", 51, raising=False)
    monkeypatch.setattr(writer.fcntl, "fcntl", fcntl_failed)
    with pytest.raises(writer.NotSaved, match=os.strerror(errno.EIO)):
        save(None, json=JSON)
    assert names(home / "Desktop") == []


def test_a_cancellation_during_the_announcement_opens_nothing(home, monkeypatch):
    opened: list[str] = []
    real = writer._open_folder
    monkeypatch.setattr(writer, "_open_folder", lambda path: opened.append(path) or real(path))
    flag: list[bool] = []
    with pytest.raises(writer.Cancelled):
        save(None, cancelled=lambda: bool(flag), before_desktop=lambda: flag.append(True))
    assert opened == [] and names(home / "Desktop") == []


def test_a_cancellation_when_the_desktop_refuses_does_not_move_home(home, monkeypatch):
    desktop = str(home / "Desktop")
    opened: list[str] = []
    flag: list[bool] = []
    real = writer._open_folder

    def open_folder(path):  # type: ignore[no-untyped-def]
        opened.append(path)
        if path == desktop:
            flag.append(True)  # Ctrl-C at the prompt, which then refuses
            raise PermissionError(errno.EPERM, os.strerror(errno.EPERM))
        return real(path)

    monkeypatch.setattr(writer, "_open_folder", open_folder)
    with pytest.raises(writer.Cancelled):
        save(None, cancelled=lambda: bool(flag))
    assert opened == [desktop] and names(home) == ["Desktop"]


# --- the #354 review, round 3: what the round-2 checks left open ------------------------


def test_a_cancellation_while_macos_asks_about_the_desktop_makes_nothing(home, monkeypatch):
    # macOS asks about the Desktop inside the open; a Ctrl-C there, then Allow, publishes
    # nothing (the #354 review, round 3, a nit).
    desktop = str(home / "Desktop")
    flag: list[bool] = []
    real = writer._open_folder

    def open_folder(path):  # type: ignore[no-untyped-def]
        if path == desktop:
            flag.append(True)  # Ctrl-C at the prompt, which then allows
        return real(path)

    monkeypatch.setattr(writer, "_open_folder", open_folder)
    made: list[str] = []
    real_create = writer._create
    monkeypatch.setattr(
        writer, "_create", lambda folder_fd, name: made.append(name) or real_create(folder_fd, name)
    )
    with pytest.raises(writer.Cancelled):
        save(None, json=JSON, cancelled=lambda: bool(flag))
    assert made == [] and names(home / "Desktop") == []


def test_the_desktop_is_announced_once(home):
    announced: list[int] = []
    save(None, before_desktop=lambda: announced.append(1))
    assert announced == [1]


def test_a_ctrl_c_from_a_file_system_call_is_cleaned_up(home, monkeypatch):
    # A KeyboardInterrupt raised outside the flag, here by the PDF's link once the JSON is
    # out, is cleaned up as far as it can be, as the module says.
    real = writer._publish

    def publish(folder_fd, temporary, final):  # type: ignore[no-untyped-def]
        if final.endswith(".pdf"):
            raise KeyboardInterrupt
        return real(folder_fd, temporary, final)

    monkeypatch.setattr(writer, "_publish", publish)
    try:
        with pytest.raises(writer.Cancelled) as stopped:
            save(None, json=JSON)
    except KeyboardInterrupt:  # escaping, it would stop the whole test run
        pytest.fail("the Ctrl-C left the save as it was")
    assert names(home / "Desktop") == [] and stopped.value.left == ()


def test_a_folder_that_cannot_be_named_again_keeps_the_report_whatever_it_raises(home, monkeypatch):
    # The folder named once before the save and again after it: a second naming that fails
    # with NotSaved, like one that fails with an OSError, keeps the saved report.
    real = writer._named
    calls: list[int] = []

    def named(folder_fd, path):  # type: ignore[no-untyped-def]
        calls.append(1)
        if len(calls) > 1:
            raise writer.NotSaved("the folder's path could not be read", path)
        return real(folder_fd, path)

    monkeypatch.setattr(writer, "_named", named)
    saved = save(None, json=JSON)
    assert os.path.exists(saved.pdf)
    assert names(home / "Desktop") == [f"{BASE}.json", f"{BASE}.pdf"]


def test_a_failed_save_in_a_relative_folder_names_what_is_left_absolutely(
    home, tmp_path, monkeypatch
):
    (tmp_path / "rel").mkdir()
    monkeypatch.chdir(tmp_path)
    _refusing(monkeypatch, "_unlink", lambda folder_fd, name: name.endswith(".json"))

    def publish(folder_fd, temporary, final):  # type: ignore[no-untyped-def]
        if final.endswith(".pdf"):
            raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))
        return os.link(temporary, final, src_dir_fd=folder_fd, dst_dir_fd=folder_fd)

    monkeypatch.setattr(writer, "_publish", publish)
    with pytest.raises(writer.NotSaved) as refused:
        writer.save(PDF, JSON, local=LOCAL, folder="rel", cancelled=never)
    assert refused.value.left == (f"{tmp_path.resolve()}/rel/{BASE}.json",)


def test_only_a_link_the_disk_cannot_make_is_named_as_no_hard_links(home, monkeypatch):
    # ENOTSUP from the link means the disk keeps no hard links; from anything else it is
    # the system's own reason (the #354 review, round 3, a nit).
    def unsupported(*args):  # type: ignore[no-untyped-def]
        raise OSError(errno.ENOTSUP, os.strerror(errno.ENOTSUP))

    monkeypatch.setattr(writer, "_publish", unsupported)
    with pytest.raises(writer.NotSaved) as refused:
        save(None)
    assert str(refused.value) == writer._NO_LINKS
    monkeypatch.undo()
    monkeypatch.setattr(writer, "home", lambda: str(home))
    monkeypatch.setattr(writer, "_create", unsupported)
    with pytest.raises(writer.NotSaved) as refused:
        save(None)
    assert str(refused.value) == os.strerror(errno.ENOTSUP)


# --- the #354 review, round 4: one temporary, 130 before 4, and whose file a name is -------


@pytest.mark.parametrize(
    ("json", "taken"),
    [(JSON, ".json"), (JSON, ".pdf"), (None, ".pdf")],
    ids=["the JSON's name", "the PDF's name", "the PDF alone"],
)
def test_a_retry_after_a_taken_name_never_makes_a_second_temporary(home, monkeypatch, json, taken):
    # Another process takes the final name as it is linked, and this run's temporary for it
    # will not go: the save stops rather than make another under the next name, and names
    # the one temporary (the #354 review, round 4, m-1; the GPT audit, G1-06).
    desktop = home / "Desktop"
    most: list[int] = []
    raced: list[bool] = []
    real_create, real_publish = writer._create, writer._publish

    def create(folder_fd, name):  # type: ignore[no-untyped-def]
        most.append(len(temporaries(desktop)))
        return real_create(folder_fd, name)

    def publish(folder_fd, temporary, final):  # type: ignore[no-untyped-def]
        if final == BASE + taken and not raced:
            raced.append(True)
            (desktop / final).write_bytes(b"theirs")  # another process takes the name
        return real_publish(folder_fd, temporary, final)

    monkeypatch.setattr(writer, "_create", create)
    monkeypatch.setattr(writer, "_publish", publish)
    _refusing(monkeypatch, "_unlink", lambda folder_fd, name: bool(raced) and name.endswith(".tmp"))
    with pytest.raises(writer.NotSaved, match="temporary") as refused:
        save(None, json=json)
    assert max(most) == 0, "no temporary was made while another was there"
    assert [os.path.basename(path) for path in refused.value.left] == temporaries(desktop)
    assert len(temporaries(desktop)) == 1
    assert (desktop / (BASE + taken)).read_bytes() == b"theirs"


def test_a_json_that_will_not_go_does_not_stop_the_retry(home, monkeypatch):
    # The PDF's name is taken as it is linked, and this run's JSON under the first name cannot
    # be removed. No temporary is left, so the save moves on to the next name and names that
    # JSON (the #354 review, round 4, m-1).
    desktop = home / "Desktop"
    raced: list[bool] = []
    real = writer._publish

    def publish(folder_fd, temporary, final):  # type: ignore[no-untyped-def]
        if final == f"{BASE}.pdf" and not raced:
            raced.append(True)
            (desktop / final).write_bytes(b"theirs")
        return real(folder_fd, temporary, final)

    monkeypatch.setattr(writer, "_publish", publish)
    _refusing(monkeypatch, "_unlink", lambda folder_fd, name: name.endswith(".json"))
    saved = save(None, json=JSON)
    assert (saved.json, saved.pdf) == (f"{desktop}/{BASE} (2).json", f"{desktop}/{BASE} (2).pdf")
    assert saved.left == (f"{desktop}/{BASE}.json",) and temporaries(desktop) == []


def test_a_cancellation_that_meets_a_temporary_that_will_not_go_is_a_cancellation(
    home, monkeypatch
):
    # The flag is set as the JSON is linked, and the JSON's temporary will not go: the save
    # stops as a cancellation, so the run exits 130, not 4 (the #354 review, round 4, m-2).
    desktop = home / "Desktop"
    flag: list[bool] = []
    real = writer._publish

    def publish(folder_fd, temporary, final):  # type: ignore[no-untyped-def]
        if final.endswith(".json"):
            flag.append(True)  # the run's handler, as the JSON is linked
        return real(folder_fd, temporary, final)

    monkeypatch.setattr(writer, "_publish", publish)
    _refusing(monkeypatch, "_unlink", lambda folder_fd, name: name.endswith(".tmp"))
    with pytest.raises(writer.Cancelled) as stopped:
        save(None, json=JSON, cancelled=lambda: bool(flag))
    assert sorted(stopped.value.left) == sorted(f"{desktop}/{name}" for name in names(desktop))
    assert len(temporaries(desktop)) == 1


def test_a_cancellation_is_read_before_a_temporary_that_will_not_go_stops_the_retry(
    home, monkeypatch
):
    # The flag is set as the JSON's name is taken at its link, and the JSON's temporary will
    # not go. No read of the flag comes between that link and the stop for the temporary,
    # and the save still ends as a cancellation (the #354 review, round 4, m-2 and m-5).
    desktop = home / "Desktop"
    flag: list[bool] = []
    real = writer._publish

    def publish(folder_fd, temporary, final):  # type: ignore[no-untyped-def]
        if final == f"{BASE}.json" and not flag:
            flag.append(True)  # the run's handler, as another process takes the name
            (desktop / final).write_bytes(b"theirs")
        return real(folder_fd, temporary, final)

    monkeypatch.setattr(writer, "_publish", publish)
    _refusing(monkeypatch, "_unlink", lambda folder_fd, name: name.endswith(".tmp"))
    with pytest.raises(writer.Cancelled) as stopped:
        save(None, json=JSON, cancelled=lambda: bool(flag))
    (left,) = stopped.value.left
    assert names(desktop) == sorted([f"{BASE}.json", os.path.basename(left)])


def test_a_cancellation_that_meets_a_failed_write_is_a_cancellation(home, monkeypatch):
    # The flag is set as the PDF's temporary is made, and its write then fails for real: a
    # cancellation still, and nothing is left (the #354 review, round 4, m-2).
    desktop = home / "Desktop"
    flag: list[bool] = []
    real_create, real_write = writer._create, writer._write_all

    def create(folder_fd, name):  # type: ignore[no-untyped-def]
        if (desktop / f"{BASE}.json").exists():
            flag.append(True)
        return real_create(folder_fd, name)

    def write_all(descriptor, data):  # type: ignore[no-untyped-def]
        if flag:
            raise OSError(errno.EFBIG, os.strerror(errno.EFBIG))
        return real_write(descriptor, data)

    monkeypatch.setattr(writer, "_create", create)
    monkeypatch.setattr(writer, "_write_all", write_all)
    with pytest.raises(writer.Cancelled) as stopped:
        save(None, json=JSON, cancelled=lambda: bool(flag))
    assert stopped.value.left == () and names(desktop) == []


def _renamed_over(folder_fd: int, temporary: str, kind: str, outside: Path) -> None:
    """Another process's file of ``kind`` made under a name of its own, then renamed over
    the temporary, whose file stays in use as it does."""
    if kind == "a symlink":
        os.symlink(str(outside), "swap", dir_fd=folder_fd)
    elif kind == "a FIFO" and os.mkfifo not in os.supports_dir_fd:
        # python.org's Python 3.11 for macOS has no mkfifoat, so os.mkfifo takes no dir_fd
        # there: the FIFO is made beside ``outside``, on the same file system, and renamed
        # over the temporary from there.
        fifo = outside.with_name("swap")
        os.mkfifo(fifo)
        os.rename(fifo, temporary, dst_dir_fd=folder_fd)
        return
    elif kind == "a FIFO":
        os.mkfifo("swap", dir_fd=folder_fd)
    else:
        theirs = os.open("swap", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=folder_fd)
        os.write(theirs, b"theirs!!")
        os.close(theirs)
    os.rename("swap", temporary, src_dir_fd=folder_fd, dst_dir_fd=folder_fd)


@pytest.mark.parametrize("kind", ["a symlink", "a FIFO", "a regular file"])
def test_a_name_the_link_made_for_another_file_is_removed_again(home, tmp_path, monkeypatch, kind):
    # Another process renames its own file over the flushed temporary just before the link,
    # so the link names their file: the save stops, the report's name goes again, and their
    # file stays at the temporary's name (the #354 review, round 4, m-3).
    desktop = home / "Desktop"
    outside = tmp_path / "outside.pdf"
    outside.write_bytes(b"not ours")
    real = writer._publish

    def publish(folder_fd, temporary, final):  # type: ignore[no-untyped-def]
        _renamed_over(folder_fd, temporary, kind, outside)
        return real(folder_fd, temporary, final)

    monkeypatch.setattr(writer, "_publish", publish)
    with pytest.raises(writer.NotSaved, match="replaced") as refused:
        save(None)
    assert [name for name in names(desktop) if not name.endswith(".tmp")] == []
    assert refused.value.left == () and len(temporaries(desktop)) == 1
    assert outside.read_bytes() == b"not ours"


def test_a_json_linked_for_another_file_stops_the_save_before_the_pdf(home, tmp_path, monkeypatch):
    # The JSON's temporary is swapped just before its link: the check just after the link
    # stops the save at once, before the PDF is made, and the JSON's name goes again (the
    # #354 review, round 4, m-3).
    desktop = home / "Desktop"
    linked: list[str] = []
    real = writer._publish

    def publish(folder_fd, temporary, final):  # type: ignore[no-untyped-def]
        linked.append(final)
        if final.endswith(".json"):
            _renamed_over(folder_fd, temporary, "a regular file", tmp_path)
        return real(folder_fd, temporary, final)

    monkeypatch.setattr(writer, "_publish", publish)
    with pytest.raises(writer.NotSaved, match="replaced") as refused:
        save(None, json=JSON)
    assert linked == [f"{BASE}.json"] and refused.value.left == ()
    (theirs,) = names(desktop)
    assert theirs.endswith(".tmp") and (desktop / theirs).read_bytes() == b"theirs!!"


def test_a_file_with_another_name_that_takes_a_published_name_is_left_alone(
    home, tmp_path, monkeypatch
):
    # Another process moves its own file, which has a second name elsewhere, onto this run's
    # published JSON. The name is theirs now, not one this run's link made for their file,
    # so the cleanup leaves it (the #354 review, round 4).
    desktop = home / "Desktop"
    theirs = tmp_path / "theirs.json"
    theirs.write_bytes(b"theirs")
    os.link(theirs, tmp_path / "their other name")
    real = writer._publish

    def publish(folder_fd, temporary, final):  # type: ignore[no-untyped-def]
        real(folder_fd, temporary, final)
        if final.endswith(".pdf"):
            os.replace(theirs, desktop / f"{BASE}.json")

    monkeypatch.setattr(writer, "_publish", publish)
    with pytest.raises(writer.NotSaved, match="replaced") as refused:
        save(None, json=JSON)
    assert names(desktop) == [f"{BASE}.json"] and refused.value.left == ()
    assert (desktop / f"{BASE}.json").read_bytes() == b"theirs"


def test_the_temporary_is_checked_by_name_just_before_its_link(home, tmp_path, monkeypatch):
    # The temporary is swapped for another process's symlink before the check that comes just
    # before the link: nothing is linked at all (the #354 review, round 4, m-3).
    desktop = home / "Desktop"
    outside = tmp_path / "outside.pdf"
    outside.write_bytes(b"not ours")
    linked: list[str] = []
    swapped: list[bool] = []
    real = writer._publish

    def publish(folder_fd, temporary, final):  # type: ignore[no-untyped-def]
        linked.append(final)
        return real(folder_fd, temporary, final)

    def cancelled() -> bool:
        found = temporaries(desktop)
        if found and not swapped:  # the PDF's temporary is written, just before its link
            swapped.append(True)
            (desktop / "swap").symlink_to(outside)
            os.rename(desktop / "swap", desktop / found[0])
        return False

    monkeypatch.setattr(writer, "_publish", publish)
    with pytest.raises(writer.NotSaved, match="replaced") as refused:
        save(None, cancelled=cancelled)
    assert swapped and linked == [] and refused.value.left == ()
    assert [name for name in names(desktop) if not name.endswith(".tmp")] == []


def test_a_regular_file_given_the_temporarys_freed_number_is_not_published(home, monkeypatch):
    # A disk can hand a freed file number straight to the next file (the #354 review, round
    # 4: a nearly full FAT32 volume did; ext4 may). Another process removes the flushed
    # temporary and writes its own file at that name, which could take the temporary's
    # number if nothing held it. The replay gives their file the recorded number only while
    # no descriptor holds the temporary's file, as such a disk would; the writer holds it
    # until the save ends, so their file is never taken for the report.
    desktop = home / "Desktop"
    held: list[int] = []
    recorded: dict[str, tuple[int, int]] = {}
    real_create, real_publish, real_identity = writer._create, writer._publish, writer._identity

    def create(folder_fd, name):  # type: ignore[no-untyped-def]
        descriptor = real_create(folder_fd, name)
        held.append(descriptor)
        return descriptor

    def freed() -> bool:
        try:
            found = os.fstat(held[-1])
        except OSError:
            return True  # closed: the number is free once no name is left either
        return (found.st_dev, found.st_ino) != recorded["identity"]

    def publish(folder_fd, temporary, final):  # type: ignore[no-untyped-def]
        found = os.stat(temporary, dir_fd=folder_fd, follow_symlinks=False)
        recorded["identity"] = (found.st_dev, found.st_ino)
        os.unlink(temporary, dir_fd=folder_fd)
        theirs = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=folder_fd)
        os.write(theirs, b"theirs!!")
        os.close(theirs)
        return real_publish(folder_fd, temporary, final)

    def identity(folder_fd, name):  # type: ignore[no-untyped-def]
        found = real_identity(folder_fd, name)
        if (
            "identity" in recorded
            and freed()
            and (found.st_dev, found.st_ino) != recorded["identity"]
        ):
            values = list(found)[:10]
            values[2], values[1] = recorded["identity"]  # st_dev and st_ino, as reused
            return os.stat_result(values)
        return found

    monkeypatch.setattr(writer, "_create", create)
    monkeypatch.setattr(writer, "_publish", publish)
    monkeypatch.setattr(writer, "_identity", identity)
    with pytest.raises(writer.NotSaved, match="replaced"):
        save(None)
    (theirs,) = names(desktop)
    assert theirs.endswith(".tmp") and (desktop / theirs).read_bytes() == b"theirs!!"


def test_a_regular_file_shown_with_the_held_files_number_is_still_not_this_runs(
    home, tmp_path, monkeypatch
):
    # The review's replay as it was written: their file, renamed over the flushed temporary,
    # is shown with the temporary's number even while the writer holds the temporary open.
    # No disk does that, but a volume that numbers files some other way might, and the
    # size and the count of names still tell the two apart (the #354 review, round 4).
    desktop = home / "Desktop"
    recorded: dict[str, tuple[int, int]] = {}
    real_publish, real_identity = writer._publish, writer._identity

    def publish(folder_fd, temporary, final):  # type: ignore[no-untyped-def]
        found = os.stat(temporary, dir_fd=folder_fd, follow_symlinks=False)
        recorded["identity"] = (found.st_dev, found.st_ino)
        _renamed_over(folder_fd, temporary, "a regular file", tmp_path)
        return real_publish(folder_fd, temporary, final)

    def identity(folder_fd, name):  # type: ignore[no-untyped-def]
        found = real_identity(folder_fd, name)
        if "identity" in recorded and (found.st_dev, found.st_ino) != recorded["identity"]:
            values = list(found)[:10]
            values[2], values[1] = recorded["identity"]  # st_dev and st_ino, as shown
            return os.stat_result(values)
        return found

    monkeypatch.setattr(writer, "_publish", publish)
    monkeypatch.setattr(writer, "_identity", identity)
    with pytest.raises(writer.NotSaved, match="replaced"):
        save(None)
    (theirs,) = names(desktop)
    assert theirs.endswith(".tmp") and (desktop / theirs).read_bytes() == b"theirs!!"


def test_a_name_is_this_runs_only_while_it_matches_the_held_file_in_every_fact():
    # A regular file with the held file's number, size and count of names, each read at
    # the check (the #354 review, rounds 3 and 4).
    held = os.stat_result((stat.S_IFREG | 0o600, 11, 3, 2, 501, 20, 21, 0, 0, 0))
    assert writer._ours(held, held)
    for index in (1, 2, 3, 6):  # st_ino, st_dev, st_nlink and st_size
        values = list(held)[:10]
        values[index] += 1
        assert not writer._ours(os.stat_result(values), held), index
    values = list(held)[:10]
    values[0] = stat.S_IFLNK | 0o755
    assert not writer._ours(os.stat_result(values), held)


def test_a_file_moved_onto_the_temporary_while_it_is_written_is_left_alone(
    home, tmp_path, monkeypatch
):
    # Another process moves its own file onto this run's temporary while it is written, and
    # the write then fails. The cleanup finds their file at the name, not the one it holds
    # open, and leaves it (the #354 review, round 4, m-3: a name whose identity was not yet
    # recorded was removed unchecked).
    desktop = home / "Desktop"
    theirs = tmp_path / "theirs.txt"
    theirs.write_bytes(b"their data")

    def write_all(descriptor, data):  # type: ignore[no-untyped-def]
        (temporary,) = temporaries(desktop)
        os.rename(theirs, desktop / temporary)
        raise OSError(errno.EFBIG, os.strerror(errno.EFBIG))

    monkeypatch.setattr(writer, "_write_all", write_all)
    with pytest.raises(writer.NotSaved, match=os.strerror(errno.EFBIG)) as refused:
        save(None)
    assert temporaries(desktop), "their file is gone"
    (temporary,) = temporaries(desktop)
    assert (desktop / temporary).read_bytes() == b"their data" and refused.value.left == ()


def test_a_folder_at_the_temporarys_name_does_not_move_the_save_home(home, monkeypatch):
    # link(2) refuses a folder with EPERM, which is also how macOS refuses the Desktop. It
    # moves the save home only while the temporary is still this run's (the #354 review,
    # round 4, n-3).
    desktop = home / "Desktop"
    real = writer._publish

    def publish(folder_fd, temporary, final):  # type: ignore[no-untyped-def]
        if _in(desktop)(folder_fd):
            os.unlink(temporary, dir_fd=folder_fd)
            os.mkdir(temporary, dir_fd=folder_fd)
        return real(folder_fd, temporary, final)

    monkeypatch.setattr(writer, "_publish", publish)
    with pytest.raises(writer.NotSaved, match="replaced") as refused:
        save(None)
    assert refused.value.left == () and names(home) == ["Desktop"]
    (theirs,) = names(desktop)
    assert (desktop / theirs).is_dir()


def test_a_desktop_that_keeps_the_pdfs_temporary_does_not_move_the_save_home(home, monkeypatch):
    # macOS refuses the Desktop from the PDF's link on, removals included, so the PDF's
    # temporary stays there. The save's own check for a temporary left on the Desktop stops
    # the move home (the #354 review, round 4, m-5).
    desktop = home / "Desktop"
    refusing: list[bool] = []
    real = writer._publish

    def publish(folder_fd, temporary, final):  # type: ignore[no-untyped-def]
        if final.endswith(".pdf") and _in(desktop)(folder_fd):
            refusing.append(True)
            raise PermissionError(errno.EPERM, os.strerror(errno.EPERM))
        return real(folder_fd, temporary, final)

    monkeypatch.setattr(writer, "_publish", publish)
    _refusing(
        monkeypatch, "_unlink", lambda folder_fd, name: bool(refusing) and _in(desktop)(folder_fd)
    )
    with pytest.raises(writer.NotSaved) as refused:
        save(None, json=JSON)
    assert names(home) == ["Desktop"], "nothing was made at home"
    assert len(temporaries(desktop)) == 1
    assert sorted(refused.value.left) == sorted(f"{desktop}/{name}" for name in names(desktop))


def test_a_fallback_names_the_json_the_desktop_kept(home, monkeypatch):
    # macOS refuses the Desktop once the JSON is there, removals included: no temporary is
    # left, the report goes home, and Saved names the JSON left on the Desktop (the #354
    # review, round 4, m-5).
    desktop = home / "Desktop"
    refusing: list[bool] = []
    real = writer._create

    def create(folder_fd, name):  # type: ignore[no-untyped-def]
        if _in(desktop)(folder_fd) and (desktop / f"{BASE}.json").exists():
            refusing.append(True)
            raise PermissionError(errno.EPERM, os.strerror(errno.EPERM))
        return real(folder_fd, name)

    monkeypatch.setattr(writer, "_create", create)
    _refusing(
        monkeypatch, "_unlink", lambda folder_fd, name: bool(refusing) and _in(desktop)(folder_fd)
    )
    saved = save(None, json=JSON)
    assert saved.fallback and names(desktop) == [f"{BASE}.json"]
    assert saved.left == (f"{desktop}/{BASE}.json",)
    assert (saved.json, saved.pdf) == (f"{home}/{BASE}.json", f"{home}/{BASE}.pdf")


def test_a_cancellation_during_the_folders_flush_undoes_the_save(home, monkeypatch):
    # The flag is read last after the folder's flush, the slowest step after the links, so a
    # Ctrl-C during it still undoes the save (the #354 review, round 4, m-5).
    flag: list[bool] = []
    real = writer._sync

    def sync(descriptor):  # type: ignore[no-untyped-def]
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            flag.append(True)
        return real(descriptor)

    monkeypatch.setattr(writer, "_sync", sync)
    with pytest.raises(writer.Cancelled) as stopped:
        save(None, json=JSON, cancelled=lambda: bool(flag))
    assert names(home / "Desktop") == [] and stopped.value.left == ()


# A child that sets the flag as the PDF is linked, as the run's handler would, and kills
# itself with SIGKILL when the cleanup that follows is about to remove one of the two
# report files while the other is already gone.
_KILLED_IN_THE_CLEANUP = """
import os, signal, sys
from voltry_mac import writer
folder = sys.argv[1]
flag = []
real_publish, real_unlink = writer._publish, writer._unlink
def publish(folder_fd, temporary, final):
    if final.endswith(".pdf"):
        flag.append(True)
    return real_publish(folder_fd, temporary, final)
def unlink(folder_fd, name):
    if flag and not name.endswith(".tmp") and len(os.listdir(folder)) == 1:
        os.kill(os.getpid(), signal.SIGKILL)
    return real_unlink(folder_fd, name)
writer._publish, writer._unlink = publish, unlink
writer.save(b"%PDF", b"{}", local="2026-09-23T14:05:31-07:00", folder=folder,
            cancelled=lambda: bool(flag))
"""


def test_a_kill_in_the_cleanup_leaves_a_json_without_its_pdf_never_the_pdf_alone(tmp_path):
    # The cleanup removes the newest name first, so a hard kill during it leaves at most what
    # the docs name: a JSON without its PDF (the #354 review, round 4, n-1).
    folder = tmp_path / "reports"
    folder.mkdir()
    killed = subprocess.run(
        [sys.executable, "-c", _KILLED_IN_THE_CLEANUP, str(folder)], timeout=60, check=False
    )
    assert killed.returncode == -signal.SIGKILL
    assert names(folder) == [f"{BASE}.json"]


def test_the_name_taken_reason_names_no_file(home):
    # The run prints the reason inside a sentence it wraps, so the reason names no file that
    # a wrap could split (the review of the copy pass, MAC 3.11, m10).
    desktop = home / "Desktop"
    for number in range(1, writer.LAST + 1):
        stem = BASE if number == 1 else f"{BASE} ({number})"
        (desktop / f"{stem}.pdf").write_bytes(b"x")
    with pytest.raises(writer.NotSaved, match=r"\(99\)") as refused:
        save(None)
    assert "Voltry Mac Report" not in str(refused.value)


def test_every_reason_in_the_writers_own_words_is_a_constant_listed_in_reasons():
    # The copy pass pins each reason word for word (MAC 3.11): no reason is written where it
    # is raised, and REASONS lists every constant one is given, once, in a fixed order.
    tree = ast.parse(Path(writer.__file__).read_text(encoding="utf-8"))
    given = set()
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
            continue
        if node.func.id == "NotSaved":
            reason = node.args[0]
        elif node.func.id in ("OSError", "_NoLinks") and len(node.args) == 2:
            reason = node.args[1]
        else:
            continue
        assert not isinstance(reason, ast.Constant | ast.JoinedStr), ast.unparse(node)
        if isinstance(reason, ast.Name):
            given.add(getattr(writer, reason.id))
    assert isinstance(writer.REASONS, tuple) and len(set(writer.REASONS)) == len(writer.REASONS)
    assert given == set(writer.REASONS)


def test_a_temporary_a_save_left_is_the_pdfs_second_name():
    # Change record 21: once a save is complete, only the PDF's temporary can be left, a
    # second name for the PDF, which keeps O1 from opening it; a JSON left is not.
    temporary = "/Users/jane/Desktop/.voltry-mac-0123456789abcdef.tmp"
    json = "/Users/jane/Desktop/Voltry Mac Report 2026-09-23 14.05.json"
    pdf = "/Users/jane/Voltry Mac Report 2026-09-23 14.05.pdf"
    assert writer.Saved(pdf, None, False, False, (temporary,)).second_name
    assert not writer.Saved(pdf, None, True, False, (json,)).second_name
    assert not writer.Saved(pdf, None, False, False).second_name
