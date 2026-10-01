"""`voltry-mac render REPORT.json [--output DIR] [--no-open]` (docs/VOLTRY_MAC_SPEC.md,
Decision 4's render rules; Failure modes' render rows and the exit codes; Decision 5).

The command reads the saved report with a 4 MiB cap, reading at most one byte past it and
only from a regular file, opened without waiting; hands the bytes to render.render, which
validates them before anything else; says in one line when another version made the report;
and then uses the same naming, collision, save and open rules as a live run. It collects
nothing: the open is the only command it may start. A file it cannot read, or one that is
not a report it can render, exits 2 and is named by its field path, never its value.
"""

from __future__ import annotations

import copy
import errno
import os
import select
import signal
import subprocess
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
import voltry_mac_test_reports as r
from voltry_mac_test_fake_mac import command

import voltry_mac
from voltry_mac import (
    canonical,
    cli,
    console,
    manifests,
    preflight,
    render,
    report_pdf,
    run,
    spawn,
    writer,
)

TESTS = Path(__file__).resolve().parent
FIXTURES = TESTS / "fixtures" / "reports"
SUPPORTED = preflight.Platform(macos=True, arm64=True, translated=False, release="25.6.0")
PDF_NAME = "Voltry Mac Report 2026-09-23 14.05.pdf"
MADE_BY = "0.1.0"  # the version the saved fixtures say made them


@pytest.fixture
def mac(monkeypatch, tmp_path):  # type: ignore[no-untyped-def]
    """A supported Mac, a home folder under tmp_path, and a chokepoint that may run O1 only."""
    home = tmp_path / "home"
    (home / "Desktop").mkdir(parents=True)
    ran: list[str] = []
    opened: list[str] = []

    def execute(argv, **kwargs):  # type: ignore[no-untyped-def]
        command_id = kwargs["command_id"]
        ran.append(command_id)
        if command_id == "O1":
            opened.append(argv[-1])
        return spawn.Result(command_id, spawn.Ending.EXITED, 0, "", "", 20, False, True)

    monkeypatch.setattr(spawn, "_execute", execute)
    monkeypatch.setattr(os, "geteuid", lambda: 501)
    monkeypatch.setattr(preflight, "read", lambda **_: SUPPORTED)
    monkeypatch.setattr(writer, "home", lambda: str(home))
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    monkeypatch.delenv("SSH_TTY", raising=False)
    monkeypatch.chdir(tmp_path)
    return SimpleNamespace(home=home, desktop=home / "Desktop", ran=ran, opened=opened)


def go(capsys, *argv: str) -> tuple[int, str, str]:
    code = cli.main(["render", *argv])
    out, err = capsys.readouterr()
    return code, out, err


def saved(name: str = "m5-laptop") -> bytes:
    return (FIXTURES / f"{name}.json").read_bytes()


def report_file(tmp_path: Path, data: bytes, name: str = "report.json") -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def pdf_name(data: bytes) -> str:
    """The file name a report's own local time gives."""
    local = str(canonical.load(data)["collected_at_local"])
    return f"Voltry Mac Report {local[:10]} {local[11:13]}.{local[14:16]}.pdf"


# --- a saved report back to its PDF --------------------------------------------------------------


@pytest.mark.parametrize("name", ["m5-laptop", "concerning-desktop", "m5-laptop-declined-a4"])
def test_a_saved_report_is_drawn_again_and_saved_on_the_desktop(capsys, mac, tmp_path, name):
    path = report_file(tmp_path, saved(name))
    code, out, err = go(capsys, str(path))
    assert (code, err) == (0, "")
    # At 80 columns, broken where the copy pass breaks it (MAC 3.11). At 0.1.0 itself the
    # fixtures are this version's own reports, so render names no second version: the
    # release commit ran this at 0.1.0 first (2026-09-29).
    both = (
        f"This report was made by voltry-mac {MADE_BY}, renderer {report_pdf.RENDERER}; this PDF"
        f" is drawn by\nvoltry-mac {voltry_mac.__version__}, renderer {report_pdf.RENDERER}, so"
        " it may differ from the original PDF.\n\n"
    )
    said = both if voltry_mac.__version__ != MADE_BY else ""
    named = pdf_name(saved(name))
    assert out == (
        f"{cli.HEADER}\n\n{said}{run.DESKTOP}\nSaved: ~/Desktop/{named}\n{run.OPENING}\n"
    )
    assert [p.name for p in mac.desktop.iterdir()] == [named]
    assert (mac.desktop / named).read_bytes() == render.render(saved(name)).pdf
    assert mac.ran == ["O1"] and mac.opened == [str(mac.desktop / named)]


def test_a_report_this_version_made_names_no_second_version(capsys, mac, tmp_path, monkeypatch):
    for module in (run, render, manifests):
        monkeypatch.setattr(module, "__version__", MADE_BY)
    path = report_file(tmp_path, saved())
    code, out, _ = go(capsys, str(path))
    assert code == 0
    assert out == f"{cli.HEADER}\n\n{run.DESKTOP}\nSaved: ~/Desktop/{PDF_NAME}\n{run.OPENING}\n"
    pdf = (mac.desktop / PDF_NAME).read_bytes()
    document = canonical.load(saved())
    assert pdf == report_pdf.render(document, manifests.templates(MADE_BY))


def test_the_file_is_named_for_the_reports_own_time(capsys, mac, tmp_path):
    document = copy.deepcopy(r.load("m5-laptop"))
    document["collected_at_local"] = "2026-09-23T09:41:31-12:00"
    document["collected_at_utc"] = "2026-09-23T21:41:31Z"
    path = report_file(tmp_path, canonical.canonical_json(r.rehash(document)).encode())
    code, out, _ = go(capsys, str(path))
    assert code == 0
    assert "Saved: ~/Desktop/Voltry Mac Report 2026-09-23 09.41.pdf\n" in out


def test_an_explicit_folder_is_used_as_given_and_not_announced(capsys, mac, tmp_path):
    folder = tmp_path / "out"
    folder.mkdir()
    path = report_file(tmp_path, saved())
    code, out, _ = go(capsys, str(path), "--output", str(folder))
    assert code == 0
    assert run.DESKTOP not in out
    assert f"Saved: {folder / PDF_NAME}\n{run.OPENING}\n" in out


def test_a_taken_name_takes_the_next(capsys, mac, tmp_path):
    (mac.desktop / PDF_NAME).write_bytes(b"not ours")
    code, out, _ = go(capsys, str(report_file(tmp_path, saved())))
    assert code == 0
    assert (
        "Saved: ~/Desktop/Voltry Mac Report 2026-09-23 14.05 (2).pdf\n"
        f"{run.RENAMED.format(time='14:05')}\n{run.OPENING}\n"
    ) in out
    assert (mac.desktop / PDF_NAME).read_bytes() == b"not ours"


def test_a_refused_desktop_saves_in_the_home_folder(capsys, mac, tmp_path, monkeypatch):
    real = writer._open_folder

    def refusing(path):  # type: ignore[no-untyped-def]
        if path == str(mac.desktop):
            raise PermissionError(errno.EPERM, os.strerror(errno.EPERM))
        return real(path)

    monkeypatch.setattr(writer, "_open_folder", refusing)
    code, out, _ = go(capsys, str(report_file(tmp_path, saved())))
    assert code == 0
    assert out.endswith(
        f"{run.DESKTOP}\n{run.FALLBACK_BEFORE}\n  ~/{PDF_NAME}\n{run.FALLBACK_AFTER}\n"
        f"{run.OPENING}\n"
    )


def test_a_report_that_cannot_be_saved_exits_4(capsys, mac, tmp_path):
    code, _, err = go(capsys, str(report_file(tmp_path, saved())), "--output", "missing")
    assert code == 4
    # render shows no report above: its own words (the run's review, round 1, m1).
    assert (
        err == "The PDF could not be saved in this folder: No such file or directory.\n  missing\n"
    )
    assert "shown above" not in err
    assert mac.ran == []


def test_a_signal_during_the_save_saves_nothing_and_exits_130(capsys, mac, tmp_path, monkeypatch):
    real = writer._write_all

    def interrupted(*args, **kwargs):  # type: ignore[no-untyped-def]
        os.kill(os.getpid(), signal.SIGINT)
        return real(*args, **kwargs)

    monkeypatch.setattr(writer, "_write_all", interrupted)
    code, _, err = go(capsys, str(report_file(tmp_path, saved())))
    assert (code, err) == (130, f"{run.STOPPED}\n")
    assert list(mac.desktop.iterdir()) == [] and mac.opened == []


@pytest.mark.parametrize(
    "setup", ["--no-open", "SSH_CONNECTION", "SSH_TTY"], ids=["--no-open", "SSH", "SSH_TTY"]
)
def test_no_open_with_no_open_or_over_ssh(capsys, mac, tmp_path, monkeypatch, setup):
    argv = [str(report_file(tmp_path, saved()))]
    if setup.startswith("--"):
        argv.append(setup)
    else:
        monkeypatch.setenv(setup, "10.0.0.2 50000 10.0.0.1 22")
    code, out, _ = go(capsys, *argv)
    assert code == 0
    assert mac.ran == [] and out.endswith(f"Saved: ~/Desktop/{PDF_NAME}\n")


def test_a_pdf_that_cannot_be_drawn_exits_4_with_nothing_saved(capsys, mac, tmp_path, monkeypatch):
    def broken(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise RuntimeError("a bug")

    monkeypatch.setattr(report_pdf, "render", broken)
    code, out, err = go(capsys, str(report_file(tmp_path, saved())))
    assert (code, out, err) == (4, "", f"{run.RENDER_PDF_BUG}\n")
    assert list(mac.desktop.iterdir()) == []


# --- what render refuses -------------------------------------------------------------------------


def test_a_report_it_cannot_validate_names_the_field_never_the_value(capsys, mac, tmp_path):
    document = copy.deepcopy(r.load("m5-laptop"))
    document["time_zone"] = "Secret/Value\u202e"
    report_file(tmp_path, canonical.canonical_json(document).encode())
    code, out, err = go(capsys, "report.json")
    assert (code, out) == (2, "")  # a refusal goes to stderr alone
    # The field on a line of its own, above the file (the copy pass's review, round 2, m2),
    # and the problem below a line that gives it its subject (round 3, n1).
    assert err == (
        "Could not render this file. The field below is wrong:\n"
        "a control, separator, bidirectional or surrogate character.\n"
        "  time_zone\n  report.json\n"
    )
    assert "Secret" not in err
    assert list(mac.desktop.iterdir()) == [] and mac.ran == []


@pytest.mark.parametrize(
    ("data", "said"),
    [
        (b"{", "Could not render this file: not well-formed JSON.\n"),
        (b"[]", "Could not render this file: the top level is not an object.\n"),
        (
            b'{"a": 1, "a": 2}',
            "Could not render this file. The field below is wrong:\na duplicate key.\n  a\n",
        ),
    ],
    ids=["not JSON", "not an object", "a duplicate key"],
)
def test_a_file_that_is_not_a_report_exits_2(capsys, mac, tmp_path, data, said):
    report_file(tmp_path, data)
    code, _, err = go(capsys, "report.json")
    assert code == 2
    # A problem at a field names it on a line of its own, above the file (the copy pass's
    # review, round 2, m2), below a line that gives the problem its subject (round 3, n1).
    assert err == f"{said}  report.json\n"


def test_a_report_whose_id_does_not_recompute_exits_2(capsys, mac, tmp_path):
    document = copy.deepcopy(r.load("m5-laptop"))
    document["report_id"] = "sha256:" + "0" * 64
    code, _, err = go(
        capsys, str(report_file(tmp_path, canonical.canonical_json(document).encode()))
    )
    assert code == 2
    assert "report_id" in err


def test_a_file_past_4_mib_is_refused_without_being_read_whole(capsys, mac, tmp_path, monkeypatch):
    path = tmp_path / "big.json"
    with path.open("wb") as stream:
        stream.truncate(64 * 1024 * 1024)  # sparse: 64 MiB of zeros
    real = os.read
    taken: list[int] = []

    def read(descriptor, count):  # type: ignore[no-untyped-def]
        data = real(descriptor, count)
        taken.append(len(data))
        return data

    monkeypatch.setattr(os, "read", read)
    code, _, err = go(capsys, str(path))
    assert code == 2
    assert sum(taken) == canonical.MAX_BYTES + 1
    assert "larger than the 4 MiB limit" in err


@pytest.mark.parametrize("kind", ["missing", "a folder", "a FIFO"])
def test_a_path_that_is_not_a_readable_file_exits_2(capsys, mac, tmp_path, kind):
    path = tmp_path / "report.json"
    if kind == "a folder":
        path.mkdir()
    elif kind == "a FIFO":
        os.mkfifo(path)  # opened without waiting, so this never blocks
    code, out, err = go(capsys, "report.json")
    assert (code, out) == (2, "")
    reason = os.strerror(errno.ENOENT) if kind == "missing" else run.NOT_A_FILE
    assert err == f"Could not read this file: {reason}.\n  report.json\n"
    assert mac.ran == []


def test_a_path_is_printed_through_the_display_path_function(capsys, mac, tmp_path):
    code, _, err = go(capsys, "evil\x1b[2J.json")
    assert code == 2
    assert "evil\\x1b[2J.json" in err and "\x1b" not in err


def test_render_never_collects(capsys, mac, tmp_path, monkeypatch):
    def refused(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise AssertionError("render collects nothing")

    monkeypatch.setattr(run, "collect", refused)
    code, _, _ = go(capsys, str(report_file(tmp_path, saved())), "--no-open")
    assert code == 0 and mac.ran == []


def test_the_render_words_have_no_dash():
    for text in (run.BOTH_VERSIONS, run.RENDER_REFUSED, run.UNREADABLE, run.NOT_A_FILE):
        assert chr(0x2013) not in text and chr(0x2014) not in text


# --- the run's review, round 1 --------------------------------------------------------------


def test_a_pdf_render_cannot_draw_asks_for_a_report_without_the_runs_flag(
    capsys, mac, tmp_path, monkeypatch
):
    # render has no --debug, so its line never points at it (m1).
    def broken(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise RuntimeError("a bug")

    monkeypatch.setattr(report_pdf, "render", broken)
    report_file(tmp_path, saved())
    code, out, err = go(capsys, "report.json")
    assert (code, out) == (4, "")
    assert err == f"{run.RENDER_PDF_BUG}\n" and "--debug" not in err


@pytest.mark.parametrize("when", ["during the save", "after the save"])
def test_a_bug_in_renders_save_or_open_is_named_by_a_fixed_line(
    capsys, mac, tmp_path, monkeypatch, when
):
    # m2 and m3: never a traceback, and never "nothing was saved" once it was.
    def broken(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise RuntimeError("a bug")

    monkeypatch.setattr(
        writer if when == "during the save" else run,
        "save" if when == "during the save" else "_open",
        broken,
    )
    report_file(tmp_path, saved())
    code, _, err = go(capsys, "report.json")
    if when == "during the save":
        assert (code, err) == (4, f"{run.RENDER_UNEXPECTED}\n")
    else:
        assert (code, err) == (1, f"{run.RENDER_SAVED_THEN_UNEXPECTED}\n")
    assert "a bug" not in err


@pytest.mark.parametrize("signum", run.SIGNALS)
def test_a_signal_while_render_reads_a_file_that_stalls_stops_it_at_once(
    capsys, mac, tmp_path, monkeypatch, signum
):
    # m7: a read that stalls on a slow or dead volume stops at once, since nothing is saved
    # yet, where a signal that only set the flag would wait on the read. SIGTERM and SIGHUP
    # do the same, where they once ended the process (the pre-audit of pass 3, 05).
    real = run._read_report
    main = threading.main_thread().ident
    assert main is not None

    def stalled(path):  # type: ignore[no-untyped-def]
        timer = threading.Timer(0.2, signal.pthread_kill, (main, signum))
        timer.start()
        try:
            select.select([], [], [], 5)  # the read, stalled; the signal comes into it
        finally:
            timer.cancel()
        return real(path)

    monkeypatch.setattr(run, "_read_report", stalled)
    report_file(tmp_path, saved())
    started = time.monotonic()
    code, out, err = command(capsys, "render", "report.json")
    assert (code, out, err) == (130, "", f"{run.STOPPED}\n")
    assert time.monotonic() - started < 4, "stopped at once, never after the stall"
    assert list(mac.desktop.iterdir()) == [] and mac.ran == []


@pytest.mark.parametrize("signum", run.SIGNALS)
def test_a_signal_as_render_draws_the_pdf_stops_it(capsys, mac, tmp_path, monkeypatch, signum):
    real = render.render

    def drawn(data):  # type: ignore[no-untyped-def]
        os.kill(os.getpid(), signum)
        return real(data)

    monkeypatch.setattr(render, "render", drawn)
    report_file(tmp_path, saved())
    code, out, err = command(capsys, "render", "report.json")
    assert (code, out, err) == (130, "", f"{run.STOPPED}\n")
    assert list(mac.desktop.iterdir()) == [] and mac.ran == []


def test_a_signal_once_render_has_saved_opens_nothing_and_says_so_in_its_words(
    capsys, mac, tmp_path, monkeypatch
):
    # The run's "Your report is saved" is render's "The PDF is saved" (the copy pass).
    real = run._named

    def named(saved, local):  # type: ignore[no-untyped-def]
        real(saved, local)
        os.kill(os.getpid(), signal.SIGINT)

    monkeypatch.setattr(run, "_named", named)
    report_file(tmp_path, saved())
    code, out, err = go(capsys, "report.json")
    assert code == 130
    assert run.OPENING not in out and mac.opened == []
    assert err == f"{run.RENDER_STOPPED_SAVED}\n"
    assert len(list(mac.desktop.iterdir())) == 1


# Change record 10 (the GPT audit, pass 1, G1-09): render's save, like the run's, is complete
# when the output writer's last read of the flag passes.


def test_a_signal_just_before_renders_pdf_is_linked_saves_nothing(
    capsys, mac, tmp_path, monkeypatch
):
    real = writer._publish

    def publish(folder_fd, temporary, final):  # type: ignore[no-untyped-def]
        os.kill(os.getpid(), signal.SIGINT)
        return real(folder_fd, temporary, final)

    monkeypatch.setattr(writer, "_publish", publish)
    report_file(tmp_path, saved())
    code, out, err = go(capsys, "report.json")
    assert (code, err) == (130, f"{run.STOPPED}\n")
    assert "Saved:" not in out and list(mac.desktop.iterdir()) == [] and mac.ran == []


def test_a_signal_once_renders_save_is_complete_keeps_the_pdf_and_opens_nothing(
    capsys, mac, tmp_path, monkeypatch
):
    real = writer._named

    def named(folder_fd, path):  # type: ignore[no-untyped-def]
        if (mac.desktop / PDF_NAME).exists():  # the writer's last step, after its last read
            os.kill(os.getpid(), signal.SIGINT)
        return real(folder_fd, path)

    monkeypatch.setattr(writer, "_named", named)
    report_file(tmp_path, saved())
    code, out, err = go(capsys, "report.json")
    assert (code, err) == (130, f"{run.RENDER_STOPPED_SAVED}\n")
    assert f"Saved: ~/Desktop/{PDF_NAME}\n" in out and mac.ran == []
    assert [path.name for path in mac.desktop.iterdir()] == [PDF_NAME]


def test_a_signal_as_renders_open_returns_still_stops_it(capsys, mac, tmp_path, monkeypatch):
    # The GPT audit, pass 2, G2-03: render read the flag for the last time before the open.
    real = spawn.Runner.run

    def ran(runner, command_id, **kwargs):  # type: ignore[no-untyped-def]
        found = real(runner, command_id, **kwargs)
        os.kill(os.getpid(), signal.SIGINT)
        return found

    monkeypatch.setattr(spawn.Runner, "run", ran)
    report_file(tmp_path, saved())
    code, out, err = go(capsys, "report.json")
    assert (code, err) == (130, f"{run.RENDER_STOPPED_OPENING}\n")
    assert out.endswith(f"Saved: ~/Desktop/{PDF_NAME}\n") and run.OPENING not in out
    assert [path.name for path in mac.desktop.iterdir()] == [PDF_NAME]
    assert mac.opened == [str(mac.desktop / PDF_NAME)]


def test_a_ctrl_c_while_render_reads_the_file_stops_it(capsys, mac, tmp_path, monkeypatch):
    def interrupted(path):  # type: ignore[no-untyped-def]
        raise KeyboardInterrupt

    monkeypatch.setattr(run, "_read_report", interrupted)
    try:
        code, out, err = go(capsys, "report.json")
    except KeyboardInterrupt:  # escaping, it would stop the whole test run
        pytest.fail("the Ctrl-C left render as it was")
    assert (code, out, err) == (130, "", f"{run.STOPPED}\n")


def test_a_report_drawn_by_another_renderer_names_both_on_the_terminal(capsys, mac, tmp_path):
    # n5: the same package version with another renderer gets the line too, as Appendix B's
    # note does.
    document = copy.deepcopy(r.load("m5-laptop"))
    document["tool"]["version"] = voltry_mac.__version__
    document["tool"]["renderer_version"] = "9999"
    report_file(tmp_path, canonical.canonical_json(r.rehash(document)).encode())
    code, out, _ = go(capsys, "report.json")
    assert code == 0
    line = (
        f"This report was made by voltry-mac {voltry_mac.__version__}, renderer 9999; this PDF"
        f" is drawn by voltry-mac {voltry_mac.__version__}, renderer {report_pdf.RENDERER}, so"
        " it may differ from the original PDF."
    )
    # At 80 columns, at the last space that fits: where depends on the version's length, so
    # 0.1.0.dev0 breaks before "by" and 0.1.0 after it.
    cut = line.rindex(" ", 0, 81)
    both = f"{line[:cut]}\n{line[cut + 1 :]}"
    assert len(line[cut + 1 :]) <= 80
    assert f"\n\n{both}\n\n" in out


def test_render_closes_the_file_it_read(capsys, mac, tmp_path):
    report_file(tmp_path, saved())
    before = len(os.listdir("/dev/fd"))
    go(capsys, "report.json")
    assert len(os.listdir("/dev/fd")) == before


# --- the run's review, round 2 --------------------------------------------------------------


def test_a_ctrl_c_then_a_folder_refused_stops_render(capsys, mac, tmp_path, monkeypatch):
    # m12: as in the run, a Ctrl-C at the folder's permission prompt, then Don't Allow, is a
    # stop: 130 comes before 4.
    guarded = tmp_path / "Documents"
    guarded.mkdir()
    real = writer._open_folder

    def asked(path):  # type: ignore[no-untyped-def]
        if path == str(guarded):
            os.kill(os.getpid(), signal.SIGINT)
            raise PermissionError(errno.EPERM, os.strerror(errno.EPERM))
        return real(path)

    monkeypatch.setattr(writer, "_open_folder", asked)
    report_file(tmp_path, saved())
    code, _, err = go(capsys, "report.json", "--output", str(guarded))
    assert (code, err) == (130, f"{run.STOPPED}\n")
    assert list(guarded.iterdir()) == [] and mac.ran == []


@pytest.mark.parametrize("when", ["during the save", "after the save"])
def test_a_ctrl_c_then_a_bug_in_renders_save_exits_130(capsys, mac, tmp_path, monkeypatch, when):
    # m12: a cancellation outranks a bug, as in the run; the line still says whether the PDF
    # was saved.
    def broken(*args, **kwargs):  # type: ignore[no-untyped-def]
        os.kill(os.getpid(), signal.SIGINT)
        raise RuntimeError("a bug")

    if when == "during the save":
        monkeypatch.setattr(writer, "_write_all", broken)
    else:
        real = run._named

        def named(files, local):  # type: ignore[no-untyped-def]
            real(files, local)
            broken()

        monkeypatch.setattr(run, "_named", named)
    report_file(tmp_path, saved())
    code, _, err = go(capsys, "report.json")
    line = run.STOPPED if when == "during the save" else run.RENDER_SAVED_THEN_UNEXPECTED
    assert (code, err) == (130, f"{line}\n")
    assert mac.opened == []
    assert [p.name for p in mac.desktop.iterdir()] == (
        [] if when == "during the save" else [PDF_NAME]
    )


@pytest.mark.parametrize("signum", run.SIGNALS)
def test_a_signal_between_renders_draw_and_its_save_stops_it(
    capsys, mac, tmp_path, monkeypatch, signum
):
    # n17: a signal between the draw and the save is a stop too, never a traceback: the save
    # reads the flag before it writes.
    real = run._say

    def said(text: str = "", end: str = "\n") -> None:
        real(text, end)
        if text == console.HEADER:
            os.kill(os.getpid(), signum)

    monkeypatch.setattr(run, "_say", said)
    report_file(tmp_path, saved())
    code, out, err = command(capsys, "render", "report.json")
    assert (code, err) == (130, f"{run.STOPPED}\n")
    assert out.startswith(console.HEADER) and "Saved:" not in out
    assert list(mac.desktop.iterdir()) == [] and mac.ran == []


def test_an_open_a_stop_came_before_or_cut_short_says_so_in_renders_words(
    capsys, mac, tmp_path, monkeypatch
):
    # The GPT audit, pass 1, G1-01: render's side of the run's test.
    def execute(argv, **kwargs):  # type: ignore[no-untyped-def]
        command_id = kwargs["command_id"]
        mac.ran.append(command_id)
        return spawn.Result(command_id, spawn.Ending.CANCELLED, None, "", "", 0, False, True)

    monkeypatch.setattr(spawn, "_execute", execute)
    report_file(tmp_path, saved())
    code, out, err = go(capsys, "report.json")
    assert code == 130 and run.OPENING not in out
    assert err == f"{run.RENDER_STOPPED_OPENING}\n"
    assert len(list(mac.desktop.iterdir())) == 1


def test_a_stop_just_before_renders_open_says_the_pdf_was_not_opened(
    capsys, mac, tmp_path, monkeypatch
):
    # The review of #326, round 1, N3: render's side of the run's test.
    real = spawn.Runner.published

    def published(runner, path):  # type: ignore[no-untyped-def]
        real(runner, path)
        os.kill(os.getpid(), signal.SIGINT)

    monkeypatch.setattr(spawn.Runner, "published", published)
    report_file(tmp_path, saved())
    code, out, err = go(capsys, "report.json")
    assert code == 130 and "O1" not in mac.ran and run.OPENING not in out
    assert err == f"{run.RENDER_STOPPED_SAVED}\n"
    assert len(list(mac.desktop.iterdir())) == 1


# --- the review of #326, round 2 -----------------------------------------------------------------


def _home_through_a_link(monkeypatch, tmp_path) -> Path:  # type: ignore[no-untyped-def]
    """The home folder, as the account database names it, is a symlink, tmp_path/Users/jane,
    to the folder itself, tmp_path/Data/jane, which this returns (made-up names)."""
    itself = tmp_path / "Data" / "jane"
    (itself / "Documents").mkdir(parents=True)
    home = tmp_path / "Users" / "jane"
    home.parent.mkdir()
    home.symlink_to(itself)
    monkeypatch.setattr(writer, "home", lambda: str(home))
    return itself


@pytest.mark.parametrize("kind", ["missing", "the folder itself", "refused"])
def test_a_report_path_in_a_home_folder_reached_through_a_symlink_prints_with_a_tilde(
    capsys, mac, tmp_path, monkeypatch, kind
):
    # m1 and n8: the path names the folder itself, not the link the account database names,
    # and the file system finds the home folder in it all the same.
    itself = _home_through_a_link(monkeypatch, tmp_path)
    if kind == "missing":
        path, shown = itself / "Documents" / "missing.json", "~/Documents/missing.json"
    elif kind == "the folder itself":
        path, shown = itself, "~"
    else:
        path, shown = report_file(itself / "Documents", b"{"), "~/Documents/report.json"
    code, out, err = go(capsys, str(path))
    assert (code, out) == (2, "")
    assert err.endswith(f"\n  {shown}\n") and str(itself) not in err


def test_render_saves_in_a_home_folder_reached_through_a_symlink_and_prints_a_tilde(
    capsys, mac, tmp_path, monkeypatch
):
    itself = _home_through_a_link(monkeypatch, tmp_path)
    path = report_file(tmp_path, saved())
    monkeypatch.chdir(itself)
    code, out, err = go(capsys, str(path), "--output", ".")
    assert (code, err) == (0, "")
    assert out.endswith(f"Saved: ~/{PDF_NAME}\n{run.OPENING}\n")
    assert [p.name for p in itself.iterdir() if p.suffix == ".pdf"] == [PDF_NAME]


# --- the GPT audit, pass 2, G2-03 ----------------------------------------------------------------
#
# render's side of the run's tests: a signal on every path of the open, once render's read of
# the flag just after the save's lines has passed, and while a real child stands in for O1,
# stops render in its own words.

# The real chokepoint, before the fixture stands in for it: a test-owned /bin/sleep stands in
# for O1, never /usr/bin/open.
_REAL_EXECUTE = spawn._execute
_REAL_POPEN = spawn._popen
OPEN_PATHS = {
    "--no-open": run.RENDER_STOPPED_SAVED,
    "over SSH": run.RENDER_STOPPED_SAVED,
    "a refused open": run.RENDER_STOPPED_SAVED,
    "an open that could not start": run.RENDER_STOPPED_SAVED,
    "an open that failed": run.RENDER_STOPPED_OPENING,
    "an open that finished": run.RENDER_STOPPED_OPENING,
    "after the open": run.RENDER_STOPPED_OPENING,
}
_ENDINGS = {
    "an open that could not start": (spawn.Ending.NOT_STARTED, None),
    "an open that failed": (spawn.Ending.EXITED, 1),
    "an open that finished": (spawn.Ending.EXITED, 0),
}


@pytest.mark.parametrize("signum", run.SIGNALS)
@pytest.mark.parametrize("path", list(OPEN_PATHS))
def test_a_signal_on_every_path_of_renders_open_stops_it(
    capsys, mac, tmp_path, monkeypatch, path, signum
):
    def send() -> None:
        os.kill(os.getpid(), signum)

    argv = ["report.json"]
    if path in ("--no-open", "after the open"):
        real = run._open

        def opened(*args, **kwargs):  # type: ignore[no-untyped-def]
            stopped = real(*args, **kwargs)
            send()
            return stopped

        monkeypatch.setattr(run, "_open", opened)
        if path == "--no-open":
            argv.append("--no-open")
    elif path == "over SSH":
        monkeypatch.setattr(run, "_ssh", lambda: send() or True)
    elif path == "a refused open":

        def refused(runner, pdf):  # type: ignore[no-untyped-def]
            send()
            raise spawn.Refused("the published report cannot be read")

        monkeypatch.setattr(spawn.Runner, "published", refused)
    else:
        ending, code = _ENDINGS[path]

        def execute(argv, **kwargs):  # type: ignore[no-untyped-def]
            mac.ran.append(kwargs["command_id"])
            send()  # while O1 runs, in the pass that collects its end
            return spawn.Result("O1", ending, code, "", "", 20, False, True)

        monkeypatch.setattr(spawn, "_execute", execute)
    report_file(tmp_path, saved())
    code, out, err = go(capsys, *argv)
    assert (code, err) == (130, f"{OPEN_PATHS[path]}\n")
    assert [each.name for each in mac.desktop.iterdir()] == [PDF_NAME]
    opened = path == "after the open"
    assert out.endswith(f"{run.OPENING}\n" if opened else f"Saved: ~/Desktop/{PDF_NAME}\n")
    assert (mac.ran == ["O1"]) == (path.startswith("an open that") or opened)


@pytest.mark.parametrize("signum", run.SIGNALS)
@pytest.mark.parametrize("both", [True, False], ids=["the open and render", "render alone"])
def test_a_signal_while_a_real_open_runs_stops_render(
    capsys, mac, tmp_path, monkeypatch, signum, both
):
    # /bin/sleep 5 stands in for O1 under the real chokepoint. A terminal's Ctrl-C or hang-up
    # reaches both and ends the open at once; a script's kill reaches render alone, and the
    # chokepoint stops the open.
    children: list[subprocess.Popen[bytes]] = []

    def popen(argv):  # type: ignore[no-untyped-def]
        assert argv == ["/bin/sleep", "5"], "never /usr/bin/open"
        child = _REAL_POPEN(argv)
        children.append(child)
        if both:
            child.send_signal(signum)
            child.wait(5)
        os.kill(os.getpid(), signum)
        return child

    def execute(argv, **kwargs):  # type: ignore[no-untyped-def]
        assert kwargs["command_id"] == "O1"
        return _REAL_EXECUTE(["/bin/sleep", "5"], **kwargs)

    monkeypatch.setattr(spawn, "_popen", popen)
    monkeypatch.setattr(spawn, "_execute", execute)
    report_file(tmp_path, saved())
    started = time.monotonic()
    code, out, err = go(capsys, "report.json")
    assert (code, err) == (130, f"{run.RENDER_STOPPED_OPENING}\n")
    assert run.OPENING not in out and len(list(mac.desktop.iterdir())) == 1
    (child,) = children
    assert child.returncode == -(signum if both else signal.SIGTERM)
    assert time.monotonic() - started < 4, "stopped at once, never at its 5 s"


def test_a_pdf_whose_temporary_stays_is_saved_and_render_says_why_it_did_not_open(
    capsys, mac, tmp_path, monkeypatch
):
    # Change record 21: render's side of the run's test. Its temporary is a second name for
    # the PDF, so the open is refused, and render says why after naming the file.
    real = writer._unlink

    def unlink(folder_fd, name):  # type: ignore[no-untyped-def]
        if name.startswith(".voltry-mac-"):
            raise PermissionError(errno.EPERM, os.strerror(errno.EPERM))
        real(folder_fd, name)

    monkeypatch.setattr(writer, "_unlink", unlink)
    report_file(tmp_path, saved())
    code, out, err = go(capsys, "report.json")
    (left,) = [path.name for path in mac.desktop.iterdir() if path.name.startswith(".voltry")]
    assert (code, err) == (0, f"{run.LEFT_ONE}\n  ~/Desktop/{left}\n{run.SECOND_NAME}\n")
    assert out.endswith(f"Saved: ~/Desktop/{PDF_NAME}\n") and mac.ran == []


# --- the audit fixes' review, round 3, and the pre-audit of pass 3 ----------------------------
#
# render's side of the run's tests: an exit that saves nothing reads the flag after it says
# why, a refusal keeps its code and words, and a signal once render has read the flag for the
# last time changes nothing, never a traceback or the end of the process.

# How each reason starts, on its first line whatever its wrapping.
NOT_SAVED = {
    "a folder that is not there": run.RENDER_NOT_SAVED_IN.split(":")[0],
    "a full disk": run.RENDER_NOT_SAVED.split(":")[0] + ":",
    "a PDF that cannot be drawn": run.RENDER_PDF_BUG.split(".")[0],
    "an unexpected error before the save": run.RENDER_UNEXPECTED.split(".")[0],
}


def _broken(*args: object, **kwargs: object) -> object:
    raise RuntimeError("a bug")


def _full(*args: object, **kwargs: object) -> object:
    raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))


def _saving_nothing(monkeypatch: pytest.MonkeyPatch, path: str) -> list[str]:
    """render's arguments, with render set to save nothing on one path."""
    argv = ["render", "report.json"]
    if path == "a folder that is not there":
        argv += ["--output", "missing"]
    elif path == "a full disk":
        monkeypatch.setattr(writer, "_write_all", _full)
    elif path == "a PDF that cannot be drawn":
        monkeypatch.setattr(render, "render", _broken)
    else:
        monkeypatch.setattr(writer, "save", _broken)
    return argv


@pytest.mark.parametrize("signum", run.SIGNALS)
@pytest.mark.parametrize("path", list(NOT_SAVED))
def test_a_signal_as_render_says_why_nothing_was_saved_stops_it(
    capsys, mac, tmp_path, monkeypatch, path, signum
):
    # The pre-audit of pass 3, 01: 130 comes before 4, so the stop line follows the reason.
    argv = _saving_nothing(monkeypatch, path)
    real = run._tell

    def told(text: str) -> None:
        if text.startswith(NOT_SAVED[path]):
            os.kill(os.getpid(), signum)  # as the reason prints
        real(text)

    monkeypatch.setattr(run, "_tell", told)
    report_file(tmp_path, saved())
    code, _, err = command(capsys, *argv)
    assert code == 130 and err.startswith(NOT_SAVED[path])
    assert err.endswith(f"\n{run.STOPPED}\n") and err.count("Stopped.") == 1
    assert list(mac.desktop.iterdir()) == [] and mac.ran == []


@pytest.mark.parametrize("path", list(NOT_SAVED))
def test_with_no_signal_render_that_saves_nothing_exits_4(capsys, mac, tmp_path, monkeypatch, path):
    argv = _saving_nothing(monkeypatch, path)
    report_file(tmp_path, saved())
    code, _, err = command(capsys, *argv)
    assert code == 4 and err.startswith(NOT_SAVED[path]) and "Stopped" not in err


@pytest.mark.parametrize("signum", run.SIGNALS)
@pytest.mark.parametrize("name", ["missing.json", "report.json"], ids=["missing", "not JSON"])
def test_a_signal_as_render_refuses_a_file_leaves_its_code_and_its_words(
    capsys, mac, tmp_path, monkeypatch, name, signum
):
    # 2 comes before 130 (Failure modes, the exit codes), so the refusal stands and no stop
    # line follows it.
    report_file(tmp_path, b"{")
    expected = command(capsys, "render", name)
    real = run._tell

    def told(text: str) -> None:
        os.kill(os.getpid(), signum)  # as the refusal prints
        real(text)

    monkeypatch.setattr(run, "_tell", told)
    assert command(capsys, "render", name) == expected
    assert expected[0] == 2 and "Stopped" not in expected[2]


@pytest.mark.parametrize("signum", run.SIGNALS)
def test_a_signal_once_render_has_ended_changes_nothing(capsys, mac, tmp_path, monkeypatch, signum):
    # After render's last read, in the moments before the tool exits, a signal is not reported
    # (change record 10): render's own code, no stop line, no traceback; and all three are
    # ignored from then until the process ends.
    real = run.rebuild

    def rebuilt(args):  # type: ignore[no-untyped-def]
        code = real(args)
        os.kill(os.getpid(), signum)
        return code

    monkeypatch.setattr(run, "rebuild", rebuilt)
    report_file(tmp_path, saved())
    code, out, err = command(capsys, "render", "report.json")
    assert (code, err) == (0, "")
    assert out.endswith(f"Saved: ~/Desktop/{PDF_NAME}\n{run.OPENING}\n")
    assert [signal.getsignal(each) for each in run.SIGNALS] == [signal.SIG_IGN] * 3
