"""The collecting run, from the header to the saved report and its one open, and render.

docs/VOLTRY_MAC_SPEC.md, "CLI transcripts" 1, 2, 4 and 5; Decision 2's sequence and "What
the owner sees before sudo asks"; Decision 4's render rules; Decision 5; Decision 7's
validated configurations; Failure modes and the exit codes; the Architecture's run order.

A collecting run, once the preflight has passed: the 27 user reads and the panic count
(R1), timed on one line; Voltry's explanation and the question when the elevated path
applies, then the elevation broker, with a line for each payload; the terminal summary;
the PDF, and the JSON when asked for; the save; the open, once, unless --no-open or over
SSH. The exit code is the first of 130, 4, 6, 1 and 0 that applies; the preflight's 5 and
3, and 2 for bad arguments, come before the run.

``voltry-mac render REPORT.json`` reads a saved report with the 4 MiB cap, at most one byte
past it and only from a regular file, draws it with render.render, says in one line when
another version made it, and saves and opens it by the same rules. It collects nothing,
and a file it cannot read or render exits 2.

From the start of the command, SIGINT, SIGTERM and SIGHUP only set the cancellation flag,
but for render's read and draw, which one stops at once. Every cleanup, the final sudo -k
included, runs in ordinary control flow. A signal once the report is saved keeps it and
still stops the run, until the run's last read of the flag, the last step of every exit;
after that read all three are ignored until the process ends. The report goes to stdout; a
failure, a warning or a file to delete goes to stderr. No message carries a command's
output or an error's text: an unexpected error is named by a fixed line. A path prints
through the display path, with the home folder as ~ wherever the file system finds it in
the path, or, when it cannot look the home folder up, where the path spells it exactly.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import os
import select
import stat
import sys
import termios
import textwrap
import time
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from typing import Final

from voltry_mac import (
    __version__,
    allowlist,
    appendices,
    assemble,
    availability,
    canonical,
    console,
    elevation,
    in_process,
    manifests,
    model,
    preflight,
    render,
    report_pdf,
    signals,
    spawn,
    terminal,
    tracking,
    validate,
    writer,
)

# The words, from the spec's transcripts, Decision 2 and the failure rows.
BLURB: Final = (
    "Reads system information without changing any setting. Voltry sends\n"
    "nothing over the network and creates only the report files you ask for."
)
READING: Final = "Reading this Mac..."
EXPLANATION: Final = (
    "The rest of the report needs administrator access for two read-only\n"
    "steps:\n"
    "\n"
    "  1. Count the memory errors macOS has recorded.\n"
    "     Runs /usr/bin/sqlite3 on one Apple database, read-only, as\n"
    "     macOS's own memory-maintenance account rather than as root,\n"
    "     inside a sandbox that forbids writing any file.\n"
    "  2. Measure processor power and thermal pressure for 5 seconds.\n"
    "     Runs /usr/bin/powermetrics as root, read-only, inside the same\n"
    "     kind of sandbox.\n"
    "\n"
    "Nothing else runs with administrator access. Voltry clears it right\n"
    "after these two reads and warns you if that fails. If you say no,\n"
    "you still get the report; these two items will say they need\n"
    "administrator access."
)
QUESTION: Final = "Allow these two administrator reads? [y/N] "
COUNTING: Final = "Reading memory error records..."
SAMPLING: Final = "Measuring power and thermal pressure for 5 seconds..."
DONE: Final = " done"
NOT_READ: Final = " not read"
CLEARED: Final = "Administrator access cleared."
SKIPPING: Final = "Skipping the two administrator reads."
WARNING: Final = "WARNING: administrator access could not be cleared. Run: sudo -k"
FULL_REPORT: Final = (
    "The full report, with Appendix A (everything tried) and Appendix B\n"
    "(how it was made), is in the PDF."
)
DESKTOP: Final = (
    "macOS may ask whether your terminal app can use your Desktop folder.\n"
    "Choose Allow to save the report there."
)
FALLBACK_BEFORE: Final = (
    "macOS did not let your terminal app use your Desktop folder, so the\n"
    "report was saved at the top of your home folder instead:"
)
FALLBACK_AFTER: Final = (
    "To use the Desktop next time: System Settings, Privacy and Security,\n"
    "Files and Folders, then allow Desktop Folder for your terminal app."
)
RENAMED: Final = "A report named for {time} was already there. It was not changed."
OPENING: Final = "Opening it in your PDF viewer."
STOPPED: Final = "Stopped. Nothing was saved."
NOT_ENOUGH: Final = (
    "Could not read enough of this Mac to make a report, so no report file was written."
)
ANSWERED: Final = "These items did answer: {items}."
NONE_ANSWERED: Final = "No item answered."
NOT_SAVED: Final = "Your report is shown above but could not be saved: {reason}."
# A path the message names stands on a line of its own, as the Desktop fallback prints it,
# so wrapping at 80 columns never splits one.
NOT_SAVED_IN: Final = (
    "Your report is shown above but could not be saved in this folder: {reason}.\n  {folder}"
)
NO_FOLDER: Final = "--output names no folder"
# The Desktop refused, then the move to the home folder failed too: the owner chose neither
# folder, so the line says why both were tried (the copy pass's review, round 1, n4).
NOT_SAVED_HOME: Final = (
    "macOS did not let your terminal app use your Desktop folder, and the report could not "
    "be saved at the top of your home folder either: {reason}."
)
PDF_BUG: Final = "Could not create the PDF. Please report this with voltry-mac --debug"
UNEXPECTED: Final = (
    "Could not finish the report because of an unexpected error. Nothing was saved.\n"
    "Please report this with voltry-mac --debug"
)
SAVED_THEN_UNEXPECTED: Final = (
    "Your report was saved, but the run then stopped on an unexpected error.\n"
    "Please report this with voltry-mac --debug"
)
STOPPED_SAVED: Final = "Stopped. Your report is saved, and was not opened."
STOPPED_OPENING: Final = "Stopped. Your report is saved; it may not have opened."
# The PDF's temporary, named just above among the files this run could not remove, is a
# second name for the PDF, so the open is refused; the run and render both say why (change
# record 21).
SECOND_NAME: Final = "The PDF was not opened: its temporary file above is another name for it."
LEFT_ONE: Final = "This run could not remove a file it made. It is safe to delete:"
LEFT_MANY: Final = "This run could not remove files it made. They are safe to delete:"
# render's own words: Failure modes' "A line naming both versions", naming the renderers as
# Appendix B's note does, and its refusals. render shows no report and has no --debug, so it
# never borrows the run's lines for those (the run's review, round 1).
BOTH_VERSIONS: Final = (
    "This report was made by voltry-mac {made}, renderer {made_renderer}; this PDF is drawn "
    "by voltry-mac {drawn}, renderer {drawn_renderer}, so it may differ from the original PDF."
)
RENDER_NOT_SAVED: Final = "The PDF could not be saved: {reason}."
RENDER_NOT_SAVED_IN: Final = "The PDF could not be saved in this folder: {reason}.\n  {folder}"
RENDER_NOT_SAVED_HOME: Final = (
    "macOS did not let your terminal app use your Desktop folder, and the PDF could not be "
    "saved at the top of your home folder either: {reason}."
)
RENDER_PDF_BUG: Final = "Could not draw the PDF. Please report this."
RENDER_UNEXPECTED: Final = (
    "Could not save the PDF because of an unexpected error. Nothing was saved.\n"
    "Please report this."
)
RENDER_SAVED_THEN_UNEXPECTED: Final = (
    "The PDF was saved, but render then stopped on an unexpected error.\nPlease report this."
)
RENDER_STOPPED_SAVED: Final = "Stopped. The PDF is saved, and was not opened."
RENDER_STOPPED_OPENING: Final = "Stopped. The PDF is saved; it may not have opened."
RENDER_REFUSED: Final = "Could not render this file: {problem}.\n  {path}"
# A problem at a field names it on a line of its own too, above the file, so a long path or
# a key with spaces is never split (the copy pass's review, round 2, m2); the line before
# the problem gives it its subject (round 3, n1).
RENDER_REFUSED_AT: Final = (
    "Could not render this file. The field below is wrong:\n{problem}.\n  {field}\n  {path}"
)
UNREADABLE: Final = "Could not read this file: {reason}.\n  {path}"
NOT_A_FILE: Final = "it is not a file"

SIGNALS: Final = signals.SIGNALS  # the three that stop a run, and render
# Decision 7: the configurations validated for this release, by model identifier and macOS
# version, starting with the M5 MacBook Pro on macOS 26.6.2. Where later releases keep their
# lists, and how Appendix B prints them, waits on the owner (item 4 on #352).
VALIDATED: Final = frozenset({("Mac17,2", "26.6.2")})
_WIDTH: Final = 80
_POLL_S: Final = 0.1  # how often the question's wait checks the cancellation flag
_TOO_SOON_S: Final = 0.2  # a line sooner than this after the question was typed before it
_PAYLOAD_LINES: Final = {"S3": COUNTING, "S4": SAMPLING}
_UNVERIFIED: Final = "listing_failed"
# macOS's PATH_MAX (sys/syslimits.h): a path of this many bytes or more is refused with
# ENAMETOOLONG before anything is looked up.
_PATH_MAX: Final = 1024

# Seams for the tests: the clock that times the reads and the question's first moments, and
# local time as the C library gives it.
_monotonic = time.monotonic


def _local() -> datetime:
    return datetime.now().astimezone()


def _now() -> datetime:
    """The collection instant in local time. $TZ is set aside while it is read, so the offset
    follows /etc/localtime, the zone R2 names (the #355 review, N6)."""
    saved = os.environ.pop("TZ", None)
    time.tzset()
    try:
        return _local()
    finally:
        if saved is not None:
            os.environ["TZ"] = saved
            time.tzset()


def _answer(cancelled: Callable[[], bool]) -> str | None:
    """The first line typed once the question could be read, or None at the input's end or
    once the run is cancelled. The wait is a series of short selects, so a signal that only
    sets the flag still ends it, and what the terminal hands over is read as it comes: "y"
    ended with Ctrl-D is "y", never a wait for the rest of a line (the run's review, round
    1). What comes sooner than _TOO_SOON_S after the question, a line or a Ctrl-D, was on
    its way before anyone could read it, so it is dropped, and the wait goes on (round 2,
    m9)."""
    stream = sys.stdin
    if stream is None:
        return None
    try:
        descriptor = stream.fileno()
    except (OSError, ValueError):
        return None
    asked = _monotonic()
    while not cancelled():
        ready, _, _ = select.select([descriptor], [], [], _POLL_S)
        if ready:
            try:
                chunk = os.read(descriptor, 1024)
            except OSError:
                return None
            if _monotonic() - asked < _TOO_SOON_S:
                continue  # typed before the question could be read
            if not chunk:
                return None  # the input's end
            first, newline, _ = chunk.decode("utf-8", "replace").partition("\n")
            return first + newline
    return None


def _discard_typed() -> None:
    """Drop what was typed before the question, so only an answer given to it counts: an
    Enter pressed while the reads ran, or a pasted line (the run's review, round 1, M1).
    Nothing happens without a terminal."""
    stream = sys.stdin
    if stream is None:
        return
    with contextlib.suppress(OSError, ValueError, termios.error):
        descriptor = stream.fileno()
        if os.isatty(descriptor):
            termios.tcflush(descriptor, termios.TCIFLUSH)


def _stdout_terminal() -> bool:
    """Whether stdout is a terminal: the question and its explanation go there, so with it
    sent to a file there is no one to ask (the run's review, round 1)."""
    stream = sys.stdout
    try:
        return stream is not None and stream.isatty()
    except (OSError, ValueError):
        return False


def _say(text: str = "", end: str = "\n") -> None:
    console.write(sys.stdout, text + end)


def _warn(text: str) -> None:
    console.write(sys.stderr, text + "\n")


def _wrapped(text: str) -> str:
    """A message at 80 columns, as the terminal summary is set: each line longer than that
    wraps at spaces, never inside a word. An indented line, a path or a command, is left
    whole even past 80, so it copies and pastes whole (tests/test_copy.py names the kinds
    of line that are never wrapped)."""
    return "\n".join(
        (
            textwrap.fill(line, _WIDTH, break_long_words=False, break_on_hyphens=False)
            if len(line) > _WIDTH and not line.startswith(" ")
            else line
        )
        for line in text.split("\n")
    )


def _tell(text: str) -> None:
    _warn(_wrapped(text))


def _judged_by(command_id: str) -> Callable[[spawn.Result], bool]:
    """A user command's run is failed by the report's own rule, as its record must show."""

    def failed(result: spawn.Result) -> bool:
        return assemble.failed_run(command_id, result)

    return failed


def _ssh() -> bool:
    return bool(os.environ.get("SSH_CONNECTION") or os.environ.get("SSH_TTY"))


def _finished(run: spawn.PayloadRun) -> bool:
    """A payload that ended on its own with status 0; the report says whether its output
    could be read."""
    return run.started and run.forced is None and not run.cancelled and run.returncode == 0


def _payload_line(run: spawn.PayloadRun) -> str:
    """One --debug line for a payload: its ID, template, how it ended, how long it took and
    what the listing after it found. Never its output."""
    template = allowlist.display(allowlist.BY_ID[run.command_id].template)
    code = run.returncode
    if run.cancelled and not run.started:
        # The flag kept it from starting (the review of #326, round 1, M6): nothing ran and
        # no listing looked, so the line names no cleanup.
        return f"{run.command_id} {template}: cancelled, {run.duration_ms} ms"
    if not run.started:
        how = "could not start"
    elif run.forced is not None:
        how = spawn.PAYLOAD_FORCED[run.forced]
    elif run.cancelled or code is None:
        how = "cancelled"
    else:
        how = f"exit {code}" if code >= 0 else f"ended on signal {-code}"
    return f"{run.command_id} {template}: {how}, {run.duration_ms} ms, {run.cleanup}"


def _value(surfaces: Sequence[Mapping[str, object]], key: str, name: str) -> object:
    for surface in surfaces:
        values = surface["values"]
        if surface["key"] == key and isinstance(values, Mapping):
            entry = values.get(name)
            if isinstance(entry, Mapping) and entry["availability"] == "available":
                return entry["value"]
    return None


def _cleanup(record: Mapping[str, object], step: str) -> object:
    part = record[step]
    return part["cleanup"] if isinstance(part, Mapping) else None


def _validated(surfaces: Sequence[Mapping[str, object]]) -> bool:
    model_id = _value(surfaces, "hardware_overview", "machine_model")
    version = _value(surfaces, "os_version", "product_version")
    return (model_id, version) in VALIDATED


def _answered(surfaces: Sequence[Mapping[str, object]]) -> str:
    """The line that names what did answer; _tell wraps it, as every message."""
    names = [appendices.NAMES[str(s["key"])] for s in surfaces if s["availability"] == "available"]
    return ANSWERED.format(items=", ".join(names)) if names else NONE_ANSWERED


def _home() -> str:
    """The home folder for display paths, or nothing to shorten when there is none."""
    try:
        return writer.home()
    except writer.NotSaved:
        return ""


def _home_in(path: str, home: str, *, whole: bool) -> str:
    """The home folder as display_path is to find it in ``path``: the longest leading part
    of the path that the file system says is the home folder, by device and inode number,
    or nothing to shorten when no part is. So ~ stands wherever the volume finds the home
    folder, whatever case, form or spelling the path gives it (a symlink, /private,
    /System/Volumes/Data, // or a trailing /.) and whatever Unicode the volume matches
    names by, and a folder the volume keeps apart from it prints in full (the review of
    #326, round 2, m1 and n8). Only the home folder and the folders along the path are
    looked up, with stat, never opened or listed; so is the path itself when it may be a
    folder (``whole``). A part that cannot be looked up is not taken for the home folder:
    nothing is there, or the volume does not say. When the home folder itself cannot be
    looked up, only its own spelling is taken for it, name for name and exactly: a name in
    another case or Unicode form may be another folder, as it is on a case-sensitive volume
    (the GPT audit, pass 2, G2-05). A leading part of _PATH_MAX characters or more, so of
    at least as many bytes, is one macOS would refuse, so it is not looked up: a long
    argument costs no more lookups than a short one, where it once cost time in the square
    of its slashes (the audit fixes' review, round 3, n6)."""
    if not home:
        return ""
    try:
        own = os.stat(home)
    except OSError:
        return home if _spelled(path, home, whole=whole) else ""
    ends = [index for index, character in enumerate(path[:_PATH_MAX]) if character == "/"]
    if whole and len(path) < _PATH_MAX:
        ends.append(len(path))
    for end in reversed(ends):
        leading = path[:end]
        if not leading:
            continue  # the root, which display_path never shortens
        with contextlib.suppress(OSError):
            if os.path.samestat(os.stat(leading), own):
                return leading
    return ""


def _spelled(path: str, home: str, *, whole: bool) -> bool:
    """Whether the path's leading names are the home folder's as the account database spells
    them, every character the same; the path's own last name counts only when the path may
    be a folder (``whole``)."""
    parts, names = path.split("/"), home.rstrip("/").split("/")
    longer = len(parts) >= len(names) if whole else len(parts) > len(names)
    return longer and parts[: len(names)] == names


def _shown(path: str, *, whole: bool = False) -> str:
    """A path as the run and render print it: display_path, handed the home folder as the
    file system finds it in the path. ``whole`` when the path may itself be a folder: the
    folder a report could not be saved in, or the path render was handed."""
    return terminal.display_path(path, _home_in(path, _home(), whole=whole))


def display_argument(argument: str) -> str:
    """An argument a usage error names, shown as a folder the owner typed is: through the
    display path, with the home folder as ~ wherever the file system finds it, the argument
    itself included, since it may name a folder (the GPT audit, pass 2, G2-01)."""
    return _shown(argument, whole=True)


def _paper() -> str:
    """R3's paper, from the region of the owner's locale; A4 when there is no home folder."""
    try:
        home = writer.home()
    except writer.NotSaved:
        return "a4"
    return in_process.paper(home)


class _Progress:
    """How far the save and the open got, which decides what an error or a stop after the
    save says: whether the save has published the report, and whether O1 may have started
    (the chokepoint was handed it, and it did not fail to start)."""

    saved = False
    opening = False


class _Run:
    """One collecting run's state: its flags, its cancellation, whether the final clear
    failed, which decides the last warning, and how far the save got."""

    def __init__(
        self, args: argparse.Namespace, found: preflight.Platform, cancelled: Callable[[], bool]
    ) -> None:
        self.args = args
        self.found = found
        self.cancelled = cancelled
        self.clear_failed = False
        self.progress = _Progress()

    def exit(self, **causes: bool) -> int:
        return model.exit_code(clear_failed=self.clear_failed, **causes)

    def debug(self, result: spawn.Result) -> None:
        _warn(spawn.debug_line(result))

    def go(self) -> int:
        _say(console.HEADER)
        _say(BLURB)
        _say()
        on_result = self.debug if self.args.debug else None
        with spawn.Runner(on_result=on_result, cancelled=self.cancelled) as runner:
            read = self.reads(runner)
            if read is None:
                _tell(STOPPED)
                return self.exit(interrupted=True)
            try:
                granted = self.elevated(runner)
            except elevation.Cancelled:
                _tell(STOPPED)
                return self.exit(interrupted=True)
            results, panic = read
            document = self.document(runner, results, panic, granted)
            return self.report(runner, document)

    # --- collecting -------------------------------------------------------------------------

    def reads(
        self, runner: spawn.Runner
    ) -> tuple[dict[str, spawn.Result], int | availability.Unavailable] | None:
        """The 27 user reads and the panic count, on one timed line; None once cancelled.
        With --debug the line is printed whole once the reads are done, so no --debug line
        on stderr joins it on a shared screen."""
        debug = self.args.debug
        if not debug:
            _say(READING, end="")
        started = _monotonic()
        results: dict[str, spawn.Result] = {}
        for command_id in allowlist.USER_COMMAND_IDS:
            results[command_id] = runner.run(command_id, failed=_judged_by(command_id))
            if self.cancelled():
                _say(READING if debug else "")
                return None
        panic = in_process.panic_count()
        if self.cancelled():
            _say(READING if debug else "")
            return None
        _say(f"{READING if debug else ''} done ({_monotonic() - started:.1f} s).")
        _say()
        return results, panic

    def payloads(self, runner: spawn.Runner) -> elevation.Payloads:
        """The broker's payload runner, with a line for each payload and its --debug line."""

        def payload(command_id: str, uid: int) -> spawn.PayloadRun:
            # A run already cancelled here starts no payload, so no line says one is being
            # read (the review of #326, round 1, N3); tracking checks the flag again before
            # the payload starts.
            line = None if self.cancelled() else _PAYLOAD_LINES[command_id.rstrip("n")]
            if line is not None:
                _say(line, end="")
            run: spawn.PayloadRun | None = None
            try:
                run = runner.payload(command_id, uid=uid)
            finally:
                if line is not None:
                    _say(DONE if run is not None and _finished(run) else NOT_READ)
            assert run is not None  # noqa: S101 - the runner returned, so it gave a run
            if self.args.debug:
                _warn(_payload_line(run))
            return run

        return payload

    def elevated(self, runner: spawn.Runner) -> elevation.Elevation:
        """The explanation and the question when they apply, then the broker, and what it
        leaves to say: a no, the clear or its warning, survivors and unverified stops."""
        args = self.args
        # An unknown answer lets sudo decide; with --no-root nothing needs it.
        admin = True if args.no_root else preflight.admin() is not False
        if self.cancelled():  # the admin check can wait 5 s: a Ctrl-C then explains nothing
            raise elevation.Cancelled(clear_failed=False)
        # sudo prompts wherever stdin is a terminal, --yes or not. Voltry's own question
        # prints on stdout, so it is asked only when stdout is that terminal too (the run's
        # review, rounds 1 and 2).
        stdin_terminal = preflight.terminal()
        present = stdin_terminal and _stdout_terminal()
        explain = not args.no_root and admin and (args.yes or present)
        if explain:
            _say(EXPLANATION)
            _say()

        def ask() -> str | None:
            """The question and its answer, on a terminal. What was typed before it is
            dropped, and so is what comes within _TOO_SOON_S of it, before anyone could
            read it (the run's review, rounds 1 and 2). What still gets through: a paste
            larger than the terminal's input queue, when the rest of it comes later than
            that, and keys held up longer than that on a slow link."""
            _discard_typed()
            _say(QUESTION, end="")
            answer = _answer(self.cancelled)
            if answer is None or not answer.endswith("\n"):
                _say()  # nothing echoed a newline: no answer, or one ended with Ctrl-D
            return answer

        try:
            granted = elevation.run(
                yes=args.yes,
                no_root=args.no_root,
                admin=admin,
                terminal=stdin_terminal if args.yes else present,
                ask=ask,
                runner=runner,
                cancelled=self.cancelled,
                payload=self.payloads(runner),
            )
        except (elevation.Cancelled, elevation.Interrupted) as stopped:
            self.broker_ended(stopped.clear_failed, stopped.survivors, stopped.unverified)
            raise
        record = granted.record
        if record["consent"] == "no":
            _say(SKIPPING)
        if record["cleared"] == "cleared":
            _say(CLEARED)
        cleanups = [_cleanup(record, step) for step in ("count", "power")]
        self.broker_ended(granted.clear_failed, granted.survivors, _UNVERIFIED in cleanups)
        if explain:
            _say()
        return granted

    def broker_ended(
        self, clear_failed: bool, survivors: Sequence[tracking.Survivor], unverified: bool
    ) -> None:
        """The warning where the final clear failed, and the notes to act on."""
        self.clear_failed = clear_failed
        if clear_failed:
            _tell(WARNING)
        for survivor in survivors:
            _tell(tracking.survivor_note(survivor))
        if unverified:
            _tell(tracking.UNVERIFIED_NOTE)

    def document(
        self,
        runner: spawn.Runner,
        results: Mapping[str, spawn.Result],
        panic: int | availability.Unavailable,
        granted: elevation.Elevation,
    ) -> dict[str, object]:
        """The report from what the run collected, as of the end of collection."""
        collected = assemble.Collected(
            results=results,
            panic=panic,
            ledger=granted.ledger,
            power=granted.power,
            collected_at=_now(),
            show_serial=self.args.show_serial,
        )
        surfaces = assemble.surfaces(collected)
        tool = {
            "name": validate.TOOL_NAME,
            "version": __version__,
            "renderer_version": report_pdf.RENDERER,
            "python": console.python_version(),
            "architecture": preflight.architecture(self.found),
            "rosetta": self.found.translated is True,
        }
        return model.document(
            tool=tool,
            collected_at=collected.collected_at,
            time_zone=in_process.time_zone(),
            validated=_validated(surfaces),
            elevation=granted.record,
            surfaces=surfaces,
            commands=[dataclasses.asdict(record) for record in runner.records()],
            paper=self.args.paper or _paper(),
        )

    # --- reporting --------------------------------------------------------------------------

    def report(self, runner: spawn.Runner, document: dict[str, object]) -> int:
        """The summary, the files and the open; or, below the save gate, what did answer."""
        surfaces = document["surfaces"]
        assert isinstance(surfaces, list)  # noqa: S101 - the model's own document
        if not model.save_gate(surfaces):
            if self.cancelled():  # 130 comes before 4
                _tell(STOPPED)
                return self.exit(interrupted=True, not_saved=True)
            _tell(NOT_ENOUGH)
            _tell(_answered(surfaces))
            return self.exit(not_saved=True)
        try:
            pdf: bytes | None = report_pdf.render(document, manifests.templates(__version__))
        except Exception:  # noqa: BLE001 - a bug in the PDF writer; named, never shown
            pdf = None
        if self.cancelled():  # a run already stopped shows no summary before it says so
            _tell(STOPPED)
            return self.exit(interrupted=True, not_saved=True)
        _say(terminal.summary(document), end="")
        if pdf is None:
            if self.cancelled():
                _tell(STOPPED)
                return self.exit(interrupted=True, not_saved=True)
            _tell(PDF_BUG)
            return self.exit(not_saved=True)
        _say()
        _say(FULL_REPORT)
        _say()
        data = canonical.canonical_json(document).encode("utf-8") if self.args.json else None
        local = str(document["collected_at_local"])
        cause = _save(self.args, runner, self.cancelled, pdf, data, local, self.progress)
        if cause is not None:
            return self.exit(**{cause: True})
        return self.exit(unexpected=model.unexpected(document))


# --- saving and opening, for the run and for render -------------------------------------------


def _save(
    args: argparse.Namespace,
    runner: spawn.Runner,
    cancelled: Callable[[], bool],
    pdf: bytes,
    data: bytes | None,
    local: str,
    progress: _Progress,
    *,
    for_render: bool = False,
) -> str | None:
    """Save the report, name its files and open it, by the rules a live run and render
    share (Decision 5). A failed save, or a stop once saved, is said in the words of the
    one that saves; every other line is the run's, and render shares it, as its PDF is the
    report too (the copy pass's review, round 2, n5). None once saved and opened;
    otherwise the exit's cause, ``interrupted`` or ``not_saved``, once it has said why. A
    cancellation outranks a save that failed (the run's review, round 2, m12). A signal
    once the report is saved keeps it and stops the run: the flag is read after the save's
    lines and as the open returns, and the run or render reads it once more as it ends
    (_last_read)."""
    try:
        saved = writer.save(
            pdf,
            data,
            local=local,
            folder=args.output,
            cancelled=cancelled,
            before_desktop=lambda: _say(DESKTOP),
        )
    except writer.Cancelled as stopped:
        _tell(STOPPED)
        _left(stopped.left)
        return "interrupted"
    except writer.NotSaved as refused:
        if cancelled():  # 130 comes before 4, a Ctrl-C at a folder's permission prompt say
            _tell(STOPPED)
            _left(refused.left)
            return "interrupted"
        plain, named = (
            (RENDER_NOT_SAVED, RENDER_NOT_SAVED_IN) if for_render else (NOT_SAVED, NOT_SAVED_IN)
        )
        reason = str(refused)
        home = _home()
        if args.output is not None and not args.output:
            _tell(plain.format(reason=NO_FOLDER))
        elif args.output is None and not (home and refused.folder == home):
            _tell(plain.format(reason=reason))  # the Desktop, as announced
        elif args.output is None:
            # The move to the home folder failed too.
            _tell((RENDER_NOT_SAVED_HOME if for_render else NOT_SAVED_HOME).format(reason=reason))
        else:
            folder = _shown(refused.folder, whole=True)
            _tell(named.format(folder=folder, reason=reason))
        _left(refused.left)
        return "not_saved"
    progress.saved = True
    _named(saved, local)
    if cancelled() or _open(args, runner, saved, cancelled, progress):
        return _stop_once_saved(progress, for_render=for_render)
    return None


def _stop_once_saved(progress: _Progress, *, for_render: bool) -> str:
    """Say that the run stopped once its report was saved, in the words of the one that
    saved it, and return the exit's cause: the report stays, and whether O1 may have
    started decides whether it was opened (change record 10)."""
    if progress.opening:
        _tell(RENDER_STOPPED_OPENING if for_render else STOPPED_OPENING)
    else:
        _tell(RENDER_STOPPED_SAVED if for_render else STOPPED_SAVED)
    return "interrupted"


def _last_read(
    code: int, progress: _Progress, cancelled: Callable[[], bool], *, for_render: bool
) -> int:
    """The run's last read of the flag, and render's, as the last step of every exit, and
    the exit code it leaves: a signal until here stops the run, as 130 comes before 4, 6,
    1 and 0 (change record 10). Once the report is saved, it stops as one just after the
    save does, whether the open ran, failed or never started (the GPT audit, pass 2,
    G2-03); with nothing saved, it says so after the run has said why (the pre-audit of
    pass 3, 01). An exit already interrupted reads nothing more. One after this read, in the
    moments before the tool exits, is not reported (signals.cancellation)."""
    if code == model.exit_code(interrupted=True) or not cancelled():
        return code
    if progress.saved:
        _stop_once_saved(progress, for_render=for_render)
    else:
        _tell(STOPPED)
    return model.exit_code(interrupted=True)


def _named(saved: writer.Saved, local: str) -> None:
    """The last lines name the files: the JSON first, as it was published first."""
    shown = [_shown(path) for path in (saved.json, saved.pdf) if path]
    if saved.fallback:
        _say(FALLBACK_BEFORE)
        for path in shown:
            _say(f"  {path}")
        _say(FALLBACK_AFTER)
    else:
        for path in shown:
            _say(f"Saved: {path}")
    if saved.renamed:
        _say(RENAMED.format(time=local[11:16]))
    _left(saved.left)


def _left(paths: Sequence[str]) -> None:
    if not paths:
        return
    _tell(LEFT_ONE if len(paths) == 1 else LEFT_MANY)
    for path in paths:
        _warn(f"  {_shown(path)}")


def _open(
    args: argparse.Namespace,
    runner: spawn.Runner,
    saved: writer.Saved,
    cancelled: Callable[[], bool],
    progress: _Progress,
) -> bool:
    """O1, once, on the PDF just published, unless --no-open or over SSH; true when a stop
    came before it or as it ran (the GPT audit, pass 1, G1-01). The flag is read just
    before O1, and a stop then opens nothing (the review of #326, round 1, N3). It is read
    again as O1 returns, whatever its ending: a Ctrl-C at the terminal ends open(1) too, so
    the open fails in the instant the flag is set (the GPT audit, pass 2, G2-03). An O1
    the chokepoint stops, or refuses for a flag set in between, is a stop too. ``progress``
    notes whether O1 may have started. A failed open adds nothing to the path already
    printed, and one the chokepoint refuses, because the file changed after it was
    published, is a failed open too: the report is saved either way. When the PDF's
    temporary is still there, a second name for it, the refusal is that file's, and the
    run says so (change record 21)."""
    if args.no_open or _ssh():
        return False
    try:
        runner.published(saved.pdf)
        if cancelled():
            return True
        result = runner.run("O1")
    except spawn.Refused:
        if saved.second_name:
            _tell(SECOND_NAME)
        return False
    progress.opening = result.ending is not spawn.Ending.NOT_STARTED
    if result.ending is spawn.Ending.CANCELLED or cancelled():
        return True
    if result.ok:
        _say(OPENING)
    return False


def collect(args: argparse.Namespace, found: preflight.Platform) -> int:
    """The collecting run, once the preflight has passed; returns the exit code. The flag
    is read one last time as the last step of every exit (_last_read)."""
    with signals.cancellation() as cancelled:
        run = _Run(args, found, cancelled)
        try:
            code = run.go()
        except Exception:  # noqa: BLE001 - named by a fixed line, never by its text
            if run.progress.saved:
                _tell(SAVED_THEN_UNEXPECTED)
                code = run.exit(unexpected=True, interrupted=cancelled())
            elif cancelled():
                _tell(STOPPED)
                code = run.exit(interrupted=True, not_saved=True)
            else:
                _tell(UNEXPECTED)
                code = run.exit(not_saved=True)
        if run.clear_failed:
            _tell(WARNING)  # again, near the end, where the owner sees it
        # A payload the tool could not signal is still its child: collect its exit if it
        # has ended, and otherwise leave it to launchd (Decision 2, "Stopping a payload").
        spawn.collect_abandoned()
        # The last step of the run, after everything it does: a signal until here stops it
        # (change record 10; the GPT audit, pass 3, G3-02).
        code = _last_read(code, run.progress, cancelled, for_render=False)
    return code


# --- render --------------------------------------------------------------------------------


class _NotAFile(Exception):
    """The path names something other than a regular file: a folder or a FIFO, say."""


def _read_report(path: str) -> bytes:
    """A saved report's bytes: at most one byte past the cap, so a larger file is refused
    without being read whole, and only from a regular file, opened without waiting, so a
    FIFO at the path never blocks."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise _NotAFile
        chunks: list[bytes] = []
        left = canonical.MAX_BYTES + 1
        while left > 0:
            chunk = os.read(descriptor, left)
            if not chunk:
                break
            chunks.append(chunk)
            left -= len(chunk)
        return b"".join(chunks)
    finally:
        with contextlib.suppress(OSError):
            os.close(descriptor)


def _refused(invalid: canonical.Invalid, shown: str) -> str:
    """Why render refuses a file: the problem, then the field it is at, when it has one, and
    the file, each on a line of its own."""
    if invalid.path:
        return RENDER_REFUSED_AT.format(problem=invalid.message, field=invalid.path, path=shown)
    return RENDER_REFUSED.format(problem=invalid.message, path=shown)


def rebuild(args: argparse.Namespace) -> int:
    """``voltry-mac render REPORT.json``, once the preflight has passed; returns the exit
    code: 0 saved, 1 saved before an unexpected error, 2 a file it cannot read or render,
    4 not saved, 130 interrupted. A signal as the file is read or drawn stops render at
    once, so one stops a read that stalls (the run's review, round 1, m7, and round 2,
    n17); after that a signal only sets the flag, as in the run, so a refusal keeps its 2,
    which comes before 130. A cancellation outranks a bug, as in the run, and the flag is
    read one last time as the last step of every other exit (_last_read). A refusal goes to
    stderr alone, as the command line's do; the header follows only once the report is read
    and drawn."""
    with signals.cancellation() as cancelled:
        progress = _Progress()
        try:
            # The path is looked up for its home folder only when a refusal prints it.
            try:
                with signals.stopping(cancelled):
                    data = _read_report(args.report)
            except _NotAFile:
                shown = _shown(args.report, whole=True)
                _tell(UNREADABLE.format(path=shown, reason=NOT_A_FILE))
                return model.exit_code(usage=True)
            except OSError as error:
                shown = _shown(args.report, whole=True)
                _tell(UNREADABLE.format(path=shown, reason=os.strerror(error.errno or 0)))
                return model.exit_code(usage=True)
            try:
                with signals.stopping(cancelled):
                    rendered = render.render(data)
            except canonical.Invalid as invalid:
                shown = _shown(args.report, whole=True)
                _tell(_refused(invalid, shown))
                return model.exit_code(usage=True)
            except Exception:  # noqa: BLE001 - a bug in the PDF writer; named, never shown
                _tell(RENDER_PDF_BUG)
                code = model.exit_code(not_saved=True)
                return _last_read(code, progress, cancelled, for_render=True)
        except KeyboardInterrupt:  # a signal as the file was read or drawn
            _tell(STOPPED)
            return model.exit_code(interrupted=True)
        try:
            _say(console.HEADER)
            _say()
            tool = rendered.document["tool"]
            assert isinstance(tool, Mapping)  # noqa: S101 - a validated document
            if (tool["version"], tool["renderer_version"]) != (__version__, report_pdf.RENDERER):
                both = BOTH_VERSIONS.format(
                    made=tool["version"],
                    made_renderer=tool["renderer_version"],
                    drawn=__version__,
                    drawn_renderer=report_pdf.RENDERER,
                )
                _say(_wrapped(both))
                _say()
            local = str(rendered.document["collected_at_local"])
            with spawn.Runner(cancelled=cancelled) as runner:
                cause = _save(
                    args, runner, cancelled, rendered.pdf, None, local, progress, for_render=True
                )
        except Exception:  # noqa: BLE001 - named by a fixed line, never by its text
            if progress.saved:
                _tell(RENDER_SAVED_THEN_UNEXPECTED)
                code = model.exit_code(unexpected=True, interrupted=cancelled())
            elif cancelled():  # 130 comes before 4
                _tell(STOPPED)
                code = model.exit_code(interrupted=True, not_saved=True)
            else:
                _tell(RENDER_UNEXPECTED)
                code = model.exit_code(not_saved=True)
        else:
            code = model.exit_code(**{cause: True}) if cause is not None else 0
        return _last_read(code, progress, cancelled, for_render=True)
