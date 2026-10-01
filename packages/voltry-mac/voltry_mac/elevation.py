"""The elevation broker: the elevated path, from the question to the final sudo -k.

docs/VOLTRY_MAC_SPEC.md, Decision 2, steps 4 to 10. After a yes, the capability checks run
in order: the service account (R5, looked up in-process in a worker thread bounded to 5 s),
the sandbox probe (X1) and the listing (P1). Then sudo -k (S1), the one prompt (S2), the
count (S3) and the power sample (S4), and the final sudo -k (S5), which runs once S1 was
attempted, whatever happened after it, a cancellation included, and before either
payload's output is parsed. A run with --yes and no terminal uses the -n forms S2n to S4n.

Every process starts through the chokepoint. This module decides what runs next and
writes the elevation record, and the outcome tables turn that record into the two elevated
surfaces' reasons. How a payload is tracked, stopped and checked afterwards is the payload
runner's (spawn.Runner.payload), which runs each payload as its own account (the service
account's user ID for the count, root for the power sample) and hands back a
spawn.PayloadRun with any survivors, which reach the caller for the verification-first
note.
"""

from __future__ import annotations

import pwd
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Final

from voltry_mac import assemble, listing, outcomes, payloads, spawn, sudo_messages, tracking
from voltry_mac.assemble import Elevated

SERVICE_ACCOUNT: Final = "_mmaintenanced"
LOOKUP_BOUND_S: Final = 5.0
# The user IDs the count may run as (Decision 2; the Threat model: "never root"): not 0,
# root's; not a negative one, which names no account (the lookup gives -1 for the
# "no change" ID); and not 2^31 or above, which ps prints as a negative number, so tracking
# could never identify the payload (the GPT audit, pass 2, G2-04).
SERVICE_UIDS: Final = range(1, 2**31)
_NOT_RUN: Final = ("not_run", "not_applicable")


class Cancelled(Exception):
    """The run was cancelled on the elevated path, so nothing is saved (exit 130).

    S5 has run if S1 was attempted; ``clear_failed`` says whether it failed, so the
    warning with the exact sudo -k still prints, and so do the notes for any
    ``survivors`` and for a stop the last listing could not verify (``unverified``).
    """

    def __init__(
        self,
        *,
        clear_failed: bool,
        survivors: tuple[tracking.Survivor, ...] = (),
        unverified: bool = False,
    ) -> None:
        super().__init__("the run was cancelled")
        self.clear_failed = clear_failed
        self.survivors = survivors
        self.unverified = unverified


class Interrupted(Exception):
    """An unexpected error stopped the elevated path once sudo -k (S1) had been attempted.

    The final clear ran all the same; ``clear_failed`` says whether it failed, so the
    warning still prints, and so do the notes for any ``survivors`` and for a stop that
    could not be verified (``unverified``). The error is this exception's cause.
    """

    def __init__(
        self,
        *,
        clear_failed: bool,
        survivors: tuple[tracking.Survivor, ...] = (),
        unverified: bool = False,
    ) -> None:
        super().__init__("the elevated path stopped on an unexpected error")
        self.clear_failed = clear_failed
        self.survivors = survivors
        self.unverified = unverified


@dataclass(frozen=True)
class Elevation:
    """What the elevated path leaves for the report: the elevation record, what each
    elevated surface gets, and whether the final clear failed (the warning, and exit 6)."""

    record: Mapping[str, object]
    ledger: Elevated
    power: Elevated
    clear_failed: bool
    survivors: tuple[tracking.Survivor, ...] = ()


@dataclass
class _Record:
    consent: str
    skip_cause: str | None
    mode: str
    service_account: str = "not_run"
    sandbox_probe: str = "not_run"
    listing: str = "not_run"
    prepare: str = "not_run"
    authenticate: str = "not_run"
    count: tuple[str, str] = _NOT_RUN
    power: tuple[str, str] = _NOT_RUN
    cleared: str = "not_attempted"
    clear_error: str | None = None

    def json(self) -> dict[str, object]:
        return {
            "consent": self.consent,
            "skip_cause": self.skip_cause,
            "mode": self.mode,
            "checks": {
                "service_account": self.service_account,
                "sandbox_probe": self.sandbox_probe,
                "listing": self.listing,
            },
            "prepare": self.prepare,
            "authenticate": self.authenticate,
            "count": {"ending": self.count[0], "cleanup": self.count[1]},
            "power": {"ending": self.power[0], "cleanup": self.power[1]},
            "cleared": self.cleared,
            "clear_error": self.clear_error,
        }


def _stop_if(cancelled: Callable[[], bool]) -> None:
    """Before S1 nothing needs clearing, so a cancellation simply stops the path."""
    if cancelled():
        raise Cancelled(clear_failed=False)


def _lookup(name: str) -> int:
    """The account's user ID from the account database, or KeyError when it has none.

    CPython turns every failed getpwnam_r into KeyError, so a KeyError is checked against
    root's entry: a database that cannot give root's did not answer at all.
    """
    try:
        return pwd.getpwnam(name).pw_uid
    except KeyError:
        try:
            pwd.getpwuid(0)
        except KeyError:
            raise OSError("the account database did not answer") from None
        raise


def _service_account(lookup: Callable[[str], object], bound_s: float) -> tuple[str, int | None]:
    """R5 and the user ID it found. A lookup that has not returned by the bound is
    abandoned, not waited for, and one that returns after it is its error even if the
    answer arrives before it is read; one that gives anything but a user ID in
    SERVICE_UIDS, root's 0 above all, is its error too, so the count never runs as root."""
    found: list[tuple[str, int | None, float]] = []

    def work() -> None:
        try:
            uid = lookup(SERVICE_ACCOUNT)
        except KeyError:
            state, found_uid = "missing", None
        except Exception:  # noqa: BLE001 - every other failure of the lookup is its error
            state, found_uid = "error", None
        else:
            usable = type(uid) is int and uid in SERVICE_UIDS
            state, found_uid = ("present", uid) if usable else ("error", None)
        found.append((state, found_uid, time.monotonic()))

    deadline = time.monotonic() + bound_s
    worker = threading.Thread(target=work, name="voltry-mac-service-account", daemon=True)
    worker.start()
    worker.join(bound_s)
    if found and found[0][2] <= deadline:
        return found[0][0], found[0][1]
    return "error", None


def _listing_failed(result: spawn.Result) -> bool:
    if not result.ok:
        return True
    try:
        listing.processes(result.stdout)
    except listing.Unreadable:
        return True
    return False


def _authentication(result: spawn.Result) -> str:
    """S2's state. Its clock is a plain wait's deadline; the output cap and a sudo that
    could not start are failures the tool cannot explain. A signal death is read, like a
    payload's, by the lines sudo printed before it."""
    if result.ok:
        return "ok"
    if result.ending is spawn.Ending.DEADLINE:
        return "denied"
    if result.ending in (spawn.Ending.EXITED, spawn.Ending.SIGNALED):
        return sudo_messages.s2_outcome(result.stderr)
    return "error"


def _ending(run: spawn.PayloadRun) -> str | None:
    """A payload's ending, or None when sudo exited 0: then the output decides between
    ``parsed`` and ``unparsed``, both ordinary, once the final clear has run."""
    if not run.started:
        return "spawn_failed"
    if run.forced is not None:
        return run.forced
    if run.returncode != 0:
        return sudo_messages.payload_ending(run.stderr)
    return None


Payloads = Callable[[str, int], spawn.PayloadRun]


def _payload(payload: Payloads, command_id: str, uid: int, pending: list[str]) -> spawn.PayloadRun:
    """One payload command. It stays ``pending`` if anything but its own tracked end leaves
    the runner, since then no listing checked that it stopped."""
    pending.append(command_id)
    try:
        run = payload(command_id, uid)
    except spawn.PayloadInterrupted:
        pending.remove(command_id)  # stopped, and its final listing taken
        raise
    pending.remove(command_id)
    if run.command_id != command_id:
        raise ValueError(f"the payload runner ran {run.command_id} for {command_id}")
    return run


def _note(
    runner: spawn.Runner, run: spawn.PayloadRun, endings: dict[str, str | None], base: str
) -> None:
    """Classify a payload's ending once, and keep its record by that judgment."""
    endings[base] = _ending(run)
    runner.note_payload(
        run.command_id, failed=endings[base] is not None, duration_ms=run.duration_ms
    )


def _cleared(result: spawn.Result) -> tuple[str, str | None]:
    """S5's state and, when it failed, the one of five fixed codes that says how."""
    if result.ok:
        return "cleared", None
    if result.ending is spawn.Ending.NOT_STARTED:
        return "failed", "spawn_error"
    if not result.reaped:
        return "failed", "not_reaped"
    if result.ending is spawn.Ending.DEADLINE:
        return "failed", "deadline"
    if result.ending is spawn.Ending.OUTPUT_CAP:
        return "failed", "output_cap"
    return "failed", "nonzero_exit"


def _sudo(
    record: _Record,
    runner: spawn.Runner,
    payload: Payloads,
    cancelled: Callable[[], bool],
    runs: dict[str, spawn.PayloadRun],
    endings: dict[str, str | None],
    service_uid: int | None,
    pending: list[str],
) -> bool:
    """S1 to S4, each only if the steps before it allow it; true when cancelled on the way."""
    suffix = "n" if record.mode == "noninteractive" else ""
    record.prepare = "ok" if runner.run("S1").ok else "failed"
    if cancelled():
        return True
    if record.prepare != "ok":
        return False
    result = runner.authenticate(f"S2{suffix}")
    if result.ending is spawn.Ending.CANCELLED or cancelled():
        return True
    record.authenticate = _authentication(result)
    if record.authenticate != "ok":
        return False
    count_ending, count_cleanup = _NOT_RUN
    if record.service_account == "present":
        assert service_uid is not None  # noqa: S101 - a present account has its user ID
        count = runs["S3"] = _payload(payload, f"S3{suffix}", service_uid, pending)
        _note(runner, count, endings, "S3")  # the power sample's gate needs it now
        if count.cancelled or cancelled():
            return True
        # parsed and unparsed are both ordinary, so the gate needs no parse.
        count_ending, count_cleanup = endings["S3"] or "parsed", count.cleanup
    if outcomes.power_runs(
        record.authenticate, record.service_account, count_ending, count_cleanup
    ):
        # Judged after the final clear.
        power = runs["S4"] = _payload(payload, f"S4{suffix}", 0, pending)
        return power.cancelled
    return False


def _read(base: str, stdout: str) -> tuple[str, Mapping[str, object] | None]:
    """Parsed only if the output reads and a value survives its registry range: an output
    in which every value would be unavailable is unparsed, and only the report model
    applies the ranges."""
    key, read = (
        (outcomes.LEDGER, payloads.ledger) if base == "S3" else (outcomes.POWER, payloads.power)
    )
    try:
        values = read(stdout)
    except payloads.Unparsed:
        return "unparsed", None
    return ("parsed", values) if assemble.readable(key, values) else ("unparsed", None)


def _survivors(runs: Mapping[str, spawn.PayloadRun]) -> tuple[tracking.Survivor, ...]:
    return tuple(survivor for run in runs.values() for survivor in run.survivors)


def _finish(
    record: _Record,
    values: Mapping[str, Mapping[str, object] | None],
    clear_failed: bool,
    survivors: tuple[tracking.Survivor, ...] = (),
) -> Elevation:
    document = record.json()
    found = outcomes.surfaces(document)

    def elevated(key: str, base: str) -> Elevated:
        outcome = found[key]
        if outcome is None:
            return Elevated(values=values[base])
        return Elevated(reason=outcome[0], detail=outcome[1])

    return Elevation(
        record=document,
        ledger=elevated(outcomes.LEDGER, "S3"),
        power=elevated(outcomes.POWER, "S4"),
        clear_failed=clear_failed,
        survivors=survivors,
    )


def run(
    *,
    yes: bool,
    no_root: bool,
    admin: bool,
    terminal: bool,
    ask: Callable[[], str | None],
    runner: spawn.Runner,
    cancelled: Callable[[], bool],
    payload: Payloads | None = None,
    lookup: Callable[[str], object] = _lookup,
    lookup_bound_s: float = LOOKUP_BOUND_S,
) -> Elevation:
    """The elevated path. ``ask`` puts the question, and ``cancelled`` is the flag the
    signal handlers set; a cancellation raises ``Cancelled`` once S5 has run, if S1 was
    attempted, and an unexpected error there ``Interrupted``. ``payload`` runs one
    tracked payload as an account, by default the chokepoint's payload runner;
    ``lookup`` gives the service account's user ID."""
    if payload is None:

        def payload(command_id: str, uid: int) -> spawn.PayloadRun:
            return runner.payload(command_id, uid=uid)

    _stop_if(cancelled)  # a run cancelled before the broker started asks nothing
    consent, skip_cause, mode = outcomes.consent(
        yes=yes, no_root=no_root, admin=admin, terminal=terminal, ask=ask
    )
    record = _Record(consent, skip_cause, mode)
    _stop_if(cancelled)
    if mode == "none":
        return _finish(record, {}, clear_failed=False)
    record.service_account, service_uid = _service_account(lookup, lookup_bound_s)
    _stop_if(cancelled)
    probe = runner.run("X1")
    _stop_if(cancelled)
    record.sandbox_probe = "ok" if probe.ok else "failed"
    if record.sandbox_probe == "ok":
        failed = _listing_failed(runner.run("P1", failed=_listing_failed))
        _stop_if(cancelled)
        record.listing = "failed" if failed else "ok"
    if record.listing != "ok":
        return _finish(record, {}, clear_failed=False)
    runs: dict[str, spawn.PayloadRun] = {}
    endings: dict[str, str | None] = {}
    pending: list[str] = []
    stopped = True
    failure: BaseException | None = None
    try:
        stopped = _sudo(record, runner, payload, cancelled, runs, endings, service_uid, pending)
    except spawn.PayloadInterrupted as interrupted:
        runs[interrupted.run.command_id.rstrip("n")] = interrupted.run
        failure = interrupted.__cause__ or interrupted
    except KeyboardInterrupt:
        stopped = True  # a Ctrl-C no handler turned into the flag is still a cancellation
    except BaseException as error:  # noqa: BLE001 - it is raised again, with the clear's result
        failure = error
    # What the listings found is known before the final clear, so nothing after can lose it.
    found = _survivors(runs)
    # A payload an exception left unchecked, or a final listing that failed, is a stop no
    # listing verified.
    unverified = bool(pending) or any(run.cleanup == "listing_failed" for run in runs.values())
    broken = _clear(runner, record)
    clear_failed = broken is not None or record.cleared == "failed"
    if failure is None and broken is not None and not isinstance(broken, KeyboardInterrupt):
        failure = broken
    if failure is not None:
        raised = Interrupted(clear_failed=clear_failed, survivors=found, unverified=unverified)
        if broken is not None and broken is not failure:
            raised.__context__ = broken
        raise raised from failure
    if stopped or cancelled() or broken is not None:
        raise Cancelled(clear_failed=clear_failed, survivors=found, unverified=unverified)
    try:
        values = _results(runner, runs, endings, record)
    except KeyboardInterrupt:
        raise Cancelled(clear_failed=clear_failed, survivors=found, unverified=unverified) from None
    except BaseException as error:  # noqa: BLE001 - raised with the survivors it would lose
        raise Interrupted(
            clear_failed=clear_failed, survivors=found, unverified=unverified
        ) from error
    return _finish(record, values, clear_failed, found)


def _clear(runner: spawn.Runner, record: _Record) -> BaseException | None:
    """S5, the final clear, whatever came before it. An error or a Ctrl-C inside it is
    returned rather than raised, so the survivors and the first error still leave with
    the exception the broker raises; a clear that did not finish counts as failed."""
    try:
        record.cleared, record.clear_error = _cleared(runner.run("S5"))
    except BaseException as problem:  # noqa: BLE001 - reported with what is known
        return problem
    return None


def _results(
    runner: spawn.Runner,
    runs: Mapping[str, spawn.PayloadRun],
    endings: dict[str, str | None],
    record: _Record,
) -> dict[str, Mapping[str, object] | None]:
    """After the final clear: the power sample's note, then each payload's output read and
    its ending and cleanup put on the record."""
    if "S4" in runs:
        _note(runner, runs["S4"], endings, "S4")
    values: dict[str, Mapping[str, object] | None] = {}
    for base, run in runs.items():
        ending = endings[base]
        if ending is None:
            ending, values[base] = _read(base, run.stdout)
        if base == "S3":
            record.count = (ending, run.cleanup)
        else:
            record.power = (ending, run.cleanup)
    return values
