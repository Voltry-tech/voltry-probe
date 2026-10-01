"""The privacy canaries (docs/VOLTRY_MAC_SPEC.md, Test strategy part 3, "Privacy canaries";
the Threat model's privacy row; the field inventory's "Read but never kept"; the Acceptance
line on identifiers).

A made-up canary stands for each identifier the spec names. Each is planted where the fake
M5 (tests/fake_mac.py) meets it: in the user reads' output (serials, UUIDs, the UDID, volume
names and mount points, a display's name and serial, the apps in scheduled wake events), in
the panic file names R1 counts, in P1's listings, a survivor among them, in the power
sample's boot arguments, and in the preferences file R3 reads. An account name and a host
name are in every path, since the home folder holds both, and in every message the fake
sudo prints.

Each scenario runs the real command line: with --json and --debug for the reads allowed,
--show-serial, --yes with no terminal (sudo's -n forms), failures and bugs from the reads
to the save, Ctrl-C from the reads to the open (one followed by a bug, one with too little
read to save), a home folder reached through a symlink, and then render's. No canary may
reach stdout, stderr (the --debug lines and every error message), the PDF's text or bytes,
or the JSON, found in any case and with the whitespace taken out, so one the terminal or
the PDF wrapped across two lines is found whole, and in the PDF's streams decompressed (the
review of #326, round 1, M4 and M5; round 2, m1, m2 and n3). The spec allows two
exceptions, and these tests hold them to its words. The serial shows its last four
characters, or with --show-serial the whole serial in the terminal, the PDF and the JSON
only. The survivor note prints a process name only when it is one of the four the subtree
can hold. Every path under the home folder prints with ~.
"""

from __future__ import annotations

import contextlib
import dataclasses
import errno
import io
import json
import os
import plistlib
import re
import signal
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Final

import pypdf
import pytest
import voltry_mac_test_copy_golden as golden
import voltry_mac_test_fake_mac as fm
import voltry_mac_test_pdf_pages as pages
import voltry_mac_test_reports as r

import voltry_mac
from voltry_mac import (
    allowlist,
    assemble,
    canonical,
    cli,
    in_process,
    layout,
    listing,
    model,
    pdf,
    preflight,
    report_pdf,
    run,
    spawn,
    tracking,
    validate,
    writer,
)

# --- the canaries ---------------------------------------------------------------------------
#
# One made-up word per kind of identifier, none of which a report prints. A source that holds
# several values (three volumes, four UUIDs) gives each the word and a suffix, so the word
# finds any of them. Matching ignores case.

SERIAL = "CNRYSERIALQ7ZX"
LAST4 = SERIAL[-4:]
PLATFORM_UUID = "CNRYPLATFORMUUID"
PROVISIONING_UDID = "CNRYPROVISIONINGUDID"
SSD_SERIAL = "CNRYSSDSERIAL"
VOLUME = "CNRYVOLUME"
MOUNT = "CNRYMOUNTPOINT"
DISK_UUID = "CNRYDISKUUID"
DISPLAY_NAME = "CNRYDISPLAYNAME"
DISPLAY_SERIAL = "CNRYDISPLAYSERIAL"
BATTERY_SERIAL = "CNRYBATTERYSERIAL"
WAKE_APP = "CNRYWAKEAPP"
GAUGE_SERIAL = "CNRYGAUGESERIAL"
PANIC_APP = "CNRYPANICAPP"
PROCESS = "CNRYPROCESS"
BOOT_ARG = "CNRYBOOTARG"
TEXT_REPLACEMENT = "CNRYTEXTREPLACEMENT"
ACCOUNT = "cnryaccount"
HOST = "Cnry-MacBook-Pro"

SERIAL_SOURCE = "serial number (C2)"
CANARIES: Final = {
    SERIAL_SOURCE: SERIAL[:-4],  # the last four characters are the report's own
    "platform UUID (C2)": PLATFORM_UUID,
    "provisioning UDID (C2)": PROVISIONING_UDID,
    "SSD serial (C3)": SSD_SERIAL,
    "volume names (C3, C11)": VOLUME,
    "mount points (C3, C11)": MOUNT,
    "disk and volume UUIDs (C11)": DISK_UUID,
    "display name (C4)": DISPLAY_NAME,
    "display serial (C4)": DISPLAY_SERIAL,
    "battery serial and lot codes (C6)": BATTERY_SERIAL,
    "apps in scheduled wake events (C6)": WAKE_APP,
    "gauge serial (C7)": GAUGE_SERIAL,
    "panic file names (R1)": PANIC_APP,
    "process names (P1)": PROCESS,
    "boot arguments (S4)": BOOT_ARG,
    "text replacements (R3)": TEXT_REPLACEMENT,
    "account name": ACCOUNT,
    "host name": HOST,
}
SINKS: Final = ("stdout", "stderr", "PDF text", "PDF bytes", "JSON")

# What the fake sudo prints, each message naming the account and the host: a lecture the
# Mac's administrator set, at every step that goes through, and where one does not, sudo's
# own refusals (Decision 2's pinned templates) or a line it has no template for.
LECTURE = f"{HOST} is a managed Mac. {ACCOUNT}, every sudo call is logged.\n"
REFUSED_PROMPT = f"Sorry, user {ACCOUNT} may not run sudo on {HOST}.\n"
REFUSED_COUNT = (
    f"Sorry, user {ACCOUNT} is not allowed to execute '/usr/bin/sandbox-exec -p "
    f"{allowlist.PROFILE} /usr/bin/sqlite3' as _mmaintenanced on {HOST}.\n"
)
REFUSED_SAMPLE = (
    f"Sorry, user {ACCOUNT} is not allowed to execute '/usr/bin/sandbox-exec -p "
    f"{allowlist.PROFILE} /usr/bin/powermetrics' as root on {HOST}.\n"
)
CLEAR_FAILED = f"sudo: {ACCOUNT}: unable to resolve host {HOST}: nodename nor servname provided\n"
# The text of a bug's error, naming every canary; the run names a bug by a fixed line alone.
BUG = " ".join([SERIAL, *CANARIES.values()])

# The real R1 and R3, which the fake M5 stands in for: here they read the planted folder and
# the planted preferences file.
_PANIC_COUNT = in_process.panic_count
_PAPER = in_process.paper

# --- what the fake M5 answers with ------------------------------------------------------------


def _m5(command_id: str) -> str:
    return (fm.M5 / f"{command_id}.out").read_text()


def _json(command_id: str, plant: Callable[[dict], None]) -> str:
    document = json.loads(_m5(command_id))
    plant(document)
    return json.dumps(document, indent=2)


def _plist(command_id: str, plant: Callable[[object], None]) -> str:
    document = plistlib.loads(_m5(command_id).encode())
    plant(document)
    return plistlib.dumps(document).decode()


def _hardware(document: dict) -> None:
    entry = document["SPHardwareDataType"][0]
    entry["serial_number"] = SERIAL
    entry["platform_UUID"] = PLATFORM_UUID
    entry["provisioning_UDID"] = PROVISIONING_UDID


def _nvme(document: dict) -> None:
    entry = document["SPNVMeDataType"][0]["_items"][0]
    entry["device_serial"] = SSD_SERIAL
    for number, volume in enumerate(entry["volumes"], start=1):
        volume["_name"] = f"{VOLUME}{number}"
        volume["mount_point"] = f"/Volumes/{MOUNT}{number}"


def _displays(document: dict) -> None:
    display = document["SPDisplaysDataType"][0]["spdisplays_ndrvs"][0]
    display["_name"] = DISPLAY_NAME
    display["_spdisplays_display-serial-number"] = DISPLAY_SERIAL


def _power(document: dict) -> None:
    entries = {entry["_name"]: entry for entry in document["SPPowerDataType"]}
    battery = entries["spbattery_information"]["sppower_battery_model_info"]
    battery["sppower_battery_serial_number"] = BATTERY_SERIAL
    battery["sppower_battery_pack_lot_code"] = f"{BATTERY_SERIAL}PACK"
    battery["sppower_battery_pcb_lot_code"] = f"{BATTERY_SERIAL}PCB"
    events = entries["sppower_events_info"]["_items"][0]["_items"]
    for number, event in enumerate(events, start=1):
        event["scheduledby"] = f"com.example.{WAKE_APP}{number}"


def _gauge(document: object) -> None:
    assert isinstance(document, list)
    document[0]["Serial"] = GAUGE_SERIAL
    document[0]["BatteryData"]["Serial"] = GAUGE_SERIAL


def _volume(document: object) -> None:
    assert isinstance(document, dict)
    document["VolumeName"] = f"{VOLUME}C11"
    document["MountPoint"] = f"/Volumes/{MOUNT}C11"
    for number, key in enumerate(
        ("DiskUUID", "VolumeUUID", "APFSVolumeGroupID", "APFSSnapshotUUID"), start=1
    ):
        document[key] = f"{DISK_UUID}{number}"


# The user reads whose output carries an identifier, each with its canaries planted.
PLANTED: Final = {
    "C2": _json("C2", _hardware),
    "C3": _json("C3", _nvme),
    "C4": _json("C4", _displays),
    "C6": _json("C6", _power),
    "C7": _plist("C7", _gauge),
    "C11": _plist("C11", _volume),
    "C14": f"FileVault is On.\nDeferred enablement appears to be active for user '{ACCOUNT}'.\n",
}
# The power sample with boot arguments in each of its five headers, as powermetrics prints them.
POWER_SAMPLE: Final = fm.SAMPLE_E.replace("synthetic-bootargs", f"debug=0x144 {BOOT_ARG}=1")
# R1's folder: two panic reports and a crash report, named with the host and an app.
PANIC_FILES: Final = (
    f"Kernel-2026-09-01-101010-{HOST}.panic",
    f"{PANIC_APP}-2026-09-02-080000-{HOST}.panic",
    f"{PANIC_APP}-2026-09-03-090000.ips",
)

Row = tuple[int, int, int, str, str]


def _ps(*rows: Row) -> str:
    """A listing as P1 prints it: ps's header, then one row per process."""
    lines = ["  PID  PPID   UID STARTED                      COMM"]
    lines += [
        f"{pid:>5} {ppid:>5} {uid:>5} {started}     {comm}"
        for pid, ppid, uid, started, comm in rows
    ]
    return "\n".join(lines) + "\n"


def _others(home: Path) -> list[Row]:
    """What P1 sees besides Voltry's own: an app, and a tool in the home folder."""
    app = f"/Applications/{PROCESS}Mail.app/Contents/MacOS/{PROCESS}Mail"
    return [
        (1, 0, 0, "Fri Aug 28 08:00:54 2026", "/sbin/launchd"),
        (612, 1, 501, "Wed Sep 23 13:58:02 2026", app),
        (733, 1, 501, "Wed Sep 23 14:01:10 2026", f"{home}/bin/{PROCESS}Sync"),
    ]


def _survivors(home: Path) -> tuple[tracking.Survivor, ...]:
    """The survivors the listing after the power sample names, by the tracker's own rules:
    while the sample ran P1 saw sudo's subtree, with a process under sandbox-exec whose name
    is a canary, and after it sandbox-exec and that process still run."""
    helper = f"{home}/bin/{PROCESS}Helper"
    during = [
        (900, 850, 0, "Wed Sep 23 14:05:40 2026", "/usr/bin/sudo"),
        (901, 900, 0, "Wed Sep 23 14:05:40 2026", "/usr/bin/sandbox-exec"),
        (902, 901, 0, "Wed Sep 23 14:05:41 2026", "/usr/bin/powermetrics"),
        (903, 901, 0, "Wed Sep 23 14:05:41 2026", helper),
    ]
    after = [
        (901, 1, 0, "Wed Sep 23 14:05:40 2026", "/usr/bin/sandbox-exec"),
        (903, 1, 0, "Wed Sep 23 14:05:41 2026", helper),
    ]
    tracker = tracking.Tracker(
        spawned=900,
        payload=tracking.Payload(uid=0, name="powermetrics"),
        runtime_s=tracking.RUNTIME_S["S4"],
        now=0.0,
    )
    tracker.apply(listing.processes(_ps(*_others(home), *during)), tracking.POLL_S)
    return tracking.survivors(tracker.records, listing.processes(_ps(*_others(home), *after)))


def _plant(
    mac: fm.Mac, monkeypatch: pytest.MonkeyPatch, folder: Path
) -> list[tuple[str, tuple[str, ...]]]:
    """Every canary into the fake M5, its home folder and the reads made in-process; returns
    the list the chokepoint's argvs are recorded in, by command ID."""
    for command_id, text in PLANTED.items():
        mac.results[command_id] = fm.result(command_id, stdout=text)
    mac.results["P1"] = fm.result("P1", stdout=_ps(*_others(mac.home)))  # the capability check
    for command_id in ("S1", "S2", "S2n", "S5"):
        mac.results[command_id] = fm.result(command_id, stderr=LECTURE)
    mac.payloads["S3"] = fm.payload_run("S3", stderr=LECTURE)
    mac.payloads["S4"] = fm.payload_run("S4", stdout=POWER_SAMPLE, stderr=LECTURE)
    # R1 lists a folder of planted names, and R3 reads a planted file in the home folder.
    reports = folder / "DiagnosticReports"
    reports.mkdir()
    for name in PANIC_FILES:
        (reports / name).write_bytes(b"")
    monkeypatch.setattr(in_process, "panic_count", lambda *args: _PANIC_COUNT(str(reports)))
    preferences = mac.home / "Library" / "Preferences"
    preferences.mkdir(parents=True)
    (preferences / ".GlobalPreferences.plist").write_bytes(
        plistlib.dumps(
            {
                "AppleLocale": "en_US",
                "NSNavLastRootDirectory": str(mac.home / "Documents"),
                "NSUserDictionaryReplacementItems": [
                    {"on": 1, "replace": "omw", "with": TEXT_REPLACEMENT}
                ],
            }
        )
    )
    monkeypatch.setattr(in_process, "paper", _PAPER)
    # The interpreter where uv installs the tool, inside the home folder.
    interpreter = mac.home / ".local" / "share" / "uv" / "tools" / "voltry-mac" / "bin" / "python3"
    monkeypatch.setattr(sys, "executable", str(interpreter))
    argvs: list[tuple[str, tuple[str, ...]]] = []
    answer = spawn._execute  # the fake M5's

    def execute(argv, **kwargs):  # type: ignore[no-untyped-def]
        argvs.append((kwargs["command_id"], tuple(argv)))
        return answer(argv, **kwargs)

    monkeypatch.setattr(spawn, "_execute", execute)
    return argvs


# --- the scenarios --------------------------------------------------------------------------

Setup = Callable[..., None]


def _prompt_refused(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    mac.results["S2"] = fm.result("S2", 1, stderr=REFUSED_PROMPT)


def _payloads_refused(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    # What the fake printed on stdout stays planted; after a refusal no one reads it.
    for command_id, refusal in (("S3", REFUSED_COUNT), ("S4", REFUSED_SAMPLE)):
        found = mac.payloads[command_id]
        mac.payloads[command_id] = dataclasses.replace(found, returncode=1, stderr=refusal)


def _reads_fail(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    # Each read that carries an identifier exits 1 and says it all again on stderr.
    for command_id in PLANTED:
        found = mac.results[command_id]
        mac.results[command_id] = dataclasses.replace(found, returncode=1, stderr=found.stdout)


def _clear_fails(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    mac.results["S5"] = fm.result("S5", 1, stderr=CLEAR_FAILED)


def _survivor(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    mac.payloads["S4"] = dataclasses.replace(
        mac.payloads["S4"], cleanup="survivor", survivors=_survivors(mac.home)
    )


def _unverified(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    mac.payloads["S3"] = dataclasses.replace(mac.payloads["S3"], cleanup="listing_failed")


def _desktop_refused(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    real = writer._open_folder

    def refusing(path):  # type: ignore[no-untyped-def]
        if path == str(mac.desktop):
            raise PermissionError(errno.EPERM, os.strerror(errno.EPERM))
        return real(path)

    monkeypatch.setattr(writer, "_open_folder", refusing)


def _home_refused_too(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    def open_folder(path):  # type: ignore[no-untyped-def]
        if path == str(mac.desktop):
            raise PermissionError(errno.EPERM, os.strerror(errno.EPERM))
        raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))

    monkeypatch.setattr(writer, "_open_folder", open_folder)


def _reports_folder(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    (mac.home / "Documents" / "Reports").mkdir(parents=True)


def _temporary_stays(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    real = writer._unlink

    def unlink(folder_fd, name):  # type: ignore[no-untyped-def]
        if name.startswith(".voltry-mac-"):
            raise OSError(errno.EBUSY, os.strerror(errno.EBUSY))
        real(folder_fd, name)

    monkeypatch.setattr(writer, "_unlink", unlink)


def _documents(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    (mac.home / "Documents").mkdir()


def _home_through_a_link(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    # The home folder the account database names is a symlink to the folder itself, whose
    # path holds both names too, and the run starts there: --output . saves in a path that
    # names the folder, not the link (the review of #326, round 2, m1 and n8).
    itself = folder / "Volumes" / "Data" / HOST / ACCOUNT
    itself.parent.mkdir(parents=True)
    mac.home.rename(itself)
    mac.home.symlink_to(itself)
    monkeypatch.chdir(mac.home)


def _report(mac: fm.Mac, document: dict) -> None:
    """A report saved in ~/Documents, from this version, with its ID made again."""
    document["tool"]["version"] = voltry_mac.__version__
    (mac.home / "Documents").mkdir()
    (mac.home / "Documents" / "report.json").write_text(
        canonical.canonical_json(r.rehash(document)), encoding="utf-8"
    )


def _saved_report(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    _report(mac, r.load("m5-laptop"))


def _refused_report(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    # The whole serial where its last four belong, which render refuses, after a machine name
    # and a time zone it accepts: the refusal names the field and no value.
    document = r.load("m5-laptop")
    document["time_zone"] = HOST
    r.set_value(document, "hardware_overview", "machine_name", ACCOUNT)
    r.set_value(document, "hardware_overview", "serial_last4", SERIAL)
    _report(mac, document)


def _no_terminal(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    monkeypatch.setattr(preflight, "terminal", lambda: False)  # so --yes takes the -n forms


def _too_little(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    for command_id in allowlist.USER_COMMAND_IDS:
        if command_id not in ("C1", "C12"):
            found = mac.results.get(command_id) or fm.result(command_id)
            mac.results[command_id] = dataclasses.replace(found, returncode=1, stderr=found.stdout)


def _bug(owner: object, name: str, *, stopped: bool = False) -> Setup:
    """A bug in ``owner.name`` whose error names every canary; with ``stopped``, a Ctrl-C
    comes just before it."""

    def setup(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
        def broken(*args, **kwargs):  # type: ignore[no-untyped-def]
            if stopped:
                os.kill(os.getpid(), signal.SIGINT)
            raise RuntimeError(BUG)

        monkeypatch.setattr(owner, name, broken)

    return setup


def _render_bug(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    _saved_report(mac, monkeypatch, folder)
    _bug(report_pdf, "render")(mac, monkeypatch, folder)


# Ctrl-C at each point a run can stop, by the copy goldens' own setups (tests/copy_golden.py).


def _stopped_sample(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    # Ctrl-C as the power sample runs, which stops it with a canary process still running;
    # what the sample printed stays planted, and a cancelled payload's output is never read.
    mac.before["S4"] = lambda: os.kill(os.getpid(), signal.SIGINT)
    mac.payloads["S4"] = dataclasses.replace(
        mac.payloads["S4"],
        cancelled=True,
        returncode=None,
        cleanup="survivor",
        survivors=_survivors(mac.home),
    )


def _stopped_below_the_gate(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    # Ctrl-C once the reads are done, with too little read to save a report: the save gate
    # refuses, and the stop comes first, 130 before 4.
    _too_little(mac, monkeypatch, folder)
    real = model.save_gate

    def gate(surfaces):  # type: ignore[no-untyped-def]
        os.kill(os.getpid(), signal.SIGINT)
        return real(surfaces)

    monkeypatch.setattr(model, "save_gate", gate)


def _stopped_save(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    # Ctrl-C as the first temporary is written, the JSON's, which is left behind: the save
    # reads the flag once the JSON is published, and stops.
    golden._signal_in_save(mac, monkeypatch, folder)
    _temporary_stays(mac, monkeypatch, folder)


def _render(*setups: Setup) -> Setup:
    return golden._all(_saved_report, *setups)


@dataclasses.dataclass(frozen=True)
class Scenario:
    """A command line and what the fake M5 does differently for it, as in
    tests/copy_golden.py (``{home}`` in an argument is the fake home folder); its exit code;
    the files it saves; facts its saved JSON records, by dotted path; a message it must print
    and a line naming a path under the home folder, each as the stream and the text."""

    name: str
    argv: tuple[str, ...]
    setup: Setup | None = None
    code: int = 0
    saves: tuple[str, ...] = ("JSON", "PDF")
    facts: tuple[tuple[str, object], ...] = ()
    says: tuple[str, str] | None = None
    names: tuple[str, str] | None = None


FLAGS = ("--json", "--debug")
ENOENT = os.strerror(errno.ENOENT)
SAVED = f"Saved: ~/Desktop/{fm.JSON_NAME}\nSaved: ~/Desktop/{fm.PDF_NAME}\n{run.OPENING}"
ALLOWED = Scenario(
    "the reads allowed",
    FLAGS,
    facts=(
        ("elevation.consent", "yes"),
        ("elevation.count.ending", "parsed"),
        ("elevation.power.ending", "parsed"),
        ("elevation.cleared", "cleared"),
    ),
    names=("stdout", SAVED),
)
SHOW_SERIAL = Scenario("--show-serial", (*FLAGS, "--show-serial"), names=("stdout", SAVED))
SURVIVOR = Scenario(
    "a canary process outlives the power sample",
    FLAGS,
    _survivor,
    code=1,
    facts=(("elevation.power.cleanup", "survivor"),),
)
STOPPED = ("stderr", run.STOPPED)
# Two stops no run reached, so a leak planted in either message passed every test (the
# review of #326, round 2, m2).
STOPPED_BY_A_BUG = Scenario(
    "Ctrl-C, then an unexpected error",
    FLAGS,
    _bug(assemble, "surfaces", stopped=True),
    code=130,
    saves=(),
    says=STOPPED,
)
STOPPED_BELOW_THE_GATE = Scenario(
    "Ctrl-C with too little read to save a report",
    FLAGS,
    _stopped_below_the_gate,
    code=130,
    saves=(),
    says=STOPPED,
)
SAVED_NOT_OPENED = f"Saved: ~/Desktop/{fm.JSON_NAME}\nSaved: ~/Desktop/{fm.PDF_NAME}\n"
RENDERED = f"Saved: ~/Desktop/{fm.PDF_NAME}"
SCENARIOS: tuple[Scenario, ...] = (
    ALLOWED,
    SHOW_SERIAL,
    Scenario(
        "sudo refuses the prompt",
        FLAGS,
        _prompt_refused,
        facts=(("elevation.authenticate", "refused"), ("elevation.cleared", "cleared")),
    ),
    Scenario(
        "sudo refuses both payloads",
        FLAGS,
        _payloads_refused,
        facts=(
            ("elevation.count.ending", "policy_refusal"),
            ("elevation.power.ending", "policy_refusal"),
        ),
        says=("stdout", f"{run.COUNTING}{run.NOT_READ}\n{run.SAMPLING}{run.NOT_READ}\n"),
    ),
    Scenario(
        "--yes with no terminal",
        (*FLAGS, "--yes"),
        _no_terminal,
        facts=(
            ("elevation.consent", "flag"),
            ("elevation.mode", "noninteractive"),
            ("elevation.count.ending", "parsed"),
            ("elevation.power.ending", "parsed"),
        ),
    ),
    Scenario(
        "the reads that carry identifiers fail",
        FLAGS,
        _reads_fail,
        code=1,
        facts=(("collection.unexpected_reasons", ["tool_error"]),),
    ),
    Scenario(
        "too little read to save a report",
        FLAGS,
        _too_little,
        code=4,
        saves=(),
        says=("stderr", run.NOT_ENOUGH),
    ),
    Scenario(
        "the final clear fails",
        FLAGS,
        _clear_fails,
        code=6,
        facts=(("elevation.cleared", "failed"), ("elevation.clear_error", "nonzero_exit")),
        says=("stderr", run.WARNING),
    ),
    SURVIVOR,
    Scenario(
        "a stop that could not be verified",
        FLAGS,
        _unverified,
        code=1,
        facts=(("elevation.count.cleanup", "listing_failed"),),
        says=("stderr", tracking.UNVERIFIED_NOTE),
    ),
    Scenario(
        "macOS refuses the Desktop",
        FLAGS,
        _desktop_refused,
        names=(
            "stdout",
            f"{run.FALLBACK_BEFORE}\n  ~/{fm.JSON_NAME}\n  ~/{fm.PDF_NAME}\n"
            f"{run.FALLBACK_AFTER}",
        ),
    ),
    Scenario(
        "--output a folder under the home folder",
        (*FLAGS, "--output", "{home}/Documents/Reports"),
        _reports_folder,
        names=(
            "stdout",
            f"Saved: ~/Documents/Reports/{fm.JSON_NAME}\n"
            f"Saved: ~/Documents/Reports/{fm.PDF_NAME}",
        ),
    ),
    Scenario(
        "--output a missing folder under the home folder",
        (*FLAGS, "--output", "{home}/Documents/Gone"),
        _documents,
        code=4,
        saves=(),
        names=("stderr", run.NOT_SAVED_IN.format(reason=ENOENT, folder="~/Documents/Gone")),
    ),
    Scenario(
        "--output . in a home folder reached through a symlink",
        (*FLAGS, "--output", "."),
        _home_through_a_link,
        names=("stdout", f"Saved: ~/{fm.JSON_NAME}\nSaved: ~/{fm.PDF_NAME}\n{run.OPENING}"),
    ),
    Scenario(
        "macOS refuses the Desktop, and the home folder fails",
        FLAGS,
        _home_refused_too,
        code=4,
        saves=(),
        # The line says in words that the home folder failed too, and names no path.
        names=("stderr", run.NOT_SAVED_HOME.format(reason=os.strerror(errno.ENOSPC))),
    ),
    Scenario(
        "a temporary the save cannot remove",
        FLAGS,
        _temporary_stays,
        code=4,
        saves=(),
        names=("stderr", f"{run.LEFT_ONE}\n  ~/Desktop/.voltry-mac-"),
    ),
    Scenario(
        "the PDF cannot be drawn",
        FLAGS,
        _bug(report_pdf, "render"),
        code=4,
        saves=(),
        says=("stderr", run.PDF_BUG),
    ),
    Scenario(
        "an unexpected error",
        FLAGS,
        _bug(assemble, "surfaces"),
        code=4,
        saves=(),
        says=("stderr", run.UNEXPECTED),
    ),
    Scenario(
        "Ctrl-C during the user reads",
        FLAGS,
        golden._signal_at("C5"),
        code=130,
        saves=(),
        says=STOPPED,
    ),
    Scenario(
        "Ctrl-C at the question", FLAGS, golden._cancelled_answer, code=130, saves=(), says=STOPPED
    ),
    Scenario(
        "Ctrl-C during the power sample, a canary process outliving it",
        FLAGS,
        _stopped_sample,
        code=130,
        saves=(),
        says=STOPPED,
    ),
    STOPPED_BY_A_BUG,
    STOPPED_BELOW_THE_GATE,
    Scenario(
        "Ctrl-C during the save, a temporary left",
        FLAGS,
        _stopped_save,
        code=130,
        saves=(),
        says=STOPPED,
        names=("stderr", f"{run.LEFT_ONE}\n  ~/Desktop/.voltry-mac-"),
    ),
    Scenario(
        "Ctrl-C once the report is saved",
        FLAGS,
        golden._signal_after_save,
        code=130,
        says=("stderr", run.STOPPED_SAVED),
        names=("stdout", SAVED_NOT_OPENED),
    ),
    Scenario(
        "Ctrl-C just before the report opens",
        FLAGS,
        golden._signal_before_open,
        code=130,
        says=("stderr", run.STOPPED_SAVED),
        names=("stdout", SAVED_NOT_OPENED),
    ),
    Scenario(
        "Ctrl-C as the report opens",
        FLAGS,
        golden._open_stopped,
        code=130,
        says=("stderr", run.STOPPED_OPENING),
        names=("stdout", SAVED_NOT_OPENED),
    ),
    Scenario(
        "render a saved report",
        ("render", "{home}/Documents/report.json"),
        _saved_report,
        saves=("PDF",),
        names=("stdout", RENDERED),
    ),
    Scenario(
        "render, Ctrl-C during the save",
        ("render", "{home}/Documents/report.json"),
        _render(golden._signal_in_save),
        code=130,
        saves=(),
        says=STOPPED,
    ),
    Scenario(
        "render, Ctrl-C once the PDF is saved",
        ("render", "{home}/Documents/report.json"),
        _render(golden._signal_after_save),
        code=130,
        saves=("PDF",),
        says=("stderr", run.RENDER_STOPPED_SAVED),
        names=("stdout", RENDERED),
    ),
    Scenario(
        "render, Ctrl-C just before the PDF opens",
        ("render", "{home}/Documents/report.json"),
        _render(golden._signal_before_open),
        code=130,
        saves=("PDF",),
        says=("stderr", run.RENDER_STOPPED_SAVED),
        names=("stdout", RENDERED),
    ),
    Scenario(
        "render, Ctrl-C as the PDF opens",
        ("render", "{home}/Documents/report.json"),
        _render(golden._open_stopped),
        code=130,
        saves=("PDF",),
        says=("stderr", run.RENDER_STOPPED_OPENING),
        names=("stdout", RENDERED),
    ),
    Scenario(
        "render a file it cannot read",
        ("render", "{home}/Documents/missing.json"),
        _documents,
        code=2,
        saves=(),
        names=("stderr", run.UNREADABLE.format(reason=ENOENT, path="~/Documents/missing.json")),
    ),
    Scenario(
        "render a PDF it cannot draw",
        ("render", "{home}/Documents/report.json"),
        _render_bug,
        code=4,
        saves=(),
        says=("stderr", run.RENDER_PDF_BUG),
    ),
    Scenario(
        "render a report it refuses",
        ("render", "{home}/Documents/report.json"),
        _refused_report,
        code=2,
        saves=(),
        names=(
            "stderr",
            run.RENDER_REFUSED_AT.format(
                problem="must be exactly four characters",
                field="surfaces[1].values.serial_last4.value",
                path="~/Documents/report.json",
            ),
        ),
    ),
)
COLLECTING = [scenario for scenario in SCENARIOS if scenario.argv[0] != "render"]
NAMING = [scenario for scenario in SCENARIOS if scenario.names is not None]


# --- running them -----------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Ran:
    """What one scenario gave: its exit code; everything planted for it, as text; the fake
    home folder; the commands the fake M5 ran, and the argvs the chokepoint handed it; and
    each sink's text: stdout, stderr, and the PDF's text and bytes and the JSON when saved."""

    code: int
    planted: str
    home: str
    commands: tuple[str, ...]
    argvs: tuple[tuple[str, tuple[str, ...]], ...]
    sinks: Mapping[str, str]

    def document(self) -> dict:
        return json.loads(self.sinks["JSON"])


def _sinks(out: str, err: str, made: Sequence[Path]) -> dict[str, str]:
    sinks = {"stdout": out, "stderr": err}
    for path in made:
        if path.suffix == ".pdf":
            data = path.read_bytes()
            reader = pypdf.PdfReader(io.BytesIO(data), strict=True)
            sinks["PDF text"] = " ".join(page.extract_text() for page in reader.pages)
            # The file, each content stream decompressed, and the strings the streams draw
            # joined with nothing between: a word the layout broke across two lines, each
            # piece its own string, reads whole.
            streams = [stream.decode("latin-1") for stream in pages.streams(data)]
            drawn = "".join(pages.strings(data))
            sinks["PDF bytes"] = "\n".join([data.decode("latin-1"), *streams, drawn])
        elif path.suffix == ".json":
            sinks["JSON"] = path.read_text(encoding="utf-8")
    return sinks


def _run(scenario: Scenario, folder: Path) -> Ran:
    """One scenario: the real command line on a fake M5 with every canary planted. The home
    folder is a network home, /Network/Servers/<host>/Users/<account>, under ``folder``, so
    every path in it holds both names."""
    home = folder / "Network" / "Servers" / HOST / "Users" / ACCOUNT
    (home / "Desktop").mkdir(parents=True)
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.chdir(folder)
        mac = fm.Mac(monkeypatch, home)
        argvs = _plant(mac, monkeypatch, folder)
        if scenario.setup is not None:
            scenario.setup(mac, monkeypatch, folder)
        before = set(folder.rglob("*"))
        argv = [word.replace("{home}", str(home)) for word in scenario.argv]
        planted = [
            *(f"{found.stdout}\n{found.stderr}" for found in mac.results.values()),
            *(f"{found.stdout}\n{found.stderr}" for found in mac.payloads.values()),
            *(survivor.name for found in mac.payloads.values() for survivor in found.survivors),
            *(str(path) for path in before),
            *(path.read_text() for path in before if path.suffix in (".plist", ".json")),
            *argv,
        ]
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(argv)
        made = sorted(set(folder.rglob("*")) - before)
    return Ran(
        code,
        "\n".join(planted),
        str(home),
        tuple(mac.ran),
        tuple(argvs),
        _sinks(out.getvalue(), err.getvalue(), made),
    )


# Each scenario runs once, in the tmp_path of the first test that asks for it; every test then
# reads what it printed and saved.
_RAN: dict[str, Ran] = {}


@pytest.fixture
def ran(tmp_path) -> Callable[[Scenario], Ran]:  # type: ignore[no-untyped-def]
    def get(scenario: Scenario) -> Ran:
        if scenario.name not in _RAN:
            _RAN[scenario.name] = _run(scenario, tmp_path / f"run{SCENARIOS.index(scenario):02d}")
        return _RAN[scenario.name]

    return get


def _found(canary: str, text: str) -> bool:
    """Whether the canary is in the text, case ignored, with the whitespace taken out of
    both: the terminal and the PDF break a long word by width, a path most of all, so a name
    in it can end one line and start the next."""
    return "".join(canary.split()).casefold() in "".join(text.split()).casefold()


def _flat(text: str) -> str:
    """Text with its line breaks and runs of spaces as single spaces, as it reads."""
    return re.sub(r"\s+", " ", text)


def _at(document: Mapping[str, object], path: str) -> object:
    found: object = document
    for key in path.split("."):
        assert isinstance(found, Mapping)
        found = found[key]
    return found


def _shown(scenario: Scenario, source: str, sink: str) -> bool:
    """The one place a canary may print: the whole serial with --show-serial, in the terminal,
    the PDF and the JSON (the field inventory: "the serial prints in full in all three
    places")."""
    return scenario is SHOW_SERIAL and source == SERIAL_SOURCE and sink != "stderr"


# --- the plant ------------------------------------------------------------------------------


@pytest.mark.parametrize("scenario", COLLECTING, ids=[s.name for s in COLLECTING])
def test_every_canary_is_planted_in_every_collecting_run(ran, scenario):
    planted = ran(scenario).planted
    assert [source for source, canary in CANARIES.items() if canary not in planted] == []


def test_the_run_reads_what_was_planted(ran):
    done = ran(ALLOWED)
    assert done.commands == (*allowlist.USER_COMMAND_IDS, *fm.ELEVATED, "O1")
    # --debug named each command on stderr, and nothing else is there.
    assert [line.split(" ", 1)[0] for line in done.sinks["stderr"].splitlines()] == list(
        done.commands
    )
    # The chokepoint handed C28 the interpreter and O1 the report, both in the home folder.
    argvs = dict(done.argvs)
    assert argvs["C28"][0].startswith(f"{done.home}/")
    assert argvs["O1"][-1] == f"{done.home}/Desktop/{fm.PDF_NAME}"
    document = done.document()
    assert r.values(document, "hardware_overview")["serial_last4"]["value"] == LAST4  # C2
    assert r.values(document, "filevault_status")["enabled"]["value"] is True  # C14
    assert document["elevation"]["checks"]["listing"] == "ok"  # P1's listing parsed
    assert r.surface(document, "power_and_thermal_samples")["availability"] == "available"  # S4
    assert r.values(document, "panic_report_count")["count"]["value"] == 2  # R1's two .panic
    assert document["render"] == {"paper": "letter"}  # R3 read en_US; with no file it is a4


# --- each run, and the paths it names ---------------------------------------------------------


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s.name for s in SCENARIOS])
def test_each_run_takes_its_path(ran, scenario):
    done = ran(scenario)
    assert done.code == scenario.code
    expected = {"stdout", "stderr"}
    if "PDF" in scenario.saves:
        expected |= {"PDF text", "PDF bytes"}
    if "JSON" in scenario.saves:
        expected.add("JSON")
        document = validate.read(done.sinks["JSON"].encode())
        for path, value in scenario.facts:
            assert _at(document, path) == value, path
    assert set(done.sinks) == expected
    if scenario.says is not None:
        stream, text = scenario.says
        assert _flat(text) in _flat(done.sinks[stream])


@pytest.mark.parametrize("scenario", NAMING, ids=[s.name for s in NAMING])
def test_a_path_under_the_home_folder_prints_with_a_tilde(ran, scenario):
    done = ran(scenario)
    assert scenario.names is not None
    stream, text = scenario.names
    assert _flat(text) in _flat(done.sinks[stream])
    assert done.home not in done.sinks["stdout"] + done.sinks["stderr"]


@pytest.mark.parametrize(
    "scenario",
    [STOPPED_BY_A_BUG, STOPPED_BELOW_THE_GATE],
    ids=[STOPPED_BY_A_BUG.name, STOPPED_BELOW_THE_GATE.name],
)
def test_a_stop_that_meets_a_bug_or_the_save_gate_says_only_that_it_stopped(ran, scenario):
    # The review of #326, round 2, m2: --debug's lines aside, the stop line is the one
    # message; neither the bug's fixed line nor the save gate's words print.
    done = ran(scenario)
    said = [
        line
        for line in done.sinks["stderr"].splitlines()
        if line.split(" ", 1)[0] not in allowlist.BY_ID
    ]
    assert (done.code, said) == (130, [run.STOPPED])


# --- the matrix -------------------------------------------------------------------------------

MATRIX = [(source, sink) for source in CANARIES for sink in SINKS]


@pytest.mark.parametrize(
    ("source", "sink"), MATRIX, ids=[f"{source}, {sink}" for source, sink in MATRIX]
)
def test_no_canary_reaches_a_sink(ran, source, sink):
    runs = [(scenario, ran(scenario)) for scenario in SCENARIOS]
    read = [scenario.name for scenario, done in runs if sink in done.sinks]
    assert read, f"no run gave {sink}"
    found = [
        scenario.name
        for scenario, done in runs
        if sink in done.sinks
        and _found(CANARIES[source], done.sinks[sink])
        and not _shown(scenario, source, sink)
    ]
    assert found == [], f"{source} reached {sink}"


@pytest.mark.parametrize("compress", [False, True], ids=["as saved", "compressed"])
def test_a_canary_wrapped_across_two_lines_is_found_in_each_sink(tmp_path, compress):
    # The review of #326, round 1, M4: the layout breaks a long word by width, so a path in
    # the PDF drew "/Servers/Cnry-MacBook-Pr" on one line and "o/Users/cnryaccount/" on the
    # next, and neither PDF sink found the host name. Decision 4 allows a compressed stream.
    page = pdf.Page(pdf.LETTER)
    wrapped = (f"/Network/Servers/{HOST[:-1]}", f"{HOST[-1]}/Users/{ACCOUNT[:4]}", ACCOUNT[4:])
    for number, line in enumerate(wrapped):
        page.text(50, 700 - 12 * number, line, font=pdf.HELVETICA, size=9.5, color=layout.INK)
    path = tmp_path / "wrapped.pdf"
    path.write_bytes(
        pdf.document(
            [page],
            title="Mac hardware observation report",
            producer="voltry-mac 0.1.0",
            created="D:20260923140531-07'00'",
            identifier=bytes(32),
            compress=compress,
        )
    )
    shown = f"  Model  /Network/Servers/{HOST[:4]}\n         {HOST[4:]}/Users/{ACCOUNT}\n"
    sinks = _sinks(shown, "", [path])
    for sink in ("stdout", "PDF text", "PDF bytes"):
        assert _found(HOST, sinks[sink]) and _found(ACCOUNT, sinks[sink]), sink
    assert not _found(PROCESS, sinks["PDF bytes"])


def test_a_canary_in_another_case_is_found():
    # The review of #326, round 2, n3: the terminal prints section titles in capitals, so
    # a search that kept case would miss a canary printed in one.
    assert _found(ACCOUNT, f"THIS MAC ON /USERS/{ACCOUNT.upper()}")
    assert _found(HOST, f"/network/servers/{HOST.lower()}/users")


def test_a_canary_drawn_with_tj_is_found_in_a_compressed_stream(tmp_path):
    # Round 2, n3: the writer draws each string with Tj, which pages.strings reads. A string
    # drawn with TJ, the array form, shows in a compressed PDF only in its stream, once the
    # stream is decompressed.
    page = pdf.Page(pdf.LETTER)
    page._operations.append(f"BT /F1 9.5 Tf 50 700 Td [(Host) -250 ({HOST})] TJ ET")
    path = tmp_path / "tj.pdf"
    data = pdf.document(
        [page],
        title="Mac hardware observation report",
        producer="voltry-mac 0.1.0",
        created="D:20260923140531-07'00'",
        identifier=bytes(32),
        compress=True,
    )
    path.write_bytes(data)
    assert not _found(HOST, data.decode("latin-1")) and pages.strings(data) == []
    assert _found(HOST, _sinks("", "", [path])["PDF bytes"])


# --- the two exceptions -----------------------------------------------------------------------


@pytest.mark.parametrize("sink", ["stdout", "PDF text", "PDF bytes", "JSON"])
def test_by_default_the_serial_shows_its_last_four_characters_and_no_more(ran, sink):
    said = ran(ALLOWED).sinks[sink]
    if sink == "JSON":
        values = r.values(json.loads(said), "hardware_overview")
        assert values["serial_last4"]["value"] == LAST4
        assert "serial_number" not in values
    elif sink == "stdout":
        assert f"Serial number ending in {LAST4} (add --show-serial to print it)" in _flat(said)
    else:
        assert f"ending in {LAST4}" in _flat(said)
    assert not _found(SERIAL[:-4], said)


@pytest.mark.parametrize("sink", SINKS)
def test_show_serial_prints_the_whole_serial_in_the_terminal_the_pdf_and_the_json_only(ran, sink):
    said = ran(SHOW_SERIAL).sinks[sink]
    # stderr carries --debug and every message, and never the serial.
    assert (SERIAL in said) is (sink != "stderr")
    if sink == "JSON":
        values = r.values(json.loads(said), "hardware_overview")
        assert (values["serial_number"]["value"], values["serial_last4"]["value"]) == (
            SERIAL,
            LAST4,
        )


def test_a_surviving_canary_process_is_an_unexpected_process_and_a_subtree_name_itself(ran):
    said = _flat(ran(SURVIVOR).sinks["stderr"])
    canary = "process 903, an unexpected process, user ID 0, started Wed Sep 23 14:05:41 2026."
    subtree = "process 901, sandbox-exec, user ID 0, started Wed Sep 23 14:05:40 2026."
    assert canary in said and subtree in said
    assert said.count("A process from the administrator reads may still be running") == 2
    assert not _found(PROCESS, said)
