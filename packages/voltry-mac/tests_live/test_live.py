"""The live runs on GitHub's macOS runners (docs/VOLTRY_MAC_SPEC.md, Test strategy part 5,
"Live macOS CI", its first bullet; board item MAC 4.1, issue #323).

Each runner is a virtual machine whose account has passwordless sudo. The real, installed
voltry-mac runs here as `voltry-mac --yes --json --no-open --output <folder>` with no
terminal, so its elevated path takes the -n forms S2n to S4n (Decision 2, "--yes and runs
without a terminal"). The checks are the bullet's: the installed command's allow-list is
the pinned one and every command in it runs cleanly; the virtual machine is flagged; SMART
and the battery report unavailable or not applicable by the reasons the spec gives; the
elevated path records S2n ok, S3n as the service account and S4n as root with its exact
argv, and the kernel says the running power sample is sandboxed; both payloads' output is
complete and parsed, their exit statuses checked; the report files belong to the runner
user with mode 0600; no file appears where a payload could have made one; and SIGTERM to
the tool stops a real power sample through sudo's relay, on a pseudo-terminal of its own,
behind sudo's monitor where this image's sudo runs one (1.9.14 and later), and again with
no terminal, as in CI. Both stops must verify the payload gone.

Authorization clearing is not checked here: the runner's sudo asks for no password, so
there is no authorization to clear. tests/test_elevation.py shows it with a fake sudo.

Each check prints counts and states only, never a report's values, since a report made
here carries the virtual machine's identifiers; and no report leaves the runner.
"""

from __future__ import annotations

import importlib.metadata
import os
import pwd
import stat
import subprocess
from pathlib import Path
from typing import Any

import voltry_mac_live as live

# Decision 2's sequence with --yes and no terminal, every step taken and every stop
# verified: the record a clean run on the runner must leave (Decision 8's state machine).
CLEAN_RECORD = {
    "consent": "flag",
    "skip_cause": None,
    "mode": "noninteractive",
    "checks": {"service_account": "present", "sandbox_probe": "ok", "listing": "ok"},
    "prepare": "ok",
    "authenticate": "ok",
    "count": {"ending": "parsed", "cleanup": "verified"},
    "power": {"ending": "parsed", "cleanup": "verified"},
    "cleared": "cleared",
    "clear_error": None,
}


def _report(run: Any) -> dict[str, Any]:
    assert run.report is not None, "expected the run to save one JSON report beside its PDF"
    report: dict[str, Any] = run.report
    return report


def _state(entry: Any) -> str:
    """A value's state, in words that carry no value."""
    if entry is None:
        return "absent"
    if entry["availability"] == "unavailable":
        return f"unavailable ({entry['reason']})"
    return f"available, {entry['provenance']}"


# --- the run the checks share ------------------------------------------------------------


def test_the_installed_command_prints_the_pinned_allow_list():
    """--dry-run prints the frozen allow-list the package's own tests pin to the spec's. That
    is what the installed command may run, not what it ran: the chokepoint runs nothing but
    an exact match of an entry (the package's own tests), so each ID in a command record
    names the spec's exact argv, the -n forms included. Of the elevated steps, only the
    argv S4n executed is seen, by the power sample's check."""
    shown = subprocess.run(
        [str(live.CLI), "--dry-run"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=60,
    )
    version = importlib.metadata.version("voltry-mac")
    pinned = live.DRY_RUN.read_text(encoding="utf-8").replace("{version}", version)
    print(f"--dry-run: exit {shown.returncode}, {len(shown.stdout.splitlines())} lines")
    assert shown.returncode == 0, "expected --dry-run to exit 0"
    assert shown.stdout == pinned, "expected --dry-run to print the pinned allow-list exactly"


def test_the_run_saved_its_report_and_exited_as_the_report_says(main_run):
    """Decision 6 and "Exit codes, in one place": the exit follows from the saved report."""
    report = _report(main_run)
    expected = live.expected_exit(report)
    reasons = live.unexpected(report)
    print(f"exit {main_run.code}; the report implies {expected}; unexpected reasons {reasons}")
    assert (
        report["collection"]["unexpected_reasons"] == reasons
    ), "expected the collection block's unexpected reasons to be those on the surfaces"
    assert main_run.code == expected, f"expected exit {expected}, the code the report implies"


def test_every_allow_listed_command_ran_cleanly(main_run):
    """Decision 8's command records: one per command that ran, in allow-list ID order, each
    with one run but P1, and no failed run but C24 and C25 on a Mac with one performance
    level, where they may fail as expected."""
    report = _report(main_run)
    records = {record["id"]: record for record in report["commands"]}
    levels = live.surface(report, "kernel_and_platform")["values"].get("perf_level_count")
    one_level = levels == {"availability": "available", "value": 1, "provenance": "reported"}
    allowed = {cid: {0, 1} if one_level and cid in live.SECOND_LEVEL else {0} for cid in records}
    failed = sorted(
        cid for cid, record in records.items() if record["failed_runs"] not in allowed[cid]
    )
    repeated = sorted(cid for cid, record in records.items() if cid != "P1" and record["runs"] != 1)
    listings = records.get("P1", {}).get("runs", 0)
    total = sum(record["failed_runs"] for record in records.values())
    print(f"{len(records)} command records, {total} failed runs, P1 ran {listings} times")
    assert [record["id"] for record in report["commands"]] == list(live.NONINTERACTIVE), (
        "expected one record for each command a run with --yes and no terminal runs, in "
        "allow-list order"
    )
    assert failed == [], f"expected every command to run cleanly; these did not: {failed}"
    assert repeated == [], f"expected one run each, P1 aside; these ran more: {repeated}"
    assert listings >= 5, "expected P1 once as the check, then at least twice for each payload"


def test_the_virtual_machine_is_flagged(main_run):
    """C26 reads kern.hv_vmm_present, and At a glance opens with Decision 7's line."""
    vm = live.surface(_report(main_run), "virtualization_state")
    flagged = vm["availability"] == "available" and vm["values"].get("vmm_present") == {
        "availability": "available",
        "value": True,
        "provenance": "measured",
    }
    opens = live.GLANCE in live.flat(main_run.stdout)
    print(f"virtualization_state {vm['availability']}; flagged {flagged}; At a glance {opens}")
    assert flagged, "expected virtualization_state available, vmm_present measured and true"
    assert opens, "expected At a glance to open with the virtual machine line"


def test_smart_is_unavailable_by_the_storage_chain(main_run):
    """A virtual machine's disk gives no NVMe SMART log. Both SMART surfaces come from one
    log, so they share one outcome, and it must be one the storage dependency table and
    C28's outcome table allow for what the report shows."""
    report = _report(main_run)
    found = [
        (live.surface(report, key)["availability"], live.surface(report, key).get("reason"))
        for key in ("smart_health_snapshot", "smart_wear_attributes")
    ]
    allowed = live.smart_reasons(report)
    print(f"SMART {found[0]} and {found[1]}; the storage chain allows {sorted(allowed)}")
    assert found[0] == found[1], "expected both SMART surfaces to share one outcome"
    assert found[0][0] == "unavailable", "expected SMART unavailable on a virtual machine"
    assert found[0][1] in allowed, f"expected SMART's reason to be one of {sorted(allowed)}"


def test_the_battery_is_not_applicable(main_run):
    """A virtual machine has no battery: both battery surfaces are not applicable together,
    with no values (Decision 8's availability domains)."""
    report = _report(main_run)
    found = {
        key: (live.surface(report, key)["availability"], len(live.surface(report, key)["values"]))
        for key in ("battery_health", "battery_gauge")
    }
    print(f"battery {found}")
    assert found == {
        "battery_health": ("not_applicable", 0),
        "battery_gauge": ("not_applicable", 0),
    }, "expected both battery surfaces not applicable, with no values"


def test_the_elevated_path_took_the_n_forms_through_passwordless_sudo(main_run):
    """The elevation record: consent by --yes, the -n forms, the service account present,
    the sandbox probe X1 and the listing P1 ok, S1 and S2n ok, both payloads parsed with
    their stops verified, and the final clear done."""
    record = _report(main_run)["elevation"]
    print(f"elevation {record}")
    assert record == CLEAN_RECORD, "expected every step of the -n path to succeed"


def test_the_power_sample_ran_as_root_inside_the_sandbox_with_its_exact_argv(main_run):
    """S4n runs for about five seconds, so the listings catch it: the sudo the tool spawned
    carries S4n's argv exactly, sandbox-exec with the fixed profile in front of the payload,
    and the payload, once sandbox-exec has become it, runs as root with its exact
    arguments, as ps shows them before or after powermetrics cuts its --samplers list in
    place (live.parsed_in_place). That it runs sandboxed is observed, not inferred from the
    argv: asked by the runner user while it ran, the kernel said it was sandboxed, and said
    its sudo, which runs outside the profile, was not, so the answer tells the two apart
    here."""
    watched = main_run.watched
    power = watched.power
    chain = [(process.name, process.uid) for process in watched.chain]
    print(f"power sample seen {power is not None}; chain {chain}; shapes {watched.shapes()}")
    print(f"sandboxed: powermetrics {watched.power_sandboxed}, its sudo {watched.sudo_sandboxed}")
    assert power is not None, "expected the listings to show powermetrics under the tool's sudo"
    assert power.uid == 0, "expected powermetrics to run as root"
    assert watched.sudo_arguments == " ".join(live.S4N), "expected sudo's argv to be S4n's"
    assert watched.power_arguments in (
        " ".join(live.POWERMETRICS),
        live.parsed_in_place(live.POWERMETRICS),
    ), "expected the payload's arguments to be powermetrics' exact ones"
    assert watched.sudo_sandboxed is False, "expected its sudo, outside the profile, not sandboxed"
    assert watched.power_sandboxed is True, "expected the kernel to say powermetrics ran sandboxed"


def test_the_count_ran_as_the_service_account(main_run):
    """S3n ends in milliseconds, too fast for a listing to catch every time, so this check is
    indirect. The store's folder is closed to the runner user, so a count that parsed was
    read as another account; but root reads the store too, so that it was _mmaintenanced
    rests on the argv the dry run pins (the allow-list check) and on the chokepoint, which
    runs nothing else. The sqlite3 clauses hold only when a listing caught one, which is
    rare: then it ran as that account, and the kernel, if it answered while it still ran,
    said it was sandboxed. No listing shows the argv S1, S2n, S3n or S5 executed, and
    sudo's own log cannot, since Apple's sudoers sets `Defaults !log_allowed`."""
    try:
        service: int | None = pwd.getpwnam(live.SERVICE_ACCOUNT).pw_uid
    except KeyError:
        service = None
    try:
        os.listdir(live.STORE_FOLDER)
        folder = "listed"
    except PermissionError:
        folder = "closed"
    except FileNotFoundError:
        folder = "absent"
    caught = [
        uid
        for found in main_run.watched.seen.values()
        for _, uid, name in found
        if name == "sqlite3"
    ]
    answers = list(main_run.watched.count_sandboxed.values())
    ending = _report(main_run)["elevation"]["count"]["ending"]
    print(f"store folder {folder} to the runner; count {ending}; sqlite3 caught {len(caught)}")
    print(f"sqlite3 sandboxed, as the kernel answered: {answers}")
    assert service is not None, "expected the _mmaintenanced account on this image"
    assert folder == "closed", "expected the store's folder closed to the runner user"
    assert ending == "parsed", "expected the count to parse what it read"
    assert all(uid == service for uid in caught), "expected sqlite3 to run as _mmaintenanced"
    assert False not in answers, "expected every sqlite3 the kernel answered for to be sandboxed"


def test_both_payloads_output_is_complete_and_parsed(main_run):
    """Both outputs drained and parsed, their exit statuses read. The count's is its two
    class rows, four measured values; were the store missing or unreadable on an image, the
    count would end payload_error (tool_error, payload_failed, as Failure modes says), and
    this check fails naming that rather than passing. The power sample's is five samples:
    the elapsed and thermal series whole, and each power series whole or, where macOS
    leaves it out, unavailable with source_changed, never a guess."""
    report = _report(main_run)
    elevation = report["elevation"]
    ledger = live.surface(report, "memory_error_ledger")
    rows = {name: _state(entry) for name, entry in ledger["values"].items()}
    power = live.surface(report, "power_and_thermal_samples")
    values = power["values"]
    series = {name: _state(values.get(name)) for name in live.SERIES}
    whole = {
        name
        for name in live.SERIES
        if (entry := values.get(name)) is not None
        and entry["availability"] == "available"
        and len(entry["value"]) == 5
    }
    records = {record["id"]: record for record in report["commands"]}
    print(f"count {elevation['count']}, ledger {ledger['availability']}, values {rows}")
    print(f"power {elevation['power']}, surface {power['availability']}, series {series}")
    if ledger["availability"] != "available":
        for line in live.count_diagnosis():  # why, in words the report never holds
            print(line)
    assert ledger["availability"] == "available" and rows == dict.fromkeys(
        live.LEDGER_VALUES, "available, measured"
    ), (
        "expected S3n's output parsed into its two class rows; the count ended "
        f"{elevation['count']['ending']} ({ledger.get('reason')}, {ledger.get('detail')})"
    )
    assert power["availability"] == "available", "expected S4n's output parsed"
    assert values.get("sample_count") == {
        "availability": "available",
        "value": 5,
        "provenance": "derived",
    }, "expected five samples"
    assert {
        "sample_elapsed_ns",
        "sample_thermal_pressure",
    } <= whole, "expected every sample's elapsed time and thermal pressure read"
    assert all(
        name in whole or series[name] == "unavailable (source_changed)" for name in live.SERIES
    ), "expected each power series whole, or unavailable with source_changed"
    assert [(records[cid]["runs"], records[cid]["failed_runs"]) for cid in ("S3n", "S4n")] == [
        (1, 0),
        (1, 0),
    ], "expected each payload to run once and exit 0"


def test_the_report_files_belong_to_the_runner_with_mode_0600(main_run):
    """Decision 5: the PDF and the JSON share one base name, each a regular file of the
    runner user's own with mode 0600 and one name; no temporary is left."""
    files = [main_run.output / name for name in main_run.files]
    kinds = sorted(path.suffix for path in files)
    bases = {path.stem for path in files}
    infos = [path.lstat() for path in files]
    owned = all(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() for info in infos)
    private = all(stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 for info in infos)
    pdf = [path for path in files if path.suffix == ".pdf"]
    print(f"{len(files)} files {kinds}; one base {len(bases) == 1}; owned {owned}; 0600 {private}")
    assert (
        kinds == [".json", ".pdf"] and len(bases) == 1
    ), "expected exactly a PDF and a JSON sharing one base name, and nothing else"
    assert owned, "expected both files to be regular files the runner user owns"
    assert private, "expected both files to have mode 0600 and one name"
    assert pdf[0].read_bytes()[:5] == b"%PDF-", "expected the PDF to be a PDF"


def test_no_file_appeared_where_a_payload_could_have_made_one(main_run):
    """What this covers: the run's working folder, which any account could write in, so a
    payload writing by a relative path would have left its file there; the output folder,
    which the files check holds to the two reports; and the ledger store's folder, where an
    SQLite open would leave a journal, -wal or -shm file, listed through sudo before and
    after the run. The first two are the test's own fresh folders. The third should not
    change either, but it can: the memory-maintenance daemon owns it, and its background
    tasks (/System/Library/LaunchDaemons/com.apple.memory-maintenance.plist) run when the
    user is idle, as a runner's always is, so one that opened the store during the run
    would leave a new -wal or -shm name here that no payload made. That is rare.

    What it does not cover: anywhere else a payload could name by an absolute path (/tmp,
    /private/var/tmp, the per-user temporary and cache folders, root's home), where the
    runner's own root processes write all the time; a file made and removed within the run;
    and a change to a file that already existed. The sandbox profile forbids all of them
    (Decision 2), and that it held the running payload is observed: while the power sample
    ran, the kernel said it was sandboxed and its sudo, outside the profile, was not. Any
    sqlite3 caught is held to the same, though S3n usually ends before a listing sees it."""
    before, after = main_run.store_before, main_run.store_after
    new = sorted(after.names - before.names)
    watched = main_run.watched
    counts = list(watched.count_sandboxed.values())
    print(
        f"working folder {len(main_run.work)} names; store folder {before.state} then "
        f"{after.state}, {len(new)} new names"
    )
    print(
        f"sandboxed: the power sample {watched.power_sandboxed}, its sudo "
        f"{watched.sudo_sandboxed}, each sqlite3 caught {counts}"
    )
    assert main_run.work == (), "expected the run's working folder still empty"
    assert (before.state, after.state) == (
        "listed",
        "listed",
    ), "expected the store's folder listed through sudo before and after the run"
    assert new == [], f"expected no new name in the store's folder; found {new}"
    assert (watched.sudo_sandboxed, watched.power_sandboxed) == (
        False,
        True,
    ), "expected the kernel to say the power sample ran sandboxed, and its sudo did not"
    assert False not in counts, "expected every sqlite3 the kernel answered for to be sandboxed"


def test_no_process_of_the_administrator_reads_was_left(main_run):
    """Every process the listings saw under the tool's sudo is gone once it has exited."""
    left = main_run.watched.left
    print(f"{len(main_run.watched.seen)} processes seen under sudo; {len(left)} left")
    assert left == (), f"expected none left; still running: {sorted(p.name for p in left)}"


# --- SIGTERM relay ------------------------------------------------------------------------


def _stopped(run: Any) -> str:
    """What any run sent SIGTERM while its power sample ran shows (Failure modes' signal
    row): exit 130, nothing saved, sudo -k attempted. Returns the cleanup the tool's own
    --debug line gives the stopped power sample."""
    printed = live.lines(run.stderr)
    cleared = any(live.CLEAR_LINE.fullmatch(line) for line in printed)
    cleanups = [found[1] for line in printed if (found := live.CANCELLED_LINE.fullmatch(line))]
    print(
        f"exit {run.code}; saved {len(run.files)}; working folder {len(run.work)}; "
        f"S5 line {cleared}; the stopped payload's cleanup {cleanups}"
    )
    assert run.code == 130, "expected exit 130 after SIGTERM"
    assert run.files == (), "expected nothing saved: no PDF, JSON or temporary"
    assert run.work == (), "expected the run's working folder still empty"
    assert live.STOPPED in printed, "expected the run to say it stopped and saved nothing"
    assert cleared, "expected sudo -k attempted: --debug's line for S5"
    assert len(cleanups) == 1, "expected one --debug line for the stopped power sample"
    return cleanups[0]


def _relayed(run: Any, cleanup: str) -> None:
    """The stop reached the payload through sudo: the tool's last listing verified it gone,
    it went well before its five samples could end on their own, and nothing is left."""
    watched = run.watched
    early = (
        watched.gone_at is not None
        and watched.absent_since is not None
        and watched.gone_at < watched.absent_since + live.EARLY_S
    )
    print(f"gone before its samples could end {early}; left {len(watched.left)}")
    assert cleanup == "verified", "expected the tool's last listing to verify the payload gone"
    assert early, (
        f"expected the payload gone within {live.EARLY_S} s of its start, when five 1 s "
        "samples take five: stopped by sudo relaying the SIGTERM"
    )
    assert watched.left == (), "expected no process of the subtree left"


def test_sigterm_stops_the_power_sample_on_a_terminal(tmp_path: Path):
    """The bullet's check. The tool runs on a pseudo-terminal of its own and takes S2 to S4,
    whose prompt the runner's passwordless sudo never shows. SIGTERM goes to the tool as
    soon as the power sample shows, and sudo relays it to the payload. On a terminal, sudo
    1.9.14 and later run the payload behind a monitor process, since use_pty is their
    default, so the chain is sudo, its monitor, then powermetrics; an older sudo runs it as
    its own child, as Apple's 1.9.13p2 does on macOS 15.0 to 15.6 and 26.0 (Decision 2,
    "Stopping a payload"; change record 12). The chain expected follows the version
    `sudo -V` prints, and the log says which case applied."""
    version = live.sudo_version()
    monitor = version[:3] >= live.MONITOR_SINCE
    case = "a monitor, as from 1.9.14" if monitor else "no monitor, as before 1.9.14"
    print(f"sudo {live.spelled(version)}: {case}")
    run = live.stop_power_sample(tmp_path, terminal=True)
    chain = [(process.name, process.uid) for process in run.watched.chain]
    expected = [("sudo", 0), *([("sudo", 0)] if monitor else []), ("powermetrics", 0)]
    asked = live.prompted(run.stdout)
    print(f"sudo asked for a password {asked}; power sample seen {run.watched.power is not None}")
    print(f"chain {chain}")
    assert not asked, "expected the runner's sudo to ask for no password on a terminal"
    assert (
        run.watched.power is not None
    ), f"expected to see the power sample running under sudo; the run exited {run.code}"
    assert chain == expected, (
        "expected sudo, its monitor, then powermetrics, each as root"
        if monitor
        else "expected sudo, then powermetrics as its own child, each as root"
    )
    _relayed(run, _stopped(run))


def test_sigterm_stops_the_power_sample_with_no_terminal(tmp_path: Path):
    """As in CI: S4n with no terminal, where sudo runs no monitor and powermetrics is its own
    child. sudo relays the tool's SIGTERM here too. It drops a signal a user sends only when
    the sender is the command, or when the command or sudo leads the sender's process
    group (src/exec_nopty.c, alike in sudo 1.9.13p2 and 1.9.17p2, and src/exec_pty.c
    behind the monitor), and the tool starts sudo in the tool's own process group, which
    neither leads. So the payload must be verified gone, as on a terminal. A survivor here
    would be a regression, not the spec's survivor case, which the sudo capture job shows
    with a sandboxed /bin/sleep 8 that sudo executes directly (Test strategy part 5)."""
    run = live.stop_power_sample(tmp_path, terminal=False)
    watched = run.watched
    chain = [(process.name, process.uid) for process in watched.chain]
    print(f"power sample seen {watched.power is not None}; chain {chain}")
    assert (
        watched.power is not None
    ), f"expected to see the power sample running under sudo; the run exited {run.code}"
    _relayed(run, _stopped(run))
