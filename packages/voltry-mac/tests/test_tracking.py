"""Tracking a payload command from the process tables (docs/VOLTRY_MAC_SPEC.md, Decision 2,
"Stopping a payload" and the outcome tables' latch; Test strategy part 3, "Process
behavior" and "Payload endings times cleanups").

The tracker is pure: it takes each listing as the rows ps printed and the monotonic time
of the pass that applies it. It records the spawned process at level 0 with every
identity it takes and each descendant down to three levels, finds the first sign that sudo
authenticated and the payload's identification, and keeps the one armed clock. The loop
that runs the listings and the stops is tested separately.
"""

from __future__ import annotations

import threading

import pytest

from voltry_mac import listing, tracking

AT = "Sat Sep 26 12:00:00 2026"
LATER = "Sat Sep 26 12:00:07 2026"
TOOL = 501
SERVICE = 283
S4 = tracking.Payload(uid=0, name="powermetrics")
S3 = tracking.Payload(uid=SERVICE, name="sqlite3")


def row(pid: int, ppid: int, uid: int, name: str, started: str = AT) -> listing.Process:
    return listing.Process(pid, ppid, uid, started, name)


LAUNCHD = row(1, 0, 0, "launchd")
TOOL_PROCESS = row(50, 1, TOOL, "python3.12")


def table(*rows: listing.Process) -> list[listing.Process]:
    return [LAUNCHD, TOOL_PROCESS, *rows]


def tracker(payload: tracking.Payload = S4, runtime_s: float = 20.0) -> tracking.Tracker:
    return tracking.Tracker(spawned=100, payload=payload, runtime_s=runtime_s, now=0.0)


def test_the_constants_are_the_specs():
    assert (tracking.AUTH_S, tracking.LAUNCH_S) == (180.0, 5.0)
    assert tracking.RUNTIME_S == {"S3": 10.0, "S3n": 10.0, "S4": 20.0, "S4n": 20.0}
    assert (tracking.POLL_S, tracking.LISTING_S, tracking.REAP_S, tracking.TERM_WAIT_S) == (
        0.2,
        2.0,
        1.0,
        3.0,
    )
    assert tracking.LEVELS == 3
    assert tracking.SUBTREE_NAMES == ("sudo", "sandbox-exec", "sqlite3", "powermetrics")


# --- the authentication clock -----------------------------------------------------------------


def test_the_authentication_clock_is_armed_at_the_spawn():
    found = tracker()
    assert (found.clock, found.deadline) == ("auth", 180.0)
    assert found.ending == "auth_failed"


def test_sudo_asking_for_the_password_for_170_s_starts_no_launch_clock():
    # sudo is setuid root, so ps shows user ID 0 from its first listing.
    found = tracker()
    for second in range(0, 171):
        found.apply(table(row(100, 50, 0, "sudo")), float(second))
    assert (found.clock, found.deadline) == ("auth", 180.0)
    assert not found.expired(179.9) and found.expired(180.0)


def test_the_child_caught_under_the_tools_own_name_starts_nothing():
    found = tracker()
    found.apply(table(row(100, 50, TOOL, "python3.12")), 0.1)
    found.apply(table(row(100, 50, 0, "sudo")), 0.3)
    assert found.clock == "auth"


def test_an_unexpected_descendant_during_the_prompt_is_recorded_and_starts_nothing():
    found = tracker()
    found.apply(table(row(100, 50, 0, "sudo"), row(101, 100, 0, "authhelper")), 5.0)
    assert found.clock == "auth"
    assert {(r.pid, r.identities) for r in found.records} == {
        (100, frozenset({(0, "sudo")})),
        (101, frozenset({(0, "authhelper")})),
    }


# --- the launch clock -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "rows",
    [
        [row(100, 50, 0, "sudo"), row(101, 100, 0, "sudo")],
        [row(100, 50, 0, "sudo"), row(101, 100, 0, "sandbox-exec")],
        [row(100, 50, 0, "sandbox-exec")],
    ],
    ids=["sudo's monitor", "a sandbox-exec descendant", "level 0 now sandbox-exec"],
)
def test_the_first_sign_that_sudo_authenticated_arms_the_launch_clock(rows):
    found = tracker()
    found.apply(table(row(100, 50, 0, "sudo")), 30.0)
    found.apply(table(*rows), 42.5)
    assert (found.clock, found.deadline, found.ending) == ("launch", 47.5, "launch_deadline")


def test_the_launch_clock_is_armed_once_from_the_first_sign():
    found = tracker()
    found.apply(table(row(100, 50, 0, "sandbox-exec")), 42.5)
    found.apply(table(row(100, 50, 0, "sandbox-exec")), 44.0)
    assert (found.clock, found.deadline) == ("launch", 47.5)


def test_the_payloads_name_at_level_0_under_another_user_is_a_sign():
    found = tracker(S3)
    found.apply(table(row(100, 50, 0, "sqlite3")), 2.0)
    assert found.clock == "launch"


def test_s4s_change_from_sudo_to_sandbox_exec_is_a_sign_though_the_user_id_stays_0():
    found = tracker(S4)
    found.apply(table(row(100, 50, 0, "sudo")), 1.0)
    found.apply(table(row(100, 50, 0, "sandbox-exec")), 1.2)
    assert found.clock == "launch"


def test_any_other_name_at_level_0_after_sudo_is_a_sign():
    found = tracker()
    found.apply(table(row(100, 50, 0, "sudo")), 1.0)
    found.apply(table(row(100, 50, 0, "env")), 1.2)
    assert found.clock == "launch"


def test_another_name_at_level_0_before_sudo_was_seen_is_no_sign():
    found = tracker()
    found.apply(table(row(100, 50, TOOL, "env")), 0.1)
    assert found.clock == "auth"


def test_a_descendant_under_the_payloads_name_but_another_identity_is_only_a_sign():
    found = tracker(S3)
    found.apply(table(row(100, 50, 0, "sudo"), row(101, 100, 0, "sqlite3")), 2.0)
    assert found.clock == "launch", "sqlite3 as root is not the count's identity"


# --- identification and the runtime clock --------------------------------------------------------


def test_a_payload_behind_sudos_monitor_is_identified_at_level_2():
    found = tracker(S4, runtime_s=20.0)
    found.apply(table(row(100, 50, 0, "sudo")), 10.0)
    found.apply(
        table(row(100, 50, 0, "sudo"), row(101, 100, 0, "sudo"), row(102, 101, 0, "powermetrics")),
        11.0,
    )
    assert (found.clock, found.deadline, found.ending) == ("runtime", 31.0, "runtime_deadline")


def test_a_payload_that_is_sudos_own_child_is_identified_at_level_1():
    # A sudo that runs no monitor forks the payload itself: with no terminal, and on a
    # terminal before sudo 1.9.14, as on macOS 15.0 to 15.6 and 26.0 (change record 12).
    found = tracker(S4, runtime_s=20.0)
    found.apply(table(row(100, 50, 0, "sudo")), 10.0)
    found.apply(table(row(100, 50, 0, "sudo"), row(101, 100, 0, "powermetrics")), 11.0)
    assert (found.clock, found.deadline, found.ending) == ("runtime", 31.0, "runtime_deadline")
    assert {r.pid for r in found.records} == {100, 101}


def test_a_directly_executed_payload_is_identified_at_level_0():
    found = tracker(S3, runtime_s=10.0)
    found.apply(table(row(100, 50, 0, "sudo")), 3.0)
    found.apply(table(row(100, 50, SERVICE, "sqlite3")), 3.4)
    assert (found.clock, found.deadline) == ("runtime", 13.4)


def test_identification_after_the_launch_clock_rearms_from_its_own_observation():
    found = tracker(S4)
    found.apply(table(row(100, 50, 0, "sandbox-exec")), 4.0)
    assert found.deadline == 9.0
    found.apply(table(row(100, 50, 0, "powermetrics")), 6.0)
    assert (found.clock, found.deadline) == ("runtime", 26.0)


def test_the_runtime_clock_is_armed_once_from_the_identification():
    found = tracker(S4)
    found.apply(table(row(100, 50, 0, "powermetrics")), 6.0)
    found.apply(table(row(100, 50, 0, "powermetrics")), 8.0)
    assert (found.clock, found.deadline) == ("runtime", 26.0)


def test_a_payload_at_level_3_is_identified():
    found = tracker(S4)
    rows = [
        row(100, 50, 0, "sudo"),
        row(101, 100, 0, "sudo"),
        row(102, 101, 0, "sandbox-exec"),
        row(103, 102, 0, "powermetrics"),
    ]
    found.apply(table(*rows), 1.0)
    assert found.clock == "runtime" and not found.failed


def test_a_matching_process_deeper_than_three_levels_is_a_tracking_failure():
    found = tracker(S4)
    rows = [
        row(100, 50, 0, "sudo"),
        row(101, 100, 0, "sudo"),
        row(102, 101, 0, "helper"),
        row(103, 102, 0, "helper"),
        row(104, 103, 0, "powermetrics"),
    ]
    found.apply(table(*rows), 1.0)
    assert found.failed
    assert 104 not in {r.pid for r in found.records}, "first seen below level 3: not recorded"


def test_a_process_below_level_3_that_is_not_the_payload_is_neither_recorded_nor_a_failure():
    found = tracker(S4)
    rows = [
        row(100, 50, 0, "sudo"),
        row(101, 100, 0, "sudo"),
        row(102, 101, 0, "helper"),
        row(103, 102, 0, "helper"),
        row(104, 103, 0, "helper"),
    ]
    found.apply(table(*rows), 1.0)
    assert not found.failed
    assert {r.pid for r in found.records} == {100, 101, 102, 103}


def test_a_listing_with_a_row_twice_is_walked_once():
    found = tracker(S4)
    rows = [row(100, 50, 0, "sudo"), row(101, 100, 0, "sudo"), row(101, 100, 0, "sudo")]
    found.apply(table(*rows), 1.0)
    assert [r.pid for r in found.records] == [100, 101]


def test_a_listing_whose_rows_loop_cannot_hang_the_tracker():
    # A hostile or garbled listing: 100's own ID listed again below its grandchild.
    found = tracker(S4)
    rows = table(row(100, 50, 0, "sudo"), row(101, 100, 0, "sudo"), row(100, 101, 0, "sudo"))
    done = threading.Event()

    def walk() -> None:
        found.apply(rows, 1.0)
        done.set()

    threading.Thread(target=walk, daemon=True).start()
    assert done.wait(5), "the walk ends"
    assert [r.pid for r in found.records] == [100, 101]


def test_a_recorded_process_seen_deeper_later_keeps_its_record():
    found = tracker(S4)
    chain = [
        row(100, 50, 0, "sudo"),
        row(101, 100, 0, "sudo"),
        row(102, 101, 0, "helper"),
        row(103, 102, 0, "helper"),
    ]
    found.apply(table(*chain), 1.0)
    deeper = [*chain[:3], row(104, 102, 0, "helper"), row(103, 104, 0, "helper2")]
    found.apply(table(*deeper), 1.2)
    (record,) = [r for r in found.records if r.pid == 103]
    assert record.identities == frozenset({(0, "helper"), (0, "helper2")})
    assert not found.failed


def test_a_failed_listing_is_a_tracking_failure():
    found = tracker()
    found.apply(None, 1.0)
    assert found.failed


def test_a_phase_change_disarms_the_clock_even_just_past_its_deadline():
    # The pass applies the listing first and only then compares the clock.
    found = tracker()
    found.apply(table(row(100, 50, 0, "sudo")), 100.0)
    found.apply(table(row(100, 50, 0, "sandbox-exec")), 181.0)
    assert (found.clock, found.expired(181.0)) == ("launch", False)


# --- the records ------------------------------------------------------------------------------


def test_every_identity_the_spawned_process_takes_is_recorded():
    found = tracker(S4)
    for when, name, uid in [
        (0.1, "python3.12", TOOL),
        (0.3, "sudo", 0),
        (4.0, "sandbox-exec", 0),
        (4.2, "powermetrics", 0),
    ]:
        found.apply(table(row(100, 50, uid, name)), when)
    (record,) = found.records
    assert record.identities == frozenset(
        {(TOOL, "python3.12"), (0, "sudo"), (0, "sandbox-exec"), (0, "powermetrics")}
    )


def test_a_reused_process_id_at_level_0_is_another_process():
    found = tracker()
    found.apply(table(row(100, 50, 0, "sudo")), 1.0)
    found.apply(table(row(100, 50, 0, "powermetrics", started=LATER)), 2.0)
    assert found.clock == "auth", "not the spawned process: another start time"
    assert [r.started for r in found.records] == [AT]


def test_a_process_that_left_the_subtree_stays_recorded():
    found = tracker(S4)
    found.apply(table(row(100, 50, 0, "sudo"), row(101, 100, 0, "powermetrics")), 1.0)
    found.apply(table(row(101, 1, 0, "powermetrics")), 2.0)  # sudo gone, payload reparented
    assert {r.pid for r in found.records} == {100, 101}


# --- the latch ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("cap", "tracking_failure", "expired", "exited", "ending"),
    [
        (True, True, "runtime_deadline", False, "output_cap"),
        (True, False, "auth_failed", False, "output_cap"),
        (True, False, None, True, "output_cap"),
        (False, True, "launch_deadline", False, "tracking_failed"),
        (False, True, None, True, "tracking_failed"),
        (False, False, "runtime_deadline", True, None),
        (False, False, "runtime_deadline", False, "runtime_deadline"),
        (False, False, None, False, None),
    ],
    ids=[
        "the cap beside a tracking failure",
        "the cap beside a clock",
        "the cap in the pass that collects the exit",
        "a tracking failure beside a clock",
        "a tracking failure with the exit",
        "a clock in the pass that collects the exit",
        "a clock alone",
        "nothing",
    ],
)
def test_the_latch_takes_the_first_forced_condition(cap, tracking_failure, expired, exited, ending):
    assert tracking.latch(cap=cap, tracking=tracking_failure, expired=expired, exited=exited) == (
        ending
    )


# --- survivors and the notes -----------------------------------------------------------------


def _recorded(*rows: listing.Process) -> tracking.Tracker:
    found = tracker(S4)
    found.apply(table(*rows), 1.0)
    return found


def test_a_recorded_process_still_alive_is_a_survivor():
    found = _recorded(row(100, 50, 0, "sudo"), row(101, 100, 0, "powermetrics"))
    final = table(row(101, 1, 0, "powermetrics"))
    assert tracking.survivors(found.records, final) == (
        tracking.Survivor(pid=101, uid=0, started=AT, name="powermetrics"),
    )


def test_a_full_path_in_comm_still_matches_by_basename():
    found = _recorded(row(100, 50, 0, "sudo"), row(101, 100, 0, "powermetrics"))
    text = (
        "  PID  PPID   UID STARTED                      COMM\n"
        f"  101     1     0 {AT}     /usr/bin/powermetrics\n"
    )
    assert [s.pid for s in tracking.survivors(found.records, listing.processes(text))] == [101]


@pytest.mark.parametrize(
    "final",
    [table(row(101, 1, 0, "powermetrics", started=LATER)), table()],
    ids=["a reused ID, another start time", "gone"],
)
def test_a_reused_id_or_a_process_gone_is_no_survivor(final):
    found = _recorded(row(100, 50, 0, "sudo"), row(101, 100, 0, "powermetrics"))
    assert tracking.survivors(found.records, final) == ()


@pytest.mark.parametrize(
    ("uid", "name"),
    [(TOOL, "powermetrics"), (0, "mdworker"), (SERVICE, "sqlite3")],
    ids=["another user", "another name", "both"],
)
def test_a_recorded_process_alive_under_another_identity_is_a_survivor(uid, name):
    # Change record 5 (the GPT audit, pass 1, S1-01): an exec after the last poll keeps the
    # process ID and start time and changes the name, and for the count the user ID. It is
    # still the recorded process, alive, so it survives, as the final listing shows it now.
    found = _recorded(row(100, 50, 0, "sudo"), row(101, 100, 0, "sandbox-exec"))
    final = table(row(101, 1, uid, name))
    assert tracking.survivors(found.records, final) == (
        tracking.Survivor(pid=101, uid=uid, started=AT, name=name),
    )


def test_the_note_names_a_survivor_as_the_final_listing_shows_it():
    # Change record 5: the note's user ID and name are the final listing's, so its ps check
    # compares what is there now, and a name outside the four still prints as unexpected.
    found = _recorded(row(100, 50, 0, "sudo"), row(101, 100, 0, "sandbox-exec"))
    (survivor,) = tracking.survivors(found.records, table(row(101, 1, TOOL, "mdworker")))
    note = tracking.survivor_note(survivor)
    assert f"user ID {TOOL}," in note and "an unexpected process" in note
    assert "sandbox-exec" not in note and "mdworker" not in note


def test_a_spawned_process_that_could_not_be_signalled_is_a_survivor_while_alive():
    found = _recorded(row(100, 50, 0, "sudo"))
    # It exec'd the payload directly as another user after the last poll saw it.
    final = table(row(100, 50, SERVICE, "sqlite3"))
    survivor = tracking.Survivor(pid=100, uid=SERVICE, started=AT, name="sqlite3")
    assert tracking.survivors(found.records, final) == (survivor,)
    assert tracking.survivors(found.records, final, unsignalled=100) == (survivor,)


def test_an_unsignalled_survivor_is_found_beside_another_survivor():
    # Round 2: the ID alone still counts when another recorded process survives too; since
    # change record 5 both are found as recorded processes, in the order they were recorded.
    found = _recorded(row(100, 50, 0, "sudo"), row(101, 100, 0, "sudo"))
    final = table(row(100, 50, SERVICE, "sqlite3"), row(101, 100, 0, "sudo"))
    assert tracking.survivors(found.records, final, unsignalled=100) == (
        tracking.Survivor(pid=100, uid=SERVICE, started=AT, name="sqlite3"),
        tracking.Survivor(pid=101, uid=0, started=AT, name="sudo"),
    )


def test_an_unsignalled_survivor_is_named_once():
    found = _recorded(row(100, 50, 0, "sudo"))
    final = table(row(100, 50, 0, "sudo"))
    assert len(tracking.survivors(found.records, final, unsignalled=100)) == 1


def test_the_survivor_note_verifies_first_and_never_gives_a_bare_kill():
    note = tracking.survivor_note(tracking.Survivor(101, 0, AT, "powermetrics"))
    assert "101" in note and "user ID 0" in note and AT in note and "powermetrics" in note
    assert "ps -p 101 -o pid,uid,lstart,comm" in note
    assert "sudo /bin/kill -TERM 101" in note
    assert note.index("ps -p 101") < note.index("sudo /bin/kill"), "the check comes first"
    assert "only if" in note.lower()


def test_a_payload_ps_prints_in_parentheses_is_named_in_the_note():
    # The first live run (2026-09-29): the final listing caught the power sample as it
    # ended, which ps prints as (powermetrics). It is the payload, and the note says so.
    header = "  PID  PPID   UID STARTED                      COMM\n"
    final = listing.processes(header + f"  101     1     0 {AT}     (powermetrics)\n")
    found = _recorded(row(100, 50, 0, "sudo"), row(101, 100, 0, "powermetrics"))
    (survivor,) = tracking.survivors(found.records, final)
    note = tracking.survivor_note(survivor)
    assert ", powermetrics, user ID 0," in note and "unexpected" not in note


def test_a_survivor_under_another_name_prints_as_an_unexpected_process():
    note = tracking.survivor_note(tracking.Survivor(202, 0, AT, "Jane's Helper"))
    assert "an unexpected process" in note and "Jane" not in note


def test_the_unverified_note_names_all_four_processes():
    note = tracking.UNVERIFIED_NOTE
    for name in tracking.SUBTREE_NAMES:
        assert name in note
    assert "could not" in note
    # It covers a listing that failed and a payload an error left unchecked, where no
    # listing ran at all.
    assert "failed or did not run" in note


def test_the_guarantee_is_stated_for_each_cleanup_and_only_what_it_can_promise():
    # Each speaks for its own step, and a survivor is named where it was, in the terminal
    # output (the GPT audit, pass 4, G4-01).
    assert tracking.guarantee("verified") == (
        "Every process the listings recorded for this step, the payload included if it "
        "started, has ended. A process that starts and ends between two listings is never "
        "recorded."
    )
    assert tracking.guarantee("survivor") == (
        "A process recorded for this step may still be running. Voltry named it in its "
        "terminal output when this report was made; nothing else is claimed."
    )
    assert tracking.guarantee("listing_failed") == (
        "The listing after this step failed, so Voltry could not check that the processes "
        "recorded for it ended, and claims nothing about them."
    )


@pytest.mark.parametrize("cleanup", ["not_applicable", "", "Verified"])
def test_there_is_no_guarantee_for_anything_else(cleanup):
    with pytest.raises(ValueError):
        tracking.guarantee(cleanup)


def test_after_eperm_the_spawned_process_is_matched_by_its_id_alone():
    # The tool has not collected its exit, so no other process can have its ID: it
    # survives under any start time a listing gives it, recorded or not.
    final = table(row(100, 50, SERVICE, "sqlite3", started=LATER))
    assert tracking.survivors((), final, unsignalled=100) == (
        tracking.Survivor(pid=100, uid=SERVICE, started=LATER, name="sqlite3"),
    )
    assert tracking.survivors((), table(row(101, 50, 0, "sudo")), unsignalled=100) == ()


def test_a_zombie_has_ended():
    found = _recorded(row(100, 50, 0, "sudo"), row(101, 100, 0, "powermetrics"))
    final = table(row(100, 50, 0, "<defunct>"), row(101, 1, 0, "<defunct>"))
    assert tracking.survivors(found.records, final, unsignalled=100) == ()


def test_a_tracked_run_keeps_its_output_out_of_its_repr():
    tracked = tracking.Tracked(
        started=True,
        forced=None,
        returncode=0,
        stdout="a secret sample",
        stderr="a secret line",
        cleanup="verified",
        survivors=(),
        records=(),
        cancelled=False,
        stop=None,
        duration_s=1.0,
        listings=(),
    )
    assert "secret" not in repr(tracked)


def test_a_tracked_run_names_no_process_in_its_repr():
    record = _recorded(row(100, 50, 0, "powermetrics")).records
    tracked = tracking.Tracked(
        started=True,
        forced=None,
        returncode=None,
        stdout="",
        stderr="",
        cleanup="survivor",
        survivors=(tracking.Survivor(100, 0, AT, "powermetrics"),),
        records=record,
        cancelled=True,
        stop="terminated",
        duration_s=1.0,
        listings=(),
    )
    assert "powermetrics" not in repr(tracked) and AT not in repr(tracked)


def test_the_notes_follow_the_copy_rules():
    texts = [
        tracking.survivor_note(tracking.Survivor(1, 0, AT, "sudo")),
        tracking.UNVERIFIED_NOTE,
        *(tracking.guarantee(c) for c in ("verified", "survivor", "listing_failed")),
    ]
    for text in texts:
        assert text.isascii()
        assert chr(0x2013) not in text and chr(0x2014) not in text
