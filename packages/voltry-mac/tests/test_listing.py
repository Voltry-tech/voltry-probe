"""The process listing, P1 (docs/VOLTRY_MAC_SPEC.md, Decision 2: the capability check and
the tracking that follows; the allow-list's P1).

`ps -axo pid,ppid,uid,lstart,comm` prints a header, then one row per process: the process
ID, its parent's, the numeric user ID, the start time as five words, and the command,
which may hold spaces and is sometimes a full path, so only its basename is kept. A
listing is read transiently: a row that does not parse makes the whole listing a failed
one, never a guess.
"""

from __future__ import annotations

import sys

import pytest

from voltry_mac import listing

HEADER = "  PID  PPID   UID STARTED                      COMM\n"
ROWS = (
    "    1     0     0 Fri Aug 28 08:00:54 2026     /sbin/launchd\n"
    "  344     1     0 Sat Sep  5 10:22:38 2026     /Library/Apple/System/Library/Core Services/x\n"
    " 4242   344   501 Sat Sep 26 12:00:01 2026     sudo\n"
)


def test_each_row_is_its_ids_start_and_basename():
    assert listing.processes(HEADER + ROWS) == [
        listing.Process(1, 0, 0, "Fri Aug 28 08:00:54 2026", "launchd"),
        listing.Process(344, 1, 0, "Sat Sep 5 10:22:38 2026", "x"),
        listing.Process(4242, 344, 501, "Sat Sep 26 12:00:01 2026", "sudo"),
    ]


def test_the_nobody_account_is_user_minus_2():
    # macOS's nobody is uid -2, and ps prints it signed.
    row = "  512     1    -2 Sat Sep 26 12:00:01 2026     /usr/libexec/helper\n"
    assert listing.processes(HEADER + row)[0].uid == -2


def test_a_name_with_spaces_keeps_them():
    row = (
        "  900     1   501 Sat Sep 26 12:00:01 2026     "
        "/Applications/My App.app/Contents/MacOS/My App\n"
    )
    (process,) = listing.processes(HEADER + row)
    assert process.name == "My App"


@pytest.mark.parametrize("name", ["powermetrics", "sudo", "sqlite3", "sandbox-exec"])
def test_a_name_ps_prints_in_parentheses_is_that_name(name):
    # ps prints a process whose path it cannot read, as while it starts or ends, by the
    # kernel's short name in parentheses. The first live run (2026-09-29) listed a power
    # sample ending on its own as (powermetrics) on macOS 26, and its survivor note called
    # it an unexpected process.
    row = f" 5927     1     0 Tue Sep 29 15:26:19 2026     ({name})\n"
    (process,) = listing.processes(HEADER + row)
    assert process.name == name


@pytest.mark.parametrize("shown", ["(sudo", "sudo)", "()", "My (App)", "<defunct>"])
def test_a_name_not_wholly_in_parentheses_is_kept_as_printed(shown):
    row = f" 5927     1     0 Tue Sep 29 15:26:19 2026     {shown}\n"
    (process,) = listing.processes(HEADER + row)
    assert process.name == shown


@pytest.mark.parametrize(
    "text",
    [
        "",
        HEADER,
        "  PID  PPID USER STARTED COMMAND\n" + ROWS,
        HEADER + "  1 0 0 Fri Aug 28 08:00:54 2026\n",
        HEADER + "  x 0 0 Fri Aug 28 08:00:54 2026 launchd\n",
        HEADER + "  1 0 0 Fri Aug 28 2026 launchd\n",
        HEADER + "  1 0 0 Fri Aug 28 25:00:54 2026 launchd\n",
        HEADER + " -1 0 0 Fri Aug 28 08:00:54 2026 launchd\n",
        HEADER + "  1 0 0 Fri Aug 28 08:00:54 2026 /usr/bin/\n",
    ],
    ids=[
        "empty",
        "a header and no process",
        "another header",
        "no command",
        "a word for a process ID",
        "a start time of four words",
        "an hour of 25",
        "a negative process ID",
        "a command with no name",
    ],
)
def test_a_listing_that_does_not_parse_is_unreadable(text):
    with pytest.raises(listing.Unreadable):
        listing.processes(text)


@pytest.mark.skipif(sys.platform != "darwin", reason="the real ps is macOS's")
def test_this_macs_listing_parses_through_the_chokepoint():
    from voltry_mac import spawn

    result = spawn.Runner().run("P1")
    assert result.ok
    found = listing.processes(result.stdout)
    assert any(process.pid == 1 and process.name == "launchd" for process in found)


# --- the #346 review ----------------------------------------------------------------------------

MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
DAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")


@pytest.mark.parametrize("month", MONTHS)
def test_every_month_reads(month):
    row = f"  900     1   501 Sat {month}  5 10:22:38 2026     sudo\n"
    assert listing.processes(HEADER + row)[0].started == f"Sat {month} 5 10:22:38 2026"


@pytest.mark.parametrize("day", DAYS)
def test_every_day_reads(day):
    row = f"  900     1   501 {day} Sep 26 12:00:01 2026     sudo\n"
    assert listing.processes(HEADER + row)[0].started.startswith(day)


@pytest.mark.parametrize(
    "started",
    [
        "Sab Sep 26 12:00:01 2026",
        "Sat Sept 26 12:00:01 2026",
        "Sat Sep 32 12:00:01 2026",
        "Sat Sep 26 12:60:01 2026",
        "Sat Sep 26 12:00:01 26",
    ],
    ids=[
        "a day that is not one",
        "a month that is not one",
        "day 32",
        "minute 60",
        "a two-digit year",
    ],
)
def test_each_part_of_a_start_time_is_checked(started):
    with pytest.raises(listing.Unreadable):
        listing.processes(HEADER + f"  900     1   501 {started}     sudo\n")


@pytest.mark.parametrize("mark", [chr(0x2028), chr(0x2029)], ids=["U+2028", "U+2029"])
def test_a_command_name_holding_a_line_separator_stays_one_row(mark):
    # macOS's ps prints these two raw; any local process can take such a name.
    row = f"  900     1   501 Sat Sep 26 12:00:01 2026     /tmp/odd{mark}name\n"
    (process,) = listing.processes(HEADER + row)
    assert process.name == f"odd{mark}name"
