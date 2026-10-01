"""C28's outcomes on the parent's side (docs/VOLTRY_MAC_SPEC.md, "C28's outcomes,
normative", and Test strategy part 1's "SMART child output fixtures").

The parent validates the child's document before decoding anything, keeps the one
controller whose media hold the startup disk's whole disk, and maps every result through
the ordered 12-row table. Rows 1 to 7 make C28's run a failed one; rows 8 to 12 do not.
Each case asserts the SMART surfaces' reason (None when both are available) and whether the
run failed.
"""

from __future__ import annotations

import json
import random
import signal

import pytest

from voltry_mac import registry, smart, spawn

LOG = bytes(range(256)) * 2
HEX = LOG.hex()


def ok(*media: str, location: str = "Internal") -> dict:
    return {"location": location, "media": list(media), "status": "ok", "smart_hex": HEX}


def failed(*media: str, error: str = "smart_read_failed") -> dict:
    return {"location": "Internal", "media": list(media), "status": "error", "error": error}


def doc(*controllers: dict) -> str:
    return json.dumps({"schema": "voltry-mac-smart/0", "controllers": list(controllers)}) + "\n"


def run(
    stdout: str = "", code: int | None = 0, ending: spawn.Ending = spawn.Ending.EXITED
) -> spawn.Result:
    return spawn.Result("C28", ending, code, stdout, "", 40, False, True)


def outcome(result: spawn.Result, whole_disk: str = "disk0") -> tuple[str | None, bool]:
    found = smart.outcome(result, whole_disk)
    return found.reason, found.failed_run


VALID = doc(ok("disk0"))

ROWS = {
    # 1 to 7: the run failed.
    "1 could not be started": (run("", None, spawn.Ending.NOT_STARTED), ("tool_error", True)),
    "2 the output cap": (run("x", -15, spawn.Ending.OUTPUT_CAP), ("source_changed", True)),
    "3 its deadline": (run("", -15, spawn.Ending.DEADLINE), ("timeout", True)),
    "4 a signal the tool did not send": (
        run("", -signal.SIGSEGV, spawn.Ending.SIGNALED),
        ("tool_error", True),
    ),
    "5 an exit status other than 0, 2 or 3": (run(VALID, 1), ("tool_error", True)),
    "5 a valid document with exit 1 is unread": (run(doc(ok("disk0")), 1), ("tool_error", True)),
    "6 malformed output with exit 0": (run("{", 0), ("source_changed", True)),
    "6 malformed output with exit 2": (run("not json", 2), ("source_changed", True)),
    "6 malformed output with exit 3": (run("[]", 3), ("source_changed", True)),
    "6 empty output with exit 0": (run("", 0), ("source_changed", True)),
    "6 empty output with exit 2": (run("", 2), ("source_changed", True)),
    "6 empty output with exit 3": (run("", 3), ("source_changed", True)),
    "6 exit 0 with no controller ok": (run(doc(failed("disk0")), 0), ("source_changed", True)),
    "6 exit 2 with a controller ok": (run(doc(ok("disk0")), 2), ("source_changed", True)),
    "6 exit 3 with a controller listed": (run(doc(failed("disk0")), 3), ("source_changed", True)),
    "7 exit 3 with a valid document": (run(doc(), 3), ("tool_error", True)),
    # 8 to 12: the run did not fail.
    "8 no controller lists the startup disk": (run(doc(ok("disk4")), 0), ("source_absent", False)),
    "8 an empty list with exit 2": (run(doc(), 2), ("source_absent", False)),
    "9 the startup disk's controller lists another medium": (
        run(doc(ok("disk0", "disk1")), 0),
        ("unsupported", False),
    ),
    "9 two media while that controller errored": (
        run(doc(failed("disk0", "disk1"), ok("disk4")), 0),
        ("unsupported", False),
    ),
    "10 interface unavailable": (
        run(doc(failed("disk0", error="interface_unavailable"), ok("disk4")), 0),
        ("unsupported", False),
    ),
    "11 the read failed": (run(doc(failed("disk0"), ok("disk4")), 0), ("tool_error", False)),
    "12 the startup disk's controller read": (run(VALID, 0), (None, False)),
    "12 after an erroring controller": (run(doc(failed("disk4"), ok("disk0")), 0), (None, False)),
    "12 before an erroring controller": (run(doc(ok("disk0"), failed("disk4")), 0), (None, False)),
}


@pytest.mark.parametrize(("result", "expected"), list(ROWS.values()), ids=list(ROWS))
def test_every_row_of_the_outcome_table(result, expected):
    assert outcome(result) == expected


def _raw(extra: str) -> str:
    return '{"schema": "voltry-mac-smart/0", "controllers": [' + extra + "]}\n"


CONTRACT_BREAKS = {
    "an unknown field at the top": '{"schema": "voltry-mac-smart/0", "controllers": [], "x": 1}\n',
    "an unknown field in a controller": doc(dict(ok("disk0"), kind="NVMe")),
    "a duplicate key": _raw(
        '{"location": "Internal", "location": "External", "media": ["disk0"], '
        '"status": "ok", "smart_hex": "' + HEX + '"}'
    ),
    "another schema": json.dumps({"schema": "voltry-mac-smart/1", "controllers": []}),
    "a medium under two controllers": doc(ok("disk0"), ok("disk0")),
    "a medium name outside the grammar": doc(ok("disk0", "Macintosh HD")),
    "nine media": doc(ok(*(f"disk{n}" for n in range(9)))),
    "a wrong hex length": doc(dict(ok("disk0"), smart_hex=HEX[:-2])),
    "hex that is not hex": doc(dict(ok("disk0"), smart_hex="zz" + HEX[2:])),
    "nine controllers": doc(ok("disk0"), *(ok(f"disk{n}") for n in range(1, 9))),
    "a 65 KiB document": doc(ok("disk0")) + " " * (65 * 1024),
    "a non-ASCII byte": doc(ok("disk0", location="Internal")).replace("Internal", "Intérnal"),
    "status ok without smart_hex": doc(
        {"location": "Internal", "media": ["disk0"], "status": "ok"}
    ),
    "status error with a smart_hex": doc(dict(failed("disk4"), smart_hex=HEX), ok("disk0")),
    "another error code": doc(failed("disk4", error="crashed"), ok("disk0")),
    "another location": doc(ok("disk0", location="Thunderbolt")),
    "another status": doc(dict(ok("disk0"), status="maybe")),
    "a number where text belongs": doc(dict(ok("disk0"), location=1)),
}


@pytest.mark.parametrize("stdout", list(CONTRACT_BREAKS.values()), ids=list(CONTRACT_BREAKS))
def test_a_document_that_breaks_the_contract_is_row_6(stdout):
    assert outcome(run(stdout, 0)) == ("source_changed", True)


def test_an_available_outcome_carries_the_decoded_log():
    found = smart.outcome(run(VALID, 0), "disk0")
    assert found.values == smart.decode(LOG)


def test_the_failed_run_does_not_depend_on_the_whole_disk():
    # C28 runs either way; rows 1 to 7 decide its failed runs before any disk is matched.
    assert smart.failed_run(run("", None, spawn.Ending.NOT_STARTED))
    assert smart.failed_run(run(doc(), 3))
    assert smart.failed_run(run("{", 0))
    assert not smart.failed_run(run(VALID, 0))
    assert not smart.failed_run(run(doc(failed("disk0")), 2))


def test_a_cancelled_child_is_a_failed_run_with_tool_error():
    assert outcome(run("", -15, spawn.Ending.CANCELLED)) == ("tool_error", True)


# --- the #344 review, round 1 ------------------------------------------------------------------

HOSTILE = {
    "a status that is neither ok nor error": _raw(
        '{"location": "Internal", "media": ["disk0"], "status": "maybe"}'
    ),
    "a location that is a list": doc(dict(ok("disk0"), location=["Internal"])),
    "a location that is an object": doc(dict(ok("disk0"), location={"a": 1})),
    "an error code that is a list": doc(
        dict(failed("disk4"), error=["smart_read_failed"]), ok("disk0")
    ),
    "a record that is not an object": _raw(
        '5, {"location": "Internal", "media": ["disk0"], '
        '"status": "ok", "smart_hex": "' + HEX + '"}'
    ),
    "media that is not a list": doc(dict(ok("disk0"), media="disk0")),
    "controllers that is not a list": '{"schema": "voltry-mac-smart/0", "controllers": {}}\n',
    "a medium name that is a number": doc(dict(ok("disk0"), media=["disk0", 4])),
    "a log that is a number": doc(dict(ok("disk0"), smart_hex=5)),
    "a top level that is a list": "[]\n",
}


@pytest.mark.parametrize("stdout", list(HOSTILE.values()), ids=list(HOSTILE))
def test_a_hostile_document_is_row_6_and_raises_nothing(stdout):
    assert outcome(run(stdout, 0)) == ("source_changed", True)
    assert smart.failed_run(run(stdout, 0))


def test_another_schema_alone_breaks_the_contract():
    # An empty list with exit 2 agrees with its exit status, so only the schema decides.
    text = json.dumps({"schema": "voltry-mac-smart/1", "controllers": []})
    assert outcome(run(text, 2)) == ("source_changed", True)
    assert outcome(run(doc(), 2)) == ("source_absent", False)


def test_the_caps_hold_at_their_edges():
    eight = doc(ok("disk0"), *(ok(f"disk{n}") for n in range(1, 8)))
    assert outcome(run(eight, 0)) == (None, False)
    media = doc(ok("disk0"), dict(failed(*(f"disk{n}" for n in range(1, 9)))))
    assert outcome(run(media, 0)) == (None, False), "8 media under one controller"
    exact = doc(ok("disk0"))
    padded = exact.rstrip("\n") + " " * (smart.MAX_DOCUMENT - len(exact)) + "\n"
    assert smart.MAX_DOCUMENT == 65_536
    assert len(padded.encode()) == smart.MAX_DOCUMENT
    assert outcome(run(padded, 0)) == (None, False)
    assert outcome(run(padded + " ", 0)) == ("source_changed", True)


def test_a_lone_surrogate_is_refused_without_raising():
    text = doc(ok("disk0")).replace("Internal", "Intern" + chr(0xD800) + "l")
    assert outcome(run(text, 0)) == ("source_changed", True)


def test_outcome_never_raises_whatever_the_child_printed():
    # Near-valid documents, one or two fields changed at a time, mostly with an exit status
    # that gets them parsed: the shapes a contract check has to survive.
    rng = random.Random(344)  # noqa: S311 - a seeded fuzzer, not a secret
    values = [
        None,
        True,
        0,
        5,
        "",
        "Internal",
        "maybe",
        "ok",
        "error",
        "disk0",
        "Macintosh HD",
        "smart_read_failed",
        HEX,
        HEX[:-2],
        ["disk0"],
        ["disk0", 4],
        [],
        {},
        {"a": 1},
    ]

    def record() -> object:
        base = dict(rng.choice([ok("disk0"), ok("disk4"), failed("disk0"), failed("disk4")]))
        for _ in range(rng.randint(1, 2)):
            roll = rng.random()
            if roll < 0.6:
                base[rng.choice(list(base) + ["error", "smart_hex"])] = rng.choice(values)
            elif roll < 0.8 and base:
                del base[rng.choice(list(base))]
            else:
                return rng.choice(values)
        return base

    endings = list(spawn.Ending)
    seen_parsed = 0
    for _ in range(4000):
        controllers = [record() for _ in range(rng.randint(1, 3))]
        text = json.dumps({"schema": "voltry-mac-smart/0", "controllers": controllers})
        if rng.random() < 0.8:
            ending, code = spawn.Ending.EXITED, rng.choice([0, 2, 3])
        else:
            ending, code = rng.choice(endings), rng.choice([None, 1, -9])
        found = smart.outcome(run(text, code, ending), rng.choice(["disk0", "disk4"]))
        assert found.reason in (None, *registry.REASONS)
        seen_parsed += found.reason is None
    assert seen_parsed > 0, "some documents are valid, so the fuzzer reaches the decoder"


# --- the #344 review, round 2 ------------------------------------------------------------------


@pytest.mark.parametrize("location", ["Internal", "External", "Unknown"])
def test_the_startup_record_reads_whatever_its_location(location):
    assert outcome(run(doc(ok("disk0", location=location)), 0)) == (None, False)


def test_an_external_controller_beside_the_startup_one_changes_nothing():
    assert outcome(run(doc(ok("disk4", location="External"), ok("disk0")), 0)) == (None, False)


@pytest.mark.parametrize(
    "stdout",
    [
        _raw(
            '{"location": "Internal", "media": ["disk0"], "status": "maybe", '
            '"error": "smart_read_failed"}'
        ),
        '{"schema": "voltry-mac-smart/0", "controllers": 5}\n',
        '{"schema": "voltry-mac-smart/0", "controllers": {}}\n',
        '["schema", "controllers"]\n',
    ],
    ids=[
        "another status with an error code",
        "controllers that is a number",
        "controllers that is an object",
        "a top level that lists the two keys",
    ],
)
def test_a_contract_break_with_exit_2_is_row_6_and_raises_nothing(stdout):
    assert outcome(run(stdout, 2)) == ("source_changed", True)
