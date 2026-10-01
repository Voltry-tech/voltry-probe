"""The preflight (docs/VOLTRY_MAC_SPEC.md, the Architecture's preflight row, Decision 2's
step 1, Decision 7, Failure modes, and transcripts 3 and 6; change record 2).

Before any read, and before an argument error: refuse the root user (exit 5), then any
platform the spec does not cover (exit 3), each with its message and nothing collected or
written. Only --version and --dry-run skip it; --help and render take it too. R4 reads the
processor type and Rosetta in-process through sysctlbyname, and with change record 2 the
Darwin release, which answers the same in compatibility mode; only a missing arm64 flag
means an Intel Mac, and a release too old to support is named before a state R4 could not
read. The admin group is the fixed group ID 80 among the process's groups, with no name
read, bounded like R5. The terminal is stdin.
"""

from __future__ import annotations

import contextlib
import ctypes
import errno
import grp
import os
import platform
import posix
import pwd
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

import voltry_mac
from voltry_mac import cli, preflight

P = preflight.Platform
APPLE_SILICON = P(macos=True, arm64=True, translated=False, release="25.6.0")
INTEL_MAC = P(macos=True, arm64=False, translated=False, release="24.6.0")
HEADER = f"Voltry Mac hardware observation report {voltry_mac.__version__} (preview)"
NO_DATA = "No report data was collected and no report file was written."


class RefusingPopen:
    def __init__(self, *args, **kwargs):
        raise AssertionError("a process was started")


@pytest.fixture
def mac(monkeypatch, tmp_path):
    """A run on a supported Mac, as a user, from an empty folder, starting no process."""
    monkeypatch.setattr(os, "geteuid", lambda: 501)
    monkeypatch.setattr(preflight, "read", lambda **_: APPLE_SILICON)
    monkeypatch.setattr(subprocess, "Popen", RefusingPopen)
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _run(capsys, *argv: str) -> tuple[int, str, str]:
    code = cli.main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


# --- the root user ----------------------------------------------------------------------------


def test_the_root_message_is_transcript_6s():
    assert preflight.ROOT == (
        "Run voltry-mac without sudo. It asks for your password only for the\n"
        "two steps that need it, and it saves the report as you, not as root.\n"
        "No report data was collected and no report file was written."
    )


@pytest.mark.parametrize(
    "argv", [[], ["--no-root"], ["--json"], ["render", "report.json"]], ids=str
)
def test_root_is_refused_with_exit_5_before_anything_is_read(capsys, mac, monkeypatch, argv):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    read = []
    monkeypatch.setattr(preflight, "read", lambda **_: read.append(True) or APPLE_SILICON)
    code, out, err = _run(capsys, *argv)
    assert (code, out, err) == (5, "", preflight.ROOT + "\n")
    assert read == [], "not even the platform is read"
    assert list(mac.iterdir()) == []


@pytest.mark.parametrize("flag", ["--version", "--dry-run"])
def test_version_and_dry_run_answer_as_root_too(capsys, mac, monkeypatch, flag):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    code, out, err = _run(capsys, flag)
    assert (code, err) == (0, "") and out


# --help is neither, so it takes the preflight as every other run does (change record 2:
# "only `--version` and `--dry-run` skip the preflight"; the pre-audit of the GPT audit's
# pass 3, control 06): root first, then the platform, then the help.
@pytest.mark.parametrize("argv", [["--help"], ["-h"], ["render", "--help"]], ids=str)
def test_help_takes_the_preflight(capsys, mac, monkeypatch, argv):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    assert _run(capsys, *argv) == (5, "", preflight.ROOT + "\n")
    monkeypatch.setattr(os, "geteuid", lambda: 501)
    monkeypatch.setattr(preflight, "read", lambda **_: INTEL_MAC)
    assert _run(capsys, *argv) == (3, "", f"{HEADER}\n\n{preflight.INTEL}\n")
    monkeypatch.setattr(preflight, "read", lambda **_: APPLE_SILICON)
    code, out, err = _run(capsys, *argv)
    assert (code, err) == (0, "") and out.startswith("usage: voltry-mac")


# The exit codes' precedence (Failure modes): "When more than one applies, the code is the
# first in this order: 5, 3, 2". Only --version and --dry-run skip the preflight, and a
# command line that does not parse is neither.
BAD_ARGUMENTS = [
    ["--yes", "--no-root"],
    ["--no-root", "--yes", "--json"],
    ["--paper", "b5"],
    ["--frobnicate"],
    ["render"],
    ["render", "report.json", "--yes"],
    ["--version", "--paper", "b5"],
    ["--dry-run", "--frobnicate"],
    # The tool's own words for each (the GPT audit, pass 2, G2-01) come after it too.
    ["/Users/cnryaccount/Reports"],
    ["--output"],
    ["--json=yes"],
    ["--no"],
    # And those of the audit fixes' round 3: "--", a folder after =, an empty argument.
    ["--"],
    ["--", "--json"],
    ["--ouput=/Users/cnryaccount/Reports"],
    [""],
]


@pytest.mark.parametrize("argv", BAD_ARGUMENTS, ids=str)
def test_the_root_refusal_comes_before_an_argument_error(capsys, mac, monkeypatch, argv):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    assert _run(capsys, *argv) == (5, "", preflight.ROOT + "\n")


@pytest.mark.parametrize("argv", BAD_ARGUMENTS, ids=str)
def test_the_platform_refusal_comes_before_an_argument_error(capsys, mac, monkeypatch, argv):
    monkeypatch.setattr(preflight, "read", lambda **_: INTEL_MAC)
    assert _run(capsys, *argv) == (3, "", f"{HEADER}\n\n{preflight.INTEL}\n")


@pytest.mark.parametrize("answer", ["--version", "--dry-run"])
@pytest.mark.parametrize("euid", [0, 501], ids=["root", "a user"])
def test_beside_version_or_dry_run_the_contradiction_is_exit_2(
    capsys, mac, monkeypatch, answer, euid
):
    # --version and --dry-run skip the preflight, so neither 5 nor 3 applies to them, and
    # the contradiction is still refused (the MAC 3.1 review).
    monkeypatch.setattr(os, "geteuid", lambda: euid)
    monkeypatch.setattr(preflight, "read", lambda **_: INTEL_MAC)
    code, out, err = _run(capsys, answer, "--yes", "--no-root")
    assert (code, out, err) == (2, "", "--yes and --no-root cannot be used together\n")


@pytest.mark.parametrize("argv", BAD_ARGUMENTS, ids=str)
def test_on_a_supported_mac_the_argument_error_is_exit_2(capsys, mac, argv):
    code, out, err = _run(capsys, *argv)
    assert (code, out) == (2, "") and err.strip() and "Traceback" not in err


# --- the platform -----------------------------------------------------------------------------


def test_the_intel_message_is_transcript_3s():
    assert preflight.INTEL == (
        "This version of voltry-mac reads Apple silicon Macs (M1 and later).\n"
        "This Mac has an Intel processor, which uses different sensors and\n"
        "storage interfaces, so voltry-mac cannot give you an honest report\n"
        "yet. No report data was collected and no report file was written."
    )


def test_the_other_refusals_are_pinned():
    assert preflight.NOT_MACOS == (
        "This version of voltry-mac reads Apple silicon Macs (M1 and later)\n"
        "running macOS 15 or later, and this computer does not run macOS.\n" + NO_DATA
    )
    assert preflight.UNKNOWN_PROCESSOR == (
        "This version of voltry-mac reads Apple silicon Macs (M1 and later),\n"
        "and could not read this Mac's processor type.\n" + NO_DATA
    )
    assert preflight.UNKNOWN_MACOS == (
        "voltry-mac needs macOS 15 or later, and could not read this Mac's\n"
        "macOS version.\n" + NO_DATA
    )
    assert preflight.UNKNOWN_ROSETTA == (
        "voltry-mac could not read whether this Python runs under Rosetta,\n"
        "which the report must record.\n" + NO_DATA
    )


def _old(named: str) -> str:
    return f"voltry-mac needs macOS 15 or later.{named}\n{NO_DATA}"


REFUSED = [
    (P(False, None, None, None), preflight.NOT_MACOS),
    (P(True, False, False, "24.6.0"), preflight.INTEL),
    (P(True, False, None, None), preflight.INTEL),
    (P(True, None, False, "25.6.0"), preflight.UNKNOWN_PROCESSOR),
    (P(True, None, True, "25.6.0"), preflight.UNKNOWN_PROCESSOR),
    (P(True, None, None, "25.6.0"), preflight.UNKNOWN_PROCESSOR),
    (P(True, True, None, "25.6.0"), preflight.UNKNOWN_ROSETTA),
    (P(True, True, None, "23.6.0"), _old(" This Mac runs macOS 14.")),
    (P(True, True, None, None), preflight.UNKNOWN_ROSETTA),
    (P(True, True, False, "23.6.0"), _old(" This Mac runs macOS 14.")),
    (P(True, True, True, "23.0.0"), _old(" This Mac runs macOS 14.")),
    (P(True, True, False, "22.6.0"), _old(" This Mac runs macOS 13.")),
    (P(True, True, False, "20.1.0"), _old(" This Mac runs macOS 11.")),
    (P(True, True, False, "19.6.0"), _old("")),
    (P(True, True, False, "0.0.0"), _old("")),
    (P(True, True, False, None), preflight.UNKNOWN_MACOS),
    # A release too old to support is named first when it is readable (change record 2),
    # before a processor type or Rosetta state that could not be read (the pre-audit of the
    # GPT audit's pass 3, control 07); an Intel Mac still comes first.
    (P(True, None, False, "23.1.0"), _old(" This Mac runs macOS 14.")),
    (P(True, None, None, "22.6.0"), _old(" This Mac runs macOS 13.")),
    (P(True, None, True, "19.6.0"), _old("")),
    (P(True, False, False, "23.6.0"), preflight.INTEL),
]
REFUSED_IDS = [
    "not macOS",
    "Intel",
    "Intel, nothing else read",
    "processor type unread",
    "processor type unread, translated",
    "processor type and translation unread",
    "translation unread",
    "translation unread on macOS 14",
    "translation and release unread",
    "Darwin 23 is macOS 14",
    "Darwin 23 under Rosetta",
    "Darwin 22 is macOS 13",
    "Darwin 20 is macOS 11",
    "Darwin 19 names no version",
    "Darwin 0",
    "no release",
    "processor type unread on macOS 14",
    "processor type and translation unread on macOS 13",
    "processor type unread on Darwin 19",
    "Intel on macOS 14",
]


@pytest.mark.parametrize(
    "argv", [[], ["--no-root"], ["--json"], ["render", "report.json"]], ids=str
)
@pytest.mark.parametrize(("found", "message"), REFUSED, ids=REFUSED_IDS)
def test_an_unsupported_platform_is_refused_with_exit_3(
    capsys, mac, monkeypatch, found, message, argv
):
    monkeypatch.setattr(preflight, "read", lambda **_: found)
    code, out, err = _run(capsys, *argv)
    assert (code, out) == (3, "")
    assert err == f"{HEADER}\n\n{message}\n", "the header, then the plain reason"
    assert list(mac.iterdir()) == []


@pytest.mark.parametrize(
    "release",
    [
        "",
        "not a version",
        "25x6x0",
        "25x6.0",
        "25.6x0",
        "25",
        "25.6",
        "25.6.0.1",
        "25.6.0 x",
        " 25.6.0",
        "25.6.0\n",
        "1000.0.0",
        "25.6.1000",
        "25.6.-1",
        "25..0",
        "-25.6.0",
        "+25.6.0",
        "25.6.0" + chr(0x0660),
        chr(0x0662) + chr(0x0665) + ".6.0",
        "10.16",
        "26.6.2x",
    ],
)
def test_a_release_outside_the_grammar_is_unreadable(release):
    assert preflight.refusal(P(True, True, False, release)) == preflight.UNKNOWN_MACOS


@pytest.mark.parametrize("release", ["24.0.0", "24.6.0", "25.6.0", "26.0.0", "99.9.9", "124.0.0"])
def test_darwin_24_and_later_on_apple_silicon_pass(release):
    # Darwin 24 is macOS 15; macOS 26 and 27 are Darwin 25 and 26.
    assert preflight.refusal(P(True, True, False, release)) is None


def test_python_under_rosetta_gets_a_full_report():
    assert preflight.refusal(P(True, True, True, "25.6.0")) is None


def test_a_supported_platform_goes_on_to_the_run(capsys, mac, monkeypatch):
    # The run gets the platform the preflight read, for the report's tool object.
    handed: list[object] = []
    monkeypatch.setattr(
        "voltry_mac.run.collect", lambda args, found: handed.append((args.no_root, found)) or 0
    )
    code, _, err = _run(capsys, "--no-root")
    assert (code, err) == (0, "")
    assert handed == [(True, APPLE_SILICON)]


def test_the_messages_follow_the_copy_rules():
    texts = [preflight.ROOT, preflight.INTEL, preflight.NOT_MACOS]
    texts += [preflight.UNKNOWN_PROCESSOR, preflight.UNKNOWN_MACOS, preflight.UNKNOWN_ROSETTA]
    texts += [preflight.refusal(P(True, True, False, f"{d}.0.0")) or "" for d in range(0, 24)]
    for text in texts:
        assert text.isascii() and text.endswith(NO_DATA)
        assert chr(0x2013) not in text and chr(0x2014) not in text
        assert all(len(line) <= 72 for line in text.splitlines())


# --- R4, through sysctlbyname -------------------------------------------------------------------


class Unreadable(OSError):
    pass


def _reads(values: dict[str, object]):
    """Readers keyed by OID: an int or text is the value, a missing key is an OID that does
    not exist, and Unreadable is a read that failed."""

    def number(name: str) -> int | None:
        found = values.get(name)
        if isinstance(found, Exception):
            raise found
        assert found is None or isinstance(found, int), name
        return found

    def text(name: str) -> str | None:
        found = values.get(name)
        if isinstance(found, Exception):
            return None
        assert found is None or isinstance(found, str), name
        return found

    return number, text


@pytest.mark.parametrize(
    ("values", "expected"),
    [
        (
            {"hw.optional.arm64": 1, "sysctl.proc_translated": 0, "kern.osrelease": "25.6.0"},
            P(True, True, False, "25.6.0"),
        ),
        (
            {"hw.optional.arm64": 1, "sysctl.proc_translated": 1, "kern.osrelease": "24.6.0"},
            P(True, True, True, "24.6.0"),
        ),
        ({"kern.osrelease": "24.6.0"}, P(True, False, False, "24.6.0")),
        (
            {"hw.optional.arm64": 0, "sysctl.proc_translated": 0, "kern.osrelease": "24.6.0"},
            P(True, False, False, "24.6.0"),
        ),
        (
            {
                "hw.optional.arm64": Unreadable(errno.EPERM, "denied"),
                "sysctl.proc_translated": 0,
                "kern.osrelease": "25.6.0",
            },
            P(True, None, False, "25.6.0"),
        ),
        (
            {
                "hw.optional.arm64": 1,
                "sysctl.proc_translated": Unreadable(errno.EPERM, "denied"),
                "kern.osrelease": "25.6.0",
            },
            P(True, True, None, "25.6.0"),
        ),
        (
            {"hw.optional.arm64": 2, "sysctl.proc_translated": -1, "kern.osrelease": "25.6.0"},
            P(True, None, None, "25.6.0"),
        ),
        ({"hw.optional.arm64": 1, "sysctl.proc_translated": 0}, P(True, True, False, None)),
        (
            {
                "hw.optional.arm64": 1,
                "sysctl.proc_translated": 0,
                "kern.osrelease": Unreadable(errno.EPERM, "denied"),
            },
            P(True, True, False, None),
        ),
    ],
    ids=[
        "Apple silicon",
        "under Rosetta",
        "Intel, no such OIDs",
        "Intel, arm64 0",
        "arm64 unreadable",
        "translation unreadable",
        "flags that are neither 0 nor 1",
        "no release",
        "release unreadable",
    ],
)
def test_r4_reads_the_processor_rosetta_and_the_release(monkeypatch, values, expected):
    monkeypatch.setattr(sys, "platform", "darwin")
    number, text = _reads(values)
    assert preflight.read(number=number, text=text) == expected


def test_r4_never_reads_the_product_version(monkeypatch):
    # In compatibility mode (SYSTEM_VERSION_COMPAT=1, or an interpreter linked against an
    # SDK older than 11), macOS 11 to 15 answer kern.osproductversion with 10.16; the
    # Darwin release answers the same, so an eligible Mac is not refused.
    monkeypatch.setattr(sys, "platform", "darwin")
    values = {
        "hw.optional.arm64": 1,
        "sysctl.proc_translated": 1,
        "kern.osrelease": "24.6.0",
        "kern.osproductversion": AssertionError("the product version was read"),
    }
    number, text = _reads(values)
    asked: list[str] = []

    def spy(name: str) -> str | None:
        asked.append(name)
        return text(name)

    found = preflight.read(number=number, text=spy)
    assert asked == ["kern.osrelease"]
    assert preflight.refusal(found) is None


def test_the_readers_are_looked_up_when_read_runs(monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    number, text = _reads({"hw.optional.arm64": 1, "kern.osrelease": "25.6.0"})
    monkeypatch.setattr(preflight, "sysctl_number", number)
    monkeypatch.setattr(preflight, "sysctl_text", text)
    assert preflight.read() == P(True, True, False, "25.6.0")


def test_without_the_release_only_the_two_flags_are_read(monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    number, _ = _reads({"hw.optional.arm64": 1, "sysctl.proc_translated": 0})

    def refuse(name: str) -> str | None:
        raise AssertionError(f"{name} was read")

    assert preflight.read(number=number, text=refuse, release=False) == P(True, True, False, None)


@pytest.mark.parametrize("name", ["linux", "win32", "freebsd14", "cygwin"])
def test_off_macos_nothing_is_read(monkeypatch, name):
    monkeypatch.setattr(sys, "platform", name)

    def refuse(name: str) -> object:
        raise AssertionError("read off macOS")

    assert preflight.read(number=refuse, text=refuse) == P(False, None, None, None)


LIVE = pytest.mark.skipif(sys.platform != "darwin", reason="sysctlbyname is macOS's")


def _sysctl(name: str) -> str | None:
    """The same OID through sysctl(8), a separate process, for comparison."""
    done = subprocess.run(  # noqa: S603 - a test-owned child with a fixed argv
        ["/usr/sbin/sysctl", "-n", name], capture_output=True, text=True, timeout=30, check=False
    )
    return done.stdout.strip() if done.returncode == 0 else None


@LIVE
def test_this_macs_r4_agrees_with_sysctl():
    # Whatever this Mac is: Apple silicon or Intel, a native or a translated interpreter.
    found = preflight.read()
    arm64 = _sysctl("hw.optional.arm64") == "1"
    assert found.macos and found.arm64 is arm64
    assert found.release == _sysctl("kern.osrelease")
    # sysctl(8) runs natively, so the translation is the interpreter's own: an x86_64
    # interpreter on Apple silicon is translated.
    assert found.translated is (arm64 and platform.machine() == "x86_64")


@LIVE
def test_this_macs_r4_passes_the_preflight_on_apple_silicon():
    found = preflight.read()
    if not found.arm64:
        pytest.skip("not Apple silicon")
    assert preflight.refusal(found) is None


@LIVE
def test_an_oid_that_does_not_exist_is_absent_not_unreadable():
    assert preflight.sysctl_number("hw.optional.voltry_nonexistent") is None
    assert preflight.sysctl_text("kern.voltry_nonexistent") is None


def _fake_sysctl(answers: dict[str, list[tuple[int, int, bytes, int]]]):
    """A sysctlbyname keyed by OID: each call to a name takes its next (status, size,
    bytes, errno); a name with no answers left fails the test."""
    queues = {name.encode("ascii"): list(calls) for name, calls in answers.items()}

    def call(name, oldp, oldlenp, newp, newlen):
        assert newp is None and newlen == 0, "R4 never writes"
        status, size, data, error = queues[name].pop(0)
        oldlenp._obj.value = size  # a byref() keeps the object it points to
        if oldp is not None and data:
            target = oldp._obj if hasattr(oldp, "_obj") else oldp
            ctypes.memmove(ctypes.addressof(target), data, len(data))
        ctypes.set_errno(error)
        return status

    return call


def _int(value: int) -> tuple[int, int, bytes, int]:
    return (0, 4, value.to_bytes(4, "little", signed=True), 0)


@pytest.mark.parametrize(
    ("answers", "expected"),
    [
        ([_int(1)], 1),
        ([_int(0)], 0),
        ([_int(-1)], -1),
        ([(-1, 0, b"", errno.ENOENT)], None),
    ],
    ids=["1", "0", "-1", "no such OID"],
)
def test_an_integer_oid(monkeypatch, answers, expected):
    fake = _fake_sysctl({"hw.optional.arm64": answers})
    monkeypatch.setattr(preflight, "_sysctlbyname", lambda: fake)
    assert preflight.sysctl_number("hw.optional.arm64") == expected


@pytest.mark.parametrize(
    "answers",
    [
        [(-1, 0, b"", errno.EPERM)],
        [(-1, 0, b"", errno.ENOMEM)],
        [(-1, 0, b"", 0)],
        [(0, 8, b"", 0)],
        [(0, 2, b"", 0)],
    ],
    ids=["refused", "no memory", "no errno", "an eight-byte value", "a two-byte value"],
)
def test_an_integer_oid_that_cannot_be_read_raises(monkeypatch, answers):
    fake = _fake_sysctl({"hw.optional.arm64": answers})
    monkeypatch.setattr(preflight, "_sysctlbyname", lambda: fake)
    with pytest.raises(OSError):
        preflight.sysctl_number("hw.optional.arm64")


def _text(value: bytes) -> list[tuple[int, int, bytes, int]]:
    return [(0, len(value), b"", 0), (0, len(value), value, 0)]


@pytest.mark.parametrize(
    ("answers", "expected"),
    [
        (_text(b"25.6.0\x00"), "25.6.0"),
        (_text(b"x" * 255 + b"\x00"), "x" * 255),
        (_text(b"x" * 256 + b"\x00"), None),
        ([(-1, 0, b"", errno.ENOENT)], None),
        ([(-1, 0, b"", errno.EPERM)], None),
        ([(-1, 7, b"", errno.EPERM)], None),
        ([(0, 0, b"", 0)], None),
        ([(0, 300, b"", 0)], None),
        ([(0, 7, b"", 0), (-1, 7, b"", errno.ENOMEM)], None),
        (_text(b"25\x076\x00"), None),
        (_text(b"2\xff5.6.0\x00"), None),
        (_text(b"25.6.0\xc3\xa9\x00"), None),
    ],
    ids=[
        "a release",
        "256 bytes with the NUL",
        "257 bytes with the NUL",
        "no such OID",
        "refused",
        "refused, with a size",
        "empty",
        "too long",
        "the second call fails",
        "a control",
        "a byte that is not ASCII",
        "UTF-8 that is not ASCII",
    ],
)
def test_a_text_oid(monkeypatch, answers, expected):
    fake = _fake_sysctl({"kern.osrelease": answers})
    monkeypatch.setattr(preflight, "_sysctlbyname", lambda: fake)
    assert preflight.sysctl_text("kern.osrelease") == expected


def test_no_library_means_nothing_could_be_read(monkeypatch):
    def missing(path: str, **kwargs: object) -> object:
        raise OSError(path)

    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(ctypes, "CDLL", missing)
    with pytest.raises(OSError):
        preflight.sysctl_number("hw.optional.arm64")
    assert preflight.sysctl_text("kern.osrelease") is None
    found = preflight.read()
    assert found == P(True, None, None, None)
    assert preflight.refusal(found) == preflight.UNKNOWN_PROCESSOR


def test_the_library_keeps_errno(monkeypatch):
    # errno tells a missing OID (ENOENT) from a read that failed, so ctypes must keep it.
    seen: list[dict[str, object]] = []

    class Library:
        sysctlbyname = staticmethod(_fake_sysctl({"hw.optional.arm64": [_int(1)]}))

    def spy(path: str, **kwargs: object) -> Library:
        seen.append({"path": path, **kwargs})
        return Library()

    monkeypatch.setattr(ctypes, "CDLL", spy)
    assert preflight.sysctl_number("hw.optional.arm64") == 1
    assert seen == [{"path": "/usr/lib/libSystem.B.dylib", "use_errno": True}]


# On macOS, ctypes' own __init__ calls os.uname(), whose result carries the host name, the
# spec never reads (change record 2). These run in a child with sys.platform set to darwin
# before anything is imported, so they exercise ctypes' Darwin branch on Linux CI too.
_UNAME_SPY = (
    "import os, posix, sys\n"
    "calls = []\n"
    "def spy(*args):\n"
    "    calls.append(1)\n"
    "    raise PermissionError('uname was called')\n"
    "os.uname = posix.uname = spy\n"
    "sys.platform = 'darwin'\n"
    "from voltry_mac import cli, run\n"
    "run.collect = lambda args, found: 0  # the preflight's part of a run, and nothing more\n"
    "code = cli.main(sys.argv[1:])\n"
    "kept = 'yes' if os.uname is spy else 'no'\n"
    "sys.stderr.write(f'\\nUNAME {len(calls)} EXIT {code} KEPT {kept}\\n')\n"
)
ANY_RUN = [["--version"], ["--dry-run"], ["--help"], [], ["render", "report.json"]]


def _spied(argv: list[str], tmp_path: Path) -> tuple[int, str]:
    child = subprocess.run(  # noqa: S603 - a test-owned child
        [sys.executable, "-c", _UNAME_SPY, *argv],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=tmp_path,
    )
    return child.returncode, child.stderr


@pytest.mark.parametrize("argv", ANY_RUN, ids=str)
def test_no_run_calls_uname(argv, tmp_path):
    code, err = _spied(argv, tmp_path)
    assert "Traceback" not in err, err
    assert code == 0 and "\nUNAME 0 EXIT " in err, err
    assert err.rstrip().endswith("KEPT yes"), "whatever was os.uname is put back"


@pytest.mark.parametrize("argv", [["--version"], ["--dry-run"], []], ids=str)
def test_a_host_name_that_cannot_be_read_breaks_no_run(argv, tmp_path):
    # The spy raises as uname(3) does when a sandbox denies kern.hostname: every run still
    # answers, --version and --dry-run with 0, a collection with its own code.
    code, err = _spied(argv, tmp_path)
    assert "Traceback" not in err
    assert code == 0 and re.search(r"EXIT [0235] KEPT yes$", err.rstrip())
    assert list(tmp_path.iterdir()) == []


def test_without_ctypes_r4_reads_nothing(monkeypatch):
    # A Python built without ctypes: R4 is unread, the collection is refused, and
    # --version still answers.
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setitem(sys.modules, "ctypes", None)
    found = preflight.read()
    assert found == P(True, None, None, None)
    assert preflight.refusal(found) == preflight.UNKNOWN_PROCESSOR


def test_what_ctypes_sees_of_uname_is_a_release_and_no_host_name(monkeypatch):
    # In-process ctypes is already loaded, so the swap is checked directly: during it,
    # os.uname answers a release past Darwin 7 and carries no host name; after it, even
    # when the import fails, os.uname is the real function again.
    real = os.uname
    seen = []
    monkeypatch.setitem(sys.modules, "ctypes", None)

    def spy_import() -> None:
        with preflight._uname_swapped_out():
            answer = os.uname()
            seen.append((int(answer.release.split(".")[0]), hasattr(answer, "nodename")))
            import ctypes  # noqa: F401 - blocked above, so this raises

    with pytest.raises(ImportError):
        spy_import()
    assert seen == [(24, False)]
    assert os.uname is real
    assert os.uname is posix.uname, "the builtin itself, which the swap never touches"


def _swaps(monkeypatch) -> list[int]:
    entered: list[int] = []
    real = preflight._uname_swapped_out

    @contextlib.contextmanager
    def counted():
        entered.append(1)
        with real():
            yield

    monkeypatch.setattr(preflight, "_uname_swapped_out", counted)
    return entered


def test_the_swap_runs_only_while_ctypes_is_not_loaded(monkeypatch):
    # Once ctypes is loaded its __init__ never runs again, so there is nothing to set aside,
    # and another thread's os.uname() is never answered by the stand-in.
    entered = _swaps(monkeypatch)
    with contextlib.suppress(OSError):
        preflight.sysctl_number("hw.optional.arm64")
    assert entered == []
    monkeypatch.delitem(sys.modules, "ctypes")
    with contextlib.suppress(OSError):
        preflight.sysctl_number("hw.optional.arm64")
    assert entered == [1]


@pytest.mark.parametrize("error", [ImportError("no ctypes"), AttributeError("sysname")])
def test_any_failure_to_load_ctypes_leaves_r4_unread(monkeypatch, error):
    # A later ctypes that read another uname field would meet the stand-in's missing
    # attribute; that too is a read that failed, never a traceback.
    @contextlib.contextmanager
    def fails():
        raise error
        yield  # pragma: no cover - never reached

    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.delitem(sys.modules, "ctypes")
    monkeypatch.setattr(preflight, "_uname_swapped_out", fails)
    assert preflight.read() == P(True, None, None, None)


def test_ctypes_is_imported_only_when_r4_reads():
    source = Path(preflight.__file__).read_text()
    assert "\nimport ctypes" not in source, "a module-level import runs ctypes' uname call"


# --- the admin group and the terminal ---------------------------------------------------------


@pytest.fixture
def no_names(monkeypatch):
    """Fail on any read of a group or account name, or of a group's members."""

    def refuse(*args: object) -> object:
        raise AssertionError("a group or account name was read")

    for name in ("getgrnam", "getgrgid", "getgrall"):
        monkeypatch.setattr(grp, name, refuse)
    for name in ("getpwnam", "getpwuid", "getpwall"):
        monkeypatch.setattr(pwd, name, refuse)


@pytest.mark.parametrize(
    ("groups", "expected"),
    [
        ([20, 80, 12], True),
        ([20, 12], False),
        ([], False),
        ([*range(100, 119), 80], True),
        ([180, 800, 8], False),
    ],
    ids=["in admin", "not in admin", "no groups", "admin twentieth", "near misses"],
)
def test_the_admin_group_is_its_fixed_id_among_this_processs_groups(
    monkeypatch, no_names, groups, expected
):
    monkeypatch.setattr(os, "getgroups", lambda: groups)
    assert preflight.admin() is expected


def test_the_admin_check_reads_no_names():
    source = Path(preflight.__file__).read_text()
    assert "import grp" not in source and "import pwd" not in source
    assert preflight.ADMIN_GID == 80


def test_a_group_list_that_cannot_be_read_is_unknown(monkeypatch, no_names):
    def fails() -> list[int]:
        raise OSError(errno.EIO, "no answer")

    monkeypatch.setattr(os, "getgroups", fails)
    assert preflight.admin() is None


@pytest.mark.parametrize("error", [RuntimeError("a bug"), MemoryError(), KeyError(80)])
def test_any_failure_of_the_admin_check_is_unknown_and_silent(capfd, monkeypatch, no_names, error):
    def fails() -> list[int]:
        raise error

    monkeypatch.setattr(os, "getgroups", fails)
    assert preflight.admin() is None
    assert capfd.readouterr().err == ""


_STALLED_ADMIN = (
    "import os, threading\n"
    "from voltry_mac import preflight\n"
    "os.getgroups = lambda: threading.Event().wait()\n"
    "preflight.ADMIN_S = 0.1\n"
    "print(preflight.admin())\n"
)


def test_a_check_that_never_returns_does_not_keep_the_process_alive():
    # The worker is a daemon thread: the run ends even while getgroups() waits forever.
    child = subprocess.run(  # noqa: S603 - a test-owned child
        [sys.executable, "-c", _STALLED_ADMIN], capture_output=True, text=True, timeout=30
    )
    assert (child.returncode, child.stdout) == (0, "None\n")


def test_the_admin_check_is_bounded_like_r5(monkeypatch, no_names):
    assert preflight.ADMIN_S == 5
    release = threading.Event()

    def stalls() -> list[int]:
        release.wait(10)
        return [80]

    monkeypatch.setattr(os, "getgroups", stalls)
    monkeypatch.setattr(preflight, "ADMIN_S", 0.05)
    started = time.monotonic()
    try:
        assert preflight.admin() is None, "a directory that does not answer is unknown"
        assert time.monotonic() - started < 2
    finally:
        release.set()


@LIVE
def test_this_macs_admin_check_answers():
    assert preflight.admin() is (80 in os.getgroups())


class _Stdin:
    def __init__(self, tty: bool) -> None:
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


@pytest.mark.parametrize(
    ("stdin", "expected"), [(_Stdin(True), True), (_Stdin(False), False), (None, False)]
)
def test_a_terminal_is_one_on_stdin(monkeypatch, stdin, expected):
    monkeypatch.setattr(sys, "stdin", stdin)
    assert preflight.terminal() is expected


# --- --version ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("found", "lines"),
    [
        (APPLE_SILICON, ["Architecture arm64", "Rosetta no"]),
        (P(True, True, True, None), ["Architecture x86_64", "Rosetta yes"]),
        (P(True, False, False, None), ["Architecture x86_64", "Rosetta no"]),
        (P(True, False, None, None), ["Architecture x86_64", "Rosetta unknown"]),
        (P(True, True, None, None), ["Architecture unknown", "Rosetta unknown"]),
        (P(True, None, False, None), ["Architecture unknown", "Rosetta no"]),
        (P(True, None, True, None), ["Architecture x86_64", "Rosetta yes"]),
        (P(True, None, None, None), ["Architecture unknown", "Rosetta unknown"]),
        (P(False, None, None, None), ["Architecture unknown", "Rosetta unknown"]),
    ],
    ids=[
        "Apple silicon",
        "under Rosetta",
        "Intel",
        "Intel, translation unread",
        "translation unread",
        "processor type unread",
        "processor type unread, translated",
        "nothing read",
        "not macOS",
    ],
)
def test_version_names_the_interpreters_architecture_and_rosetta(capsys, monkeypatch, found, lines):
    # The architecture is the interpreter's, as the report's tool object names it beside
    # the Python (change record 2): x86_64 under Rosetta.
    monkeypatch.setattr(preflight, "read", lambda **_: found)
    code, out, err = _run(capsys, "--version")
    assert (code, err) == (0, "")
    assert out.splitlines()[2:] == lines


def test_a_collection_reads_the_release(capsys, mac, monkeypatch):
    monkeypatch.setattr("voltry_mac.run.collect", lambda args, found: 0)
    asked: list[dict[str, object]] = []
    monkeypatch.setattr(preflight, "read", lambda **kwargs: asked.append(kwargs) or APPLE_SILICON)
    _run(capsys)
    assert len(asked) == 1 and asked[0].get("release", True) is True
    asked.clear()
    _run(capsys, "--version")
    assert asked == [{"release": False}]


def test_version_reads_the_two_flags_and_not_the_release(capsys, monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    asked: list[str] = []

    def number(name: str) -> int | None:
        asked.append(name)
        return {"hw.optional.arm64": 1, "sysctl.proc_translated": 0}[name]

    def refuse(name: str) -> str | None:
        raise AssertionError(f"{name} was read")

    monkeypatch.setattr(preflight, "sysctl_number", number)
    monkeypatch.setattr(preflight, "sysctl_text", refuse)
    code, out, _ = _run(capsys, "--version")
    assert code == 0 and out.splitlines()[2:] == ["Architecture arm64", "Rosetta no"]
    assert asked == ["hw.optional.arm64", "sysctl.proc_translated"]
