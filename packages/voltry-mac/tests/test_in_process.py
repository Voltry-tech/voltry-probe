"""The reads voltry-mac makes in its own process, with no command: R1, R2 and R3
(docs/VOLTRY_MAC_SPEC.md, the allow-list's in-process reads; Decision 8's time fields; the
page setup's paper rule; the field inventory's panic_report_count).

R1 counts the names ending in .panic in /Library/Logs/DiagnosticReports and keeps only the
count: the folder is readable by administrators only, so a standard account, which macOS
refuses with EACCES, gets no_admin; a refusal by policy (EPERM) is tool_error. R2 keeps the
part of the /etc/localtime link after its zoneinfo folder as the time zone identifier, or
unknown. R3 reads one key, AppleLocale, from the owner's .GlobalPreferences.plist with the
standard plist parser, for the paper: US Letter when its region is US or CA, as ICU reads a
locale's region, A4 otherwise, including when nothing can be read. Each is one read,
bounded in time, spawns nothing, writes nothing and keeps nothing.
"""

from __future__ import annotations

import ast
import errno
import os
import plistlib
import random
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from voltry_mac import in_process, validate
from voltry_mac.availability import Unavailable

# --- R1, the panic count ------------------------------------------------------------------------


def test_the_panic_count_counts_names_ending_in_panic(tmp_path):
    for name in (
        "Kernel-2026-09-01-101010.panic",
        "Kernel-2026-09-02-101010.panic",
        ".hidden.panic",
        "Kernel-2026-09-03.panic.gz",
        "panic",
        "Kernel.PANIC",
        "Retired",
        "ResetCounter-2026-09-01.diag",
    ):
        (tmp_path / name).write_bytes(b"x")
    (tmp_path / "folder.panic").mkdir()
    assert in_process.panic_count(str(tmp_path)) == 4


def test_an_empty_folder_counts_zero(tmp_path):
    assert in_process.panic_count(str(tmp_path)) == 0


@pytest.mark.parametrize(
    ("error", "reason"),
    [
        (PermissionError(errno.EACCES, "Permission denied"), "no_admin"),
        (PermissionError(errno.EPERM, "Operation not permitted"), "tool_error"),
        (FileNotFoundError(errno.ENOENT, "No such file or directory"), "source_absent"),
        (NotADirectoryError(errno.ENOTDIR, "Not a directory"), "tool_error"),
        (OSError(errno.EIO, "Input/output error"), "tool_error"),
        (ValueError("embedded null byte"), "tool_error"),
    ],
    ids=["EACCES", "EPERM", "missing", "not a folder", "EIO", "not a path"],
)
def test_a_folder_that_cannot_be_listed_is_unavailable(monkeypatch, error, reason):
    # A standard account gets EACCES; EPERM is a sandbox, privacy or management policy
    # refusing an account that may well be an administrator, so it is not an expected gap.
    def refuse(path):
        raise error

    monkeypatch.setattr(in_process.os, "listdir", refuse)
    assert in_process.panic_count("/Library/Logs/DiagnosticReports") == Unavailable(reason)


def test_a_folder_only_administrators_can_read_is_no_admin(tmp_path):
    if os.getuid() == 0:
        pytest.skip("root reads any folder")
    folder = tmp_path / "DiagnosticReports"
    folder.mkdir()
    folder.chmod(0o000)
    try:
        assert in_process.panic_count(str(folder)) == Unavailable("no_admin")
    finally:
        folder.chmod(0o700)


def test_the_panic_count_reads_the_real_folder_by_default(monkeypatch):
    seen = []
    monkeypatch.setattr(in_process.os, "listdir", lambda path: seen.append(path) or [])
    assert in_process.panic_count() == 0
    assert seen == ["/Library/Logs/DiagnosticReports"]


def test_the_panic_count_lists_the_folder_once_and_returns_only_a_count(monkeypatch):
    calls = []

    def listdir(path):
        calls.append(path)
        return ["A.panic", "B.panic"]

    monkeypatch.setattr(in_process.os, "listdir", listdir)
    found = in_process.panic_count("/x")
    assert found == 2 and type(found) is int
    assert calls == ["/x"]


# --- R2, the time zone ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("target", "zone"),
    [
        ("/var/db/timezone/zoneinfo/America/Los_Angeles", "America/Los_Angeles"),
        ("/usr/share/zoneinfo/Europe/Berlin", "Europe/Berlin"),
        ("../usr/share/zoneinfo/Asia/Kolkata", "Asia/Kolkata"),
        ("/var/db/timezone/zoneinfo/UTC", "UTC"),
        ("/var/db/timezone/zoneinfo/Etc/GMT+5", "Etc/GMT+5"),
        ("/var/db/timezone/zoneinfo/Etc/GMT-14", "Etc/GMT-14"),
        ("/var/db/timezone/zoneinfo/America/Port-au-Prince", "America/Port-au-Prince"),
        (
            "/var/db/timezone/zoneinfo/America/Argentina/Buenos_Aires",
            "America/Argentina/Buenos_Aires",
        ),
        (
            "/var/db/timezone/zoneinfo/America/Argentina/ComodRivadavia",
            "America/Argentina/ComodRivadavia",
        ),
        ("/var/db/timezone/zoneinfo/" + "A" * 64, "A" * 64),
        ("/usr/share/zoneinfo/posix/Europe/Berlin", "posix/Europe/Berlin"),
        # The last zoneinfo folder in the target, a whole name, not the first match anywhere.
        ("/a/zoneinfo/b/zoneinfo/Europe/Berlin", "Europe/Berlin"),
    ],
)
def test_the_time_zone_is_the_link_after_its_zoneinfo_folder(tmp_path, target, zone):
    link = tmp_path / "localtime"
    link.symlink_to(target)
    assert in_process.time_zone(str(link)) == zone


@pytest.mark.parametrize(
    "target",
    [
        "/var/db/timezone/America/Los_Angeles",  # no zoneinfo folder
        "/var/db/timezone/myzoneinfo/Europe/Berlin",  # zoneinfo inside a name
        "/var/db/timezone/zoneinfo/",  # nothing after it
        "/var/db/timezone/zoneinfo",  # nothing after it at all
        "/var/db/timezone/zoneinfo/Bad Zone",  # a space
        "/var/db/timezone/zoneinfo/" + "A" * 65,  # past 64 characters
        "/var/db/timezone/zoneinfo/../../etc/passwd",  # a parent step
        "/var/db/timezone/zoneinfo/./UTC",  # a current-folder step
        "/var/db/timezone/zoneinfo/Europe//Berlin",  # an empty step
        "/var/db/timezone/zoneinfo/Europe/",  # a trailing slash
        "/var/db/timezone/zoneinfo/Zürich",  # outside ASCII
        "/var/db/timezone/zoneinfo/Europe/Ber@lin",  # a character the schema refuses
        "/var/db/timezone/zoneinfo/Europe:Berlin",
        "/var/db/timezone/zoneinfo/~Berlin",
    ],
)
def test_a_malformed_link_is_unknown(tmp_path, target):
    link = tmp_path / "localtime"
    link.symlink_to(target)
    assert in_process.time_zone(str(link)) == "unknown"


def test_no_link_is_unknown(tmp_path):
    assert in_process.time_zone(str(tmp_path / "missing")) == "unknown"
    plain = tmp_path / "localtime"
    plain.write_bytes(b"TZif")
    assert in_process.time_zone(str(plain)) == "unknown"
    assert in_process.time_zone("/etc/local\x00time") == "unknown"


def test_every_zone_it_keeps_is_one_the_schema_accepts(monkeypatch):
    # Any link target gives unknown or a zone the schema's pattern accepts.
    pieces = [
        "zoneinfo",
        "America",
        "Los_Angeles",
        "GMT+5",
        "GMT-14",
        "a.b",
        ".",
        "..",
        "",
        "x" * 40,
        "@",
        ":",
        "~",
        " ",
        "é",
        "\t",
        "Etc",
        "-",
        "+",
        "_",
    ]
    targets = random.Random(20260927)  # noqa: S311 - a fixed seed, a repeatable sweep
    kept = 0
    for _ in range(4000):
        target = "/".join(targets.choice(pieces) for _ in range(targets.randint(1, 7)))
        monkeypatch.setattr(in_process.os, "readlink", lambda path, target=target: target)
        zone = in_process.time_zone()
        if zone != "unknown":
            kept += 1
            assert validate._TIME_ZONE.fullmatch(zone), (target, zone)
    assert kept > 100


def test_the_time_zone_reads_the_real_link_by_default(monkeypatch):
    seen = []
    monkeypatch.setattr(
        in_process.os, "readlink", lambda path: seen.append(path) or "/x/zoneinfo/UTC"
    )
    assert in_process.time_zone() == "UTC"
    assert seen == ["/etc/localtime"]


# --- R3, the paper ------------------------------------------------------------------------------


def _preferences(home: Path, value: object, *, fmt=plistlib.FMT_BINARY) -> Path:
    folder = home / "Library" / "Preferences"
    folder.mkdir(parents=True, exist_ok=True)
    body = {
        "AppleLocale": value,
        "AppleLanguages": ["en-US"],
        "NSUserDictionaryReplacementItems": [],
    }
    target = folder / ".GlobalPreferences.plist"
    target.write_bytes(plistlib.dumps(body, fmt=fmt))
    return target


def _raw(home: Path, data: bytes) -> Path:
    folder = home / "Library" / "Preferences"
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / ".GlobalPreferences.plist"
    target.write_bytes(data)
    return target


@pytest.mark.parametrize(
    ("locale", "paper"),
    [
        ("en_US", "letter"),
        ("es_US", "letter"),
        ("en_CA", "letter"),
        ("fr_CA", "letter"),
        ("haw_US", "letter"),
        ("en_us", "letter"),
        ("EN_US", "letter"),
        ("en-US", "letter"),
        ("zh-Hans_US", "letter"),
        ("zh_Hans_US", "letter"),
        ("zh-Hant_CA", "letter"),
        ("sr_Latn_US", "letter"),
        ("en_US_POSIX", "letter"),
        ("es_US_TRADITIONAL", "letter"),
        ("en_US.UTF-8", "letter"),
        ("en_GB", "a4"),
        ("de_DE", "a4"),
        ("ja_JP", "a4"),
        ("en_MX", "a4"),
        ("es_419", "a4"),
        ("zh-Hans_CN", "a4"),
        ("en", "a4"),
        ("", "a4"),
        # ICU reads a three-letter region too, and any language part before it.
        ("en_USA", "letter"),
        ("en_usa", "letter"),
        ("en-USA", "letter"),
        ("en_Latn_USA", "letter"),
        ("en_CAN", "letter"),
        ("en_GBR", "a4"),
        ("_US", "letter"),
        ("a_US", "letter"),
        (" en_US", "letter"),
        ("en_US ", "a4"),
        # A region override (@rg=) names the region the owner chose instead. ICU reads the
        # first rg keyword only, whatever the case of its key, among other keywords, with
        # spaces trimmed, when its value is 3 to 6 characters starting with two ASCII
        # letters; any other value is ignored, and the locale's own region stands.
        ("en_US@rg=gbzzzz", "a4"),
        ("en_GB@rg=uszzzz", "letter"),
        ("en_GB@rg=USZZZZ", "letter"),
        ("en_GB@RG=uszzzz", "letter"),
        ("en_GB@rg=usca", "letter"),
        ("en_US@rg=gbsct", "a4"),
        ("en_GB@calendar=gregorian;rg=uszzzz", "letter"),
        ("en_GB@rg=uszzzz;calendar=gregorian", "letter"),
        ("en_US@calendar=japanese;rg=dezzzz", "a4"),
        ("en_US@currency=EUR", "letter"),
        ("en_GB@myrg=uszzzz", "a4"),
        ("en_GB@rg=us", "a4"),
        ("en_GB@rg=usz", "letter"),
        ("en_GB@rg=uszzzzz", "a4"),
        ("en_GB@rg=uszzzzzz", "a4"),
        ("en_US@rg=419zzzz", "letter"),
        ("en_US@rg=840zzz", "letter"),
        ("en_GB@rg=840zzz", "a4"),
        ("en_US@rg=1", "letter"),
        ("en_US@rg=ü1zzzz", "letter"),
        ("en_US@rg=üszzzz", "letter"),
        ("en_GB@rg= uszzzz", "letter"),
        ("en_GB@rg=uszzzz ", "letter"),
        ("en_GB@ rg=uszzzz", "letter"),
        ("en_GB@rg =uszzzz", "letter"),
        ("en_GB@rg=1;rg=uszzzz", "a4"),
        ("en_GB@rg=gbzzzz;rg=uszzzz", "a4"),
        ("en_GB@rg=uszzzz;rg=gbzzzz", "letter"),
    ],
)
def test_the_paper_follows_the_locales_region(tmp_path, locale, paper):
    _preferences(tmp_path, locale)
    assert in_process.paper(str(tmp_path)) == paper


def test_a_locale_past_our_bound_is_a4(tmp_path):
    # The bound is ours, on the input, not ICU's: ICU reads longer locales, but
    # CoreFoundation aborts on some past 157 characters, so a longer AppleLocale is not a
    # setting that works (the #355 review, round 2).
    assert in_process.LOCALE_MAX == 157
    _preferences(tmp_path, "en_US@" + "x" * 151)
    assert in_process.paper(str(tmp_path)) == "letter"
    _preferences(tmp_path, "en_US@" + "x" * 152)
    assert in_process.paper(str(tmp_path)) == "a4"


def test_a_crafted_locale_is_read_at_once(tmp_path):
    # A locale built to make a backtracking pattern slow, well inside the file's cap.
    _preferences(tmp_path, "en_GB@" + "@;" * 40_000)
    started = time.monotonic()
    assert in_process.paper(str(tmp_path)) == "a4"
    assert time.monotonic() - started < 2


def test_an_xml_preferences_file_reads_the_same(tmp_path):
    _preferences(tmp_path, "en_US", fmt=plistlib.FMT_XML)
    assert in_process.paper(str(tmp_path)) == "letter"


@pytest.mark.parametrize("value", [None, 7, ["en_US"], {"region": "US"}, b"en_US"])
def test_a_locale_that_is_not_text_is_a4(tmp_path, value):
    folder = tmp_path / "Library" / "Preferences"
    folder.mkdir(parents=True)
    body = {} if value is None else {"AppleLocale": value}
    (folder / ".GlobalPreferences.plist").write_bytes(plistlib.dumps(body))
    assert in_process.paper(str(tmp_path)) == "a4"


@pytest.mark.parametrize("root", [["en_US"], "en_US", 7])
def test_a_preferences_file_whose_root_is_not_a_dictionary_is_a4(tmp_path, root):
    _raw(tmp_path, plistlib.dumps(root))
    assert in_process.paper(str(tmp_path)) == "a4"


def test_no_preferences_file_is_a4(tmp_path):
    assert in_process.paper(str(tmp_path)) == "a4"


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"not a plist",
        b"bplist00" + b"\x00" * 40,
        # Truncated XML: the parser raises ExpatError.
        b'<?xml version="1.0"?><plist><dict><key>AppleLocale</key><string>en_US',
        # A date the parser cannot read: it raises what it raises, not only ValueError.
        b'<?xml version="1.0"?><plist version="1.0"><dict><key>AppleLocale</key>'
        b"<string>en_US</string><key>d</key><date>garbage</date></dict></plist>",
    ],
    ids=["empty", "text", "a broken binary plist", "truncated XML", "a bad date"],
)
def test_a_preferences_file_that_does_not_parse_is_a4(tmp_path, data):
    _raw(tmp_path, data)
    assert in_process.paper(str(tmp_path)) == "a4"


def _sized(size: int) -> bytes:
    """An XML plist naming en_US of exactly ``size`` bytes."""
    empty = plistlib.dumps({"AppleLocale": "en_US", "Filler": ""}, fmt=plistlib.FMT_XML)
    data = plistlib.dumps(
        {"AppleLocale": "en_US", "Filler": "x" * (size - len(empty))}, fmt=plistlib.FMT_XML
    )
    assert len(data) == size
    return data


def test_a_preferences_file_at_its_cap_is_read_and_one_byte_past_it_is_a4(tmp_path):
    _raw(tmp_path, _sized(in_process.PREFERENCES_CAP))
    assert in_process.paper(str(tmp_path)) == "letter"
    _raw(tmp_path, _sized(in_process.PREFERENCES_CAP + 1))
    assert in_process.paper(str(tmp_path)) == "a4"


def test_a_preferences_file_that_cannot_be_read_is_a4(tmp_path):
    if os.getuid() == 0:
        pytest.skip("root reads any file")
    target = _preferences(tmp_path, "en_US")
    target.chmod(0o000)
    try:
        assert in_process.paper(str(tmp_path)) == "a4"
    finally:
        target.chmod(0o600)


def test_a_link_at_the_preferences_file_is_not_followed(tmp_path):
    elsewhere = tmp_path / "elsewhere.plist"
    elsewhere.write_bytes(plistlib.dumps({"AppleLocale": "en_US"}))
    folder = tmp_path / "home" / "Library" / "Preferences"
    folder.mkdir(parents=True)
    (folder / ".GlobalPreferences.plist").symlink_to(elsewhere)
    assert in_process.paper(str(tmp_path / "home")) == "a4"


def test_a_folder_where_the_preferences_file_should_be_is_a4(tmp_path):
    (tmp_path / "Library" / "Preferences" / ".GlobalPreferences.plist").mkdir(parents=True)
    assert in_process.paper(str(tmp_path)) == "a4"


def test_a_fifo_where_the_preferences_file_should_be_is_a4_at_once(tmp_path):
    folder = tmp_path / "Library" / "Preferences"
    folder.mkdir(parents=True)
    os.mkfifo(folder / ".GlobalPreferences.plist")
    answer = []
    worker = threading.Thread(
        target=lambda: answer.append(in_process.paper(str(tmp_path))), daemon=True
    )
    worker.start()
    worker.join(10)
    assert not worker.is_alive(), "the read blocked on a FIFO"
    assert answer == ["a4"]


@pytest.mark.parametrize("home", ["", "relative/home"])
def test_a_home_folder_that_is_not_an_absolute_path_is_a4(tmp_path, monkeypatch, home):
    monkeypatch.chdir(tmp_path)
    _preferences(tmp_path / "relative" / "home", "en_US")
    _preferences(tmp_path, "en_US")
    assert in_process.paper(home) == "a4"


def test_a_home_folder_with_a_nul_in_its_path_is_a4(tmp_path):
    _preferences(tmp_path, "en_US")
    assert in_process.paper(f"{tmp_path}\x00") == "a4"


def test_a_fifo_with_a_writer_is_not_read(tmp_path):
    # Opened without waiting, a FIFO with a writer would give that writer's bytes; only a
    # regular file is read.
    folder = tmp_path / "Library" / "Preferences"
    folder.mkdir(parents=True)
    fifo = folder / ".GlobalPreferences.plist"
    os.mkfifo(fifo)
    writer = os.open(fifo, os.O_RDWR | os.O_NONBLOCK)
    try:
        os.write(writer, plistlib.dumps({"AppleLocale": "en_US"}))
        assert in_process.paper(str(tmp_path)) == "a4"
    finally:
        os.close(writer)


def _colliding(keys: int) -> bytes:
    """A binary plist naming en_US in a dictionary with ``keys`` more integer keys, each a
    multiple of 2**61 - 1, which CPython hashes alike (the #355 review, round 2)."""
    shared = (1 << 61) - 1
    objects = [b"", b"\x5bAppleLocale", b"\x55en_US", b"\x09"]
    first = len(objects)
    objects += [b"\x14" + (i * shared).to_bytes(16, "big", signed=True) for i in range(1, keys + 1)]
    count = len(objects)

    def refs(values: list[int]) -> bytes:
        return b"".join(value.to_bytes(2, "big") for value in values)

    size = keys + 1
    objects[0] = b"\xdf\x12" + struct.pack(">L", size) + refs([1, *range(first, count)])
    objects[0] += refs([2] + [3] * keys)
    body = bytearray(b"bplist00")
    offsets = []
    for item in objects:
        offsets.append(len(body))
        body += item
    table = len(body)
    body += b"".join(offset.to_bytes(3, "big") for offset in offsets)
    body += b"\x00" * 6 + bytes([3, 2]) + struct.pack(">QQQ", count, 0, table)
    return bytes(body)


def test_a_preferences_file_with_keys_that_are_not_text_is_a4_at_once(tmp_path):
    # A preferences file keys everything by text; one keyed by integers that share a hash
    # would make each insert compare with every key before it, for seconds, inside the cap.
    data = _colliding(43_000)
    assert len(data) <= in_process.PREFERENCES_CAP
    _raw(tmp_path, data)
    started = time.monotonic()
    assert in_process.paper(str(tmp_path)) == "a4"
    assert time.monotonic() - started < 2


def test_the_preferences_cap_is_one_mebibyte():
    assert in_process.PREFERENCES_CAP == 1024 * 1024


def test_the_preferences_file_is_closed_even_when_the_close_fails(tmp_path, monkeypatch):
    _preferences(tmp_path, "en_US")
    closed = []
    real = os.close

    def close(descriptor):
        closed.append(descriptor)
        real(descriptor)
        raise OSError(errno.EIO, os.strerror(errno.EIO))

    monkeypatch.setattr(in_process.os, "close", close)
    assert in_process.paper(str(tmp_path)) == "letter"
    assert len(closed) == 1


@pytest.mark.parametrize("step", ["fstat", "read"])
def test_a_preferences_file_that_fails_while_it_is_read_is_a4(tmp_path, monkeypatch, step):
    _preferences(tmp_path, "en_US")

    def fail(*args):
        raise OSError(errno.EIO, os.strerror(errno.EIO))

    monkeypatch.setattr(in_process.os, step, fail)
    assert in_process.paper(str(tmp_path)) == "a4"


def test_the_paper_parses_the_file_once(tmp_path, monkeypatch):
    _preferences(tmp_path, "en_US")
    loaded = []
    real = in_process.plistlib.loads
    monkeypatch.setattr(
        in_process.plistlib, "loads", lambda data, **kw: loaded.append(1) or real(data, **kw)
    )
    assert in_process.paper(str(tmp_path)) == "letter"
    assert loaded == [1], "one parse of one read"


# --- the module ---------------------------------------------------------------------------------


def test_the_reads_spawn_nothing_write_nothing_and_reach_no_network():
    tree = ast.parse(Path(in_process.__file__).read_text(encoding="utf-8"))
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    assert imported <= {
        "__future__",
        "contextlib",
        "errno",
        "os",
        "plistlib",
        "re",
        "stat",
        "typing",
        "voltry_mac",
    }
    source = Path(in_process.__file__).read_text(encoding="utf-8")
    for name in ("subprocess", "socket", "O_WRONLY", "O_RDWR", "O_CREAT", "unlink", "rename"):
        assert name not in source, name


def test_the_reads_keep_nothing_in_the_module(tmp_path):
    _preferences(tmp_path, "en_US")
    before = {name: id(value) for name, value in vars(in_process).items()}
    in_process.panic_count(str(tmp_path))
    in_process.time_zone(str(tmp_path / "missing"))
    in_process.paper(str(tmp_path))
    assert {name: id(value) for name, value in vars(in_process).items()} == before
    # Nor on a function: an attribute set on one would outlive the read.
    for function in (in_process.panic_count, in_process.time_zone, in_process.paper):
        assert vars(function) == {}, function.__name__


# The reads, run in a child with an audit hook: one listing, one link read and one file
# opened for reading, nothing else of the kinds that start, write or reach anything.
_AUDITED = """
import os, sys, collections, plistlib
from voltry_mac import in_process
home, folder, link = sys.argv[1:4]
seen = collections.Counter()
recording = False
def hook(event, args):
    if not recording:
        return
    if event == "open":
        seen[f"open {args[2]:#x}"] += 1
    elif event.startswith(("os.", "subprocess", "socket", "shutil", "tempfile", "ctypes")):
        seen[event] += 1
sys.addaudithook(hook)
recording = True
in_process.panic_count(folder)
in_process.time_zone(link)
in_process.paper(home)
recording = False
print(sorted(seen.items()))
"""


def test_the_reads_make_one_listing_and_open_one_file_for_reading(tmp_path):
    _preferences(tmp_path, "en_US")
    (tmp_path / "reports").mkdir()
    (tmp_path / "localtime").symlink_to("/var/db/timezone/zoneinfo/UTC")
    ran = subprocess.run(
        [
            sys.executable,
            "-c",
            _AUDITED,
            str(tmp_path),
            str(tmp_path / "reports"),
            str(tmp_path / "localtime"),
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    assert ran.stdout.strip() == str(sorted({"os.listdir": 1, f"open {flags:#x}": 1}.items()))


# --- the review of #326, round 1, N1 ------------------------------------------------------------


@pytest.mark.parametrize(("first", "second"), [("en_US", "en_GB"), ("en_GB", "en_US")])
def test_applelocale_given_twice_is_a_file_the_paper_cannot_read(tmp_path, first, second):
    # The parser kept the last of the two, so the paper turned on their order. Either order
    # is now what any file the parser cannot read gives: A4.
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0"><dict>'
        f"<key>AppleLocale</key><string>{first}</string>"
        f"<key>AppleLocale</key><string>{second}</string>"
        "</dict></plist>\n"
    )
    _raw(tmp_path, xml.encode())
    assert in_process.paper(str(tmp_path)) == "a4"


def test_a_key_given_twice_deeper_in_the_file_is_a4_too(tmp_path):
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0"><dict>'
        "<key>AppleLocale</key><string>en_US</string>"
        "<key>NSUserDictionaryReplacementItems</key><array><dict>"
        "<key>replace</key><string>omw</string><key>replace</key><string>brb</string>"
        "</dict></array></dict></plist>\n"
    )
    _raw(tmp_path, xml.encode())
    assert in_process.paper(str(tmp_path)) == "a4"
