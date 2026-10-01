"""The SMART child, C28 (docs/VOLTRY_MAC_SPEC.md, the C28 contract, and Test strategy
part 2 item 6, "SMART vtable").

The child enumerates at most 8 NVMe controllers, lists each one's whole-disk media, calls
SMARTReadData once per controller and prints one ASCII JSON document of at most 64 KiB:
exit 0 when a controller read, 2 when none did or none exists, 3 when enumeration itself
failed. Its vtables bind only QueryInterface, SMARTReadData, Stop and Release as
callables; a fake COM object here records every call and proves nothing else is used.
"""

from __future__ import annotations

import ctypes
import json
import os
import subprocess
import sys
import time
from ctypes import (
    CFUNCTYPE,
    POINTER,
    Structure,
    c_int32,
    c_uint16,
    c_uint32,
    c_uint64,
    c_void_p,
)
from pathlib import Path

import pytest

from voltry_mac import allowlist
from voltry_mac import smart_iokit as child

LOG = bytes(range(256)) * 2  # 512 distinct-ish bytes


def test_the_childs_docstring_gives_c28_as_the_allow_list_does():
    # The review of the audit fixes, round 3, n3: it still gave C28 without -B (change
    # record 8).
    assert f"``{allowlist.display(allowlist.BY_ID['C28'].template)}``" in (child.__doc__ or "")


# --- the vtable ---------------------------------------------------------------------------------


def test_only_the_calls_the_child_makes_are_callable():
    # The plug-in's QueryInterface obtains the SMART interface; of that interface only the
    # read and the Release that gives it back are bound, so its own QueryInterface, the
    # identify call and the log-page call stay opaque pointers.
    callables = {name for name, kind in child.SMARTVtbl._fields_ if hasattr(kind, "argtypes")}
    assert callables == {"Release", "SMARTReadData"}
    # Of the plug-in: QueryInterface, and the Stop and Release that IODestroyPlugInInterface
    # makes, which close the SMART user client and give the plug-in back.
    plugin_callables = {
        name for name, kind in child.PlugInVtbl._fields_ if hasattr(kind, "argtypes")
    }
    assert plugin_callables == {"QueryInterface", "Release", "Stop"}


def test_the_vtable_offsets_are_the_headers():
    assert child.SMARTVtbl.version.offset == 32
    assert child.SMARTVtbl.SMARTReadData.offset == 40
    assert child.SMARTVtbl.GetIdentifyData.offset == 48
    assert child.SMARTVtbl.GetLogPage.offset == 72
    assert child.PlugInVtbl.version.offset == 32
    assert child.PlugInVtbl.Stop.offset == 56


# --- a fake COM object that records every call ---------------------------------------------------


class _Calls(list):
    pass


E_NOINTERFACE = -2147483644  # 0x80000004 as the HRESULT it is


def _fake_plugin(
    calls: _Calls, *, interface: bool = True, read_status: int = 0, query_status: int | None = None
):
    """A fake IOCFPlugInInterface** whose QueryInterface hands out a fake SMART interface,
    or returns ``query_status`` (E_NOINTERFACE by default) when ``interface`` is False."""
    keep: list[object] = []  # the callbacks and structs must outlive the call

    @CFUNCTYPE(c_int32, c_void_p, child.CFUUIDBytes, POINTER(c_void_p))
    def smart_query(this, iid, out):
        calls.append("smart.QueryInterface")
        return 1

    @CFUNCTYPE(c_uint32, c_void_p)
    def smart_release(this):
        calls.append("smart.Release")
        return 0

    @CFUNCTYPE(c_int32, c_void_p, POINTER(child.NVMeSMARTData))
    def read(this, data):
        calls.append("smart.SMARTReadData")
        ctypes.memmove(data, LOG, 512)
        return read_status

    @CFUNCTYPE(c_int32, c_void_p)
    def forbidden(this):
        calls.append("a forbidden slot")
        return 0

    class FakeSMARTVtbl(Structure):
        _fields_ = [
            ("_reserved", c_void_p),
            ("QueryInterface", type(smart_query)),
            ("AddRef", type(forbidden)),
            ("Release", type(smart_release)),
            ("version", c_uint16),
            ("revision", c_uint16),
            ("SMARTReadData", type(read)),
            ("GetIdentifyData", type(forbidden)),
            ("reserved0", c_uint64),
            ("reserved1", c_uint64),
            ("GetLogPage", type(forbidden)),
        ]

    smart_vtbl = FakeSMARTVtbl(
        None, smart_query, forbidden, smart_release, 1, 0, read, forbidden, 0, 0, forbidden
    )
    smart_object = POINTER(FakeSMARTVtbl)(smart_vtbl)

    @CFUNCTYPE(c_int32, c_void_p, child.CFUUIDBytes, POINTER(c_void_p))
    def plugin_query(this, iid, out):
        calls.append("plugin.QueryInterface")
        assert bytes(iid.bytes) == child.SMART_INTERFACE_ID
        if not interface:
            return E_NOINTERFACE if query_status is None else query_status
        out[0] = ctypes.cast(ctypes.pointer(smart_object), c_void_p).value
        return 0

    @CFUNCTYPE(c_uint32, c_void_p)
    def plugin_release(this):
        calls.append("plugin.Release")
        return 0

    @CFUNCTYPE(c_int32, c_void_p)
    def plugin_stop(this):
        calls.append("plugin.Stop")
        return 0

    class FakePlugInVtbl(Structure):
        _fields_ = [
            ("_reserved", c_void_p),
            ("QueryInterface", type(plugin_query)),
            ("AddRef", type(forbidden)),
            ("Release", type(plugin_release)),
            ("version", c_uint16),
            ("revision", c_uint16),
            ("Probe", type(forbidden)),
            ("Start", type(forbidden)),
            ("Stop", type(plugin_stop)),
        ]

    plugin_vtbl = FakePlugInVtbl(
        None, plugin_query, forbidden, plugin_release, 1, 0, forbidden, forbidden, plugin_stop
    )
    plugin_object = POINTER(FakePlugInVtbl)(plugin_vtbl)
    plugin = ctypes.cast(ctypes.pointer(plugin_object), c_void_p)
    keep.extend(
        [smart_query, smart_release, read, forbidden, plugin_query, plugin_release, plugin_stop]
    )
    keep.extend([smart_vtbl, smart_object, plugin_vtbl, plugin_object])
    return plugin, keep


def test_a_read_uses_only_query_interface_smart_read_data_stop_and_release():
    calls = _Calls()
    plugin, _keep = _fake_plugin(calls)
    assert child.read_smart(plugin) == {"status": "ok", "smart_hex": LOG.hex()}
    assert calls == [
        "plugin.QueryInterface",
        "smart.SMARTReadData",
        "smart.Release",
        "plugin.Stop",
        "plugin.Release",
    ]


def test_a_failed_read_is_smart_read_failed_and_still_releases():
    calls = _Calls()
    plugin, _keep = _fake_plugin(calls, read_status=-536870212)
    assert child.read_smart(plugin) == {"status": "error", "error": "smart_read_failed"}
    assert calls[-3:] == ["smart.Release", "plugin.Stop", "plugin.Release"]


def test_no_smart_interface_is_interface_unavailable():
    calls = _Calls()
    plugin, _keep = _fake_plugin(calls, interface=False)
    assert child.read_smart(plugin) == {"status": "error", "error": "interface_unavailable"}
    assert calls == ["plugin.QueryInterface", "plugin.Stop", "plugin.Release"]
    assert "a forbidden slot" not in calls


# --- enumeration and the document, through a fake registry --------------------------------------


class FakeRegistry:
    """The child's view of IOKit: services, each with a location, media and a reading."""

    def __init__(self, services=(), fail: bool = False):
        self._services = list(services)
        self._fail = fail
        self.reads = 0

    def services(self):
        if self._fail:
            raise child.EnumerationFailed
        return list(range(len(self._services)))

    def location(self, service):
        return self._services[service]["location"]

    def whole_media(self, service):
        return self._services[service]["media"]

    def read(self, service):
        self.reads += 1
        return self._services[service]["reading"]


OK = {"status": "ok", "smart_hex": LOG.hex()}
FAILED = {"status": "error", "error": "smart_read_failed"}


def test_one_controller_that_reads():
    registry = FakeRegistry([{"location": "Internal", "media": ["disk0"], "reading": OK}])
    text, code = child.report(registry)
    assert code == child.EXIT_READ
    assert json.loads(text) == {
        "schema": "voltry-mac-smart/0",
        "controllers": [
            {"location": "Internal", "media": ["disk0"], "status": "ok", "smart_hex": LOG.hex()}
        ],
    }
    assert text.isascii() and len(text.encode()) <= 64 * 1024


def test_no_controller_reads_or_none_exists():
    registry = FakeRegistry([{"location": "External", "media": ["disk4"], "reading": FAILED}])
    text, code = child.report(registry)
    assert code == child.EXIT_NONE_READ
    assert json.loads(text)["controllers"][0]["error"] == "smart_read_failed"
    assert child.report(FakeRegistry([])) == (child.document([]), child.EXIT_NONE_READ)


def test_a_failed_enumeration_lists_no_controllers():
    text, code = child.report(FakeRegistry(fail=True))
    assert (json.loads(text), code) == (
        {"schema": "voltry-mac-smart/0", "controllers": []},
        child.EXIT_ENUMERATION,
    )


def test_at_most_eight_controllers_and_a_controller_with_more_media_fails_closed():
    many = [
        {"location": "Internal", "media": [f"disk{n}", f"disk{n + 20}"], "reading": OK}
        for n in range(10)
    ]
    many[0]["media"] = [f"disk{n}" for n in range(30, 42)]
    registry = FakeRegistry(many)
    document = json.loads(child.report(registry)[0])
    assert len(document["controllers"]) == 8 and registry.reads == 7
    first = document["controllers"][0]
    assert first["media"] == [f"disk{n}" for n in range(30, 38)]
    assert (first["status"], first["error"]) == ("error", "smart_read_failed")


def test_a_location_other_than_internal_or_external_is_unknown():
    registry = FakeRegistry([{"location": "Thunderbolt", "media": ["disk2"], "reading": OK}])
    assert json.loads(child.report(registry)[0])["controllers"][0]["location"] == "Unknown"


@pytest.mark.parametrize(
    "other", ["Macintosh HD", "disk1000", None], ids=["a name", "four digits", "no name yet"]
)
def test_a_whole_medium_the_child_cannot_name_fails_its_record_closed(other):
    # Dropping it would make a two-disk controller look like a one-disk one (row 9).
    registry = FakeRegistry([{"location": "Internal", "media": ["disk0", other], "reading": OK}])
    record = json.loads(child.report(registry)[0])["controllers"][0]
    assert record == {
        "location": "Internal",
        "media": ["disk0"],
        "status": "error",
        "error": "smart_read_failed",
    }
    assert registry.reads == 0


def test_the_child_refuses_any_argument(capsys):
    assert child.main(["--anything"]) == child.EXIT_USAGE
    assert capsys.readouterr().out == ""


def _virtual() -> bool:
    from voltry_mac import spawn

    return spawn.Runner().run("C26").stdout.strip() == "1"


LIVE = pytest.mark.skipif(sys.platform != "darwin", reason="IOKit exists only on macOS")


@LIVE
def test_the_real_child_reads_this_macs_controller_through_the_chokepoint():
    from voltry_mac import smart, spawn

    if _virtual():
        pytest.skip("a virtual Mac has no SMART service to read")
    runner = spawn.Runner()
    for _ in range(3):  # another SMART reader may hold the client for a moment
        result = runner.run("C28", failed=smart.failed_run)
        assert result.ending is spawn.Ending.EXITED and result.returncode in (0, 2)
        document = json.loads(result.stdout)
        if result.returncode == 0:
            break
        time.sleep(1)
    assert document["schema"] == "voltry-mac-smart/0"
    (startup,) = [c for c in document["controllers"] if "disk0" in c["media"]]
    assert (startup["location"], startup["status"]) == ("Internal", "ok")
    assert [r.failed_runs for r in runner.records() if r.id == "C28"] == [0]


@LIVE
def test_the_registry_facade_reads_this_macs_startup_controller():
    # The same read-only calls the child makes, in this process, as the user.
    if _virtual():
        pytest.skip("a virtual Mac has no SMART service to read")
    registry = child.IOKitRegistry()
    try:
        services = registry.services()
        assert services, "an Apple silicon Mac has at least one NVMe controller"
        (startup,) = [s for s in services if "disk0" in registry.whole_media(s)]
        assert registry.location(startup) == "Internal"
        for _ in range(3):
            reading = registry.read(startup)
            if reading["status"] == "ok":
                break
            time.sleep(1)
        assert reading["status"] == "ok"
    finally:
        registry.close()


def test_main_prints_the_document_and_returns_its_status(capsys):
    registry = FakeRegistry([{"location": "Internal", "media": ["disk0"], "reading": OK}])
    assert child.main([], registry_type=lambda: registry) == child.EXIT_READ
    assert json.loads(capsys.readouterr().out)["controllers"][0]["media"] == ["disk0"]


# --- the #344 review, round 1 ------------------------------------------------------------------

KIO_RETURN_UNSUPPORTED = -536870201  # 0xE00002C7
KIO_RETURN_BUSY = -536870187  # 0xE00002D5
KIO_RETURN_NO_RESOURCES = -536870210  # 0xE00002BE
KIO_RETURN_EXCLUSIVE_ACCESS = -536870203  # 0xE00002C5
KIO_RETURN_ERROR = -536870212  # 0xE00002BC


def test_the_exit_statuses_are_the_contracts():
    assert (child.EXIT_READ, child.EXIT_NONE_READ, child.EXIT_ENUMERATION) == (0, 2, 3)
    assert child.EXIT_USAGE == 64


@pytest.mark.parametrize(
    ("status", "outcome"),
    [
        (0, "ok"),
        (KIO_RETURN_UNSUPPORTED, "interface_unavailable"),
        (KIO_RETURN_BUSY, "busy"),
        (KIO_RETURN_NO_RESOURCES, "busy"),
        (KIO_RETURN_EXCLUSIVE_ACCESS, "busy"),
        (KIO_RETURN_ERROR, "smart_read_failed"),
        (1, "smart_read_failed"),
    ],
)
def test_only_an_unsupported_open_means_no_interface(status, outcome):
    # A controller that carries "NVMe SMART Capable" offers the interface; another client
    # holding it, or any other failure, is a failed read (row 11), never unsupported.
    assert child.open_outcome(status) == outcome


def _opens(*statuses: int):
    calls: list[int] = []
    sleeps: list[float] = []
    plugin = c_void_p(1234)

    def create():
        status = statuses[len(calls)]
        calls.append(status)
        return status, plugin if status == 0 else c_void_p()

    return calls, sleeps, plugin, create


def test_a_busy_client_is_tried_again_a_few_times_then_fails_as_a_read():
    calls, sleeps, plugin, create = _opens(KIO_RETURN_BUSY, KIO_RETURN_NO_RESOURCES, 0)
    assert child.open_plugin(create, sleep=sleeps.append) == ("ok", plugin)
    assert len(calls) == 3 and len(sleeps) == 2 and sum(sleeps) < 2
    calls, sleeps, _, create = _opens(*([KIO_RETURN_BUSY] * 3))
    assert child.open_plugin(create, sleep=sleeps.append) == ("smart_read_failed", None)
    assert len(calls) == 3


@pytest.mark.parametrize(
    ("status", "outcome"),
    [(KIO_RETURN_UNSUPPORTED, "interface_unavailable"), (KIO_RETURN_ERROR, "smart_read_failed")],
)
def test_an_open_that_cannot_succeed_is_not_tried_again(status, outcome):
    calls, sleeps, _, create = _opens(status)
    assert child.open_plugin(create, sleep=sleeps.append) == (outcome, None)
    assert (len(calls), sleeps) == (1, [])


def test_query_interface_failing_otherwise_is_a_failed_read():
    calls = _Calls()
    plugin, _keep = _fake_plugin(calls, interface=False, query_status=1)
    assert child.read_smart(plugin) == {"status": "error", "error": "smart_read_failed"}
    assert calls == ["plugin.QueryInterface", "plugin.Stop", "plugin.Release"]


def test_the_location_external_is_kept():
    registry = FakeRegistry([{"location": "External", "media": ["disk4"], "reading": OK}])
    assert json.loads(child.report(registry)[0])["controllers"][0]["location"] == "External"


def test_main_closes_the_registry_and_an_unloadable_one_is_an_enumeration_failure(capsys):
    closed = []
    registry = FakeRegistry([{"location": "Internal", "media": ["disk0"], "reading": OK}])
    registry.close = lambda: closed.append(True)  # type: ignore[attr-defined]
    assert child.main([], registry_type=lambda: registry) == 0
    assert closed == [True]
    capsys.readouterr()

    def unloadable():
        raise OSError("no IOKit here")

    assert child.main([], registry_type=unloadable) == 3
    assert json.loads(capsys.readouterr().out) == {"schema": child.SCHEMA, "controllers": []}


def test_the_log_struct_declares_its_packed_layout():
    # Python 3.14 warns on _pack_ without _layout_, and the tests turn warnings into errors.
    assert child.NVMeSMARTData._pack_ == 1
    assert child.NVMeSMARTData._layout_ == "ms"


def test_the_child_names_no_key_that_carries_the_drives_serial():
    source = Path(child.__file__).read_text(encoding="utf-8")
    for key in ("Device Characteristics", "Serial Number", "IOPlatformSerialNumber"):
        assert key not in source, key


# --- the #344 review, round 2 ------------------------------------------------------------------


def test_query_interface_succeeding_with_no_interface_is_a_failed_read():
    calls = _Calls()
    plugin, _keep = _fake_plugin(calls, interface=False, query_status=0)
    assert child.read_smart(plugin) == {"status": "error", "error": "smart_read_failed"}
    assert calls == ["plugin.QueryInterface", "plugin.Stop", "plugin.Release"]


def test_an_open_that_succeeds_with_no_plugin_is_a_failed_read():
    calls = []

    def create():
        calls.append(0)
        return 0, c_void_p()

    assert child.open_plugin(create, sleep=calls.append) == ("smart_read_failed", None)
    assert calls == [0], "not tried again, and never slept on"


def test_exactly_eight_media_still_read():
    media = [f"disk{n}" for n in range(8)]
    registry = FakeRegistry([{"location": "Internal", "media": media, "reading": OK}])
    record = json.loads(child.report(registry)[0])["controllers"][0]
    assert (record["media"], record["status"], registry.reads) == (media, "ok", 1)


class FakeTree(child.IOKitRegistry):
    """The registry walk over a made-up IOService plane: no IOKit is loaded."""

    def __init__(self, tree, media, invalid=()):
        self.tree, self.media, self.invalid = tree, media, set(invalid)
        self.released: list[object] = []

    def _children(self, entry):
        return list(self.tree.get(entry, ())), entry not in self.invalid

    def _is_media(self, entry):
        return entry in self.media

    def _whole(self, entry):
        return self.media[entry][0] == "whole"

    def _bsd_name(self, entry):
        return self.media[entry][1]

    def _release(self, entry):
        self.released.append(entry)


# This M5's plane below its controller: the namespace, then the whole disk, whose
# partitions and APFS containers lie below it and are never walked.
M5_TREE = {"controller": ["namespace"], "namespace": ["disk0"], "disk0": ["disk0s1"]}
M5_MEDIA = {"disk0": ("whole", "disk0"), "disk0s1": ("part", "disk0s1")}


def test_the_walk_finds_the_whole_disks_at_the_first_media_level():
    registry = FakeTree(M5_TREE, M5_MEDIA)
    assert registry.whole_media("controller") == ["disk0"]
    assert sorted(registry.released) == ["disk0", "namespace"], "each child is given back"


def test_a_listing_iokit_invalidated_mid_walk_fails_the_record_closed():
    registry = FakeTree(M5_TREE, M5_MEDIA, invalid={"namespace"})
    assert registry.whole_media("controller") == ["disk0", None]


def test_a_branch_deeper_than_the_walk_goes_fails_the_record_closed():
    tree = {f"level{n}": [f"level{n + 1}"] for n in range(9)}
    registry = FakeTree(tree, {})
    assert registry.whole_media("level0") == [None]
    shallow = {f"level{n}": [f"level{n + 1}"] for n in range(8)}
    tree = {**shallow, "level8": ["disk0"]}
    assert FakeTree(tree, {"disk0": ("whole", "disk0")}).whole_media("level0") == ["disk0"]


def test_a_part_that_is_not_whole_is_not_counted():
    registry = FakeTree({"controller": ["disk0s1"]}, {"disk0s1": ("part", "disk0s1")})
    assert registry.whole_media("controller") == []


def _clients_of_this_process() -> bool:
    listing = subprocess.run(  # noqa: S603 - a fixed read-only listing, never the product
        ["/usr/sbin/ioreg", "-r", "-c", "AppleNVMeSMARTUserClient", "-a"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return f"pid {os.getpid()}," in listing


@LIVE
def test_a_read_leaves_no_smart_client_open():
    # IODestroyPlugInInterface is Stop then Release; without Stop the client stays open
    # until the process exits, and a second reader finds it busy.
    if _virtual():
        pytest.skip("a virtual Mac has no SMART service to read")
    registry = child.IOKitRegistry()
    try:
        (startup,) = [s for s in registry.services() if "disk0" in registry.whole_media(s)]
        for _ in range(3):
            reading = registry.read(startup)
            if reading["status"] == "ok":
                break
            time.sleep(1)
        assert reading["status"] == "ok"
        assert not _clients_of_this_process()
    finally:
        registry.close()


# --- found by the review of #347: ctypes' own call to uname ------------------------------------

_UNAME_SPY = (
    "import atexit, os, sys\n"
    "calls = []\n"
    "def spy(*args):\n"
    "    calls.append(1)\n"
    "    raise PermissionError('uname was called')\n"
    "os.uname = spy\n"
    "sys.platform = 'darwin'\n"
    "atexit.register(lambda: sys.stderr.write(f'UNAME {len(calls)}\\n'))\n"
    "import runpy\n"
    "runpy.run_module('voltry_mac.smart_iokit', run_name='__main__')\n"
)


def test_the_child_never_calls_uname():
    # On macOS, ctypes' own __init__ calls os.uname(), whose result carries the host name
    # the spec never reads, and which fails where a sandbox denies it. The spy raises as
    # that failure does; the child still runs to its own exit status. sys.platform is set
    # to darwin so Linux CI takes ctypes' Darwin branch too.
    process = subprocess.run(  # noqa: S603 - a test-owned child
        [sys.executable, "-c", _UNAME_SPY], capture_output=True, text=True, timeout=60
    )
    assert "Traceback" not in process.stderr, process.stderr
    assert process.stderr.rstrip().endswith("UNAME 0")
    assert process.returncode in (child.EXIT_READ, child.EXIT_NONE_READ, child.EXIT_ENUMERATION)


def test_the_swap_puts_the_real_uname_back_after_a_body_that_succeeds():
    import posix

    with child._uname_swapped_out():
        pass
    assert os.uname is posix.uname


def test_what_ctypes_sees_of_uname_is_a_release_and_no_host_name(monkeypatch):
    # In-process ctypes is already loaded, so the swap is checked directly: during it,
    # os.uname answers a release past Darwin 7 with no host name; after it, even when the
    # import fails, os.uname is the real function again.
    real = os.uname
    seen = []
    monkeypatch.setitem(sys.modules, "ctypes", None)

    def spy_import() -> None:
        with child._uname_swapped_out():
            answer = os.uname()
            seen.append((int(answer.release.split(".")[0]), hasattr(answer, "nodename")))
            import ctypes  # noqa: F401 - blocked above, so this raises

    with pytest.raises(ImportError):
        spy_import()
    assert seen == [(24, False)]
    assert os.uname is real
