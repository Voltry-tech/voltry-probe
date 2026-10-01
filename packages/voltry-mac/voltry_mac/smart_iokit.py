"""The SMART child (C28), run isolated and writing no compiled file as
``<the running interpreter> -I -B -m voltry_mac.smart_iokit``; with the preflight, the only
module that may use ctypes.

docs/VOLTRY_MAC_SPEC.md, the C28 contract. The child takes no input and refuses any
argument. It finds every IORegistry service carrying the "NVMe SMART Capable" property
(at most 8), lists the whole-disk media at the first IOMedia level below each (so APFS's
synthesized container disks are not counted), opens the SMART user client and calls
SMARTReadData once per controller. It prints one ASCII JSON document, at most 64 KiB:

    {"schema": "voltry-mac-smart/0",
     "controllers": [{"location": ..., "media": [...], "status": "ok", "smart_hex": ...}]}

Exit 0 when a controller read, 2 when none did or none exists, 3 with no controllers when
enumeration itself failed. The plug-in's QueryInterface obtains the SMART interface, and
of that interface only SMARTReadData and the Release that gives it back are bound as
callables; of the plug-in, besides QueryInterface, only the Stop and Release that
IODestroyPlugInInterface makes, which close the SMART user client and give the plug-in
back. Every other slot, the identify call that carries the drive's serial included, is an
opaque pointer this module cannot call. Importing it loads no framework, so its structs
are checked on any platform.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import sys
import time
from collections.abc import Callable, Iterator, Sequence
from typing import Final, Protocol, cast


class _NoHostName:
    """All that ctypes reads of uname on macOS: a release past Darwin 7. No host name."""

    release = "24.0.0"


def _no_host_name() -> _NoHostName:
    return _NoHostName()


@contextlib.contextmanager
def _uname_swapped_out() -> Iterator[None]:
    """os.uname set aside while ctypes is imported. On macOS, ctypes' own __init__ calls it
    to choose a dlopen mode for Darwin 7 and older; uname(3) also returns the host name,
    which the spec never reads, and it fails where a sandbox denies that name. The real
    function is put back, and never called here."""
    real = os.uname
    setattr(os, "uname", _no_host_name)  # noqa: B010 - set aside, not called
    try:
        yield
    finally:
        setattr(os, "uname", real)  # noqa: B010


with _uname_swapped_out():
    import ctypes  # noqa: E402 - imported only with os.uname set aside
    from ctypes import (  # noqa: E402
        CFUNCTYPE,
        POINTER,
        Structure,
        byref,
        c_bool,
        c_char_p,
        c_int32,
        c_long,
        c_uint8,
        c_uint16,
        c_uint32,
        c_uint64,
        c_void_p,
        create_string_buffer,
    )

SCHEMA: Final = "voltry-mac-smart/0"
MAX_CONTROLLERS: Final = 8
MAX_MEDIA: Final = 8
EXIT_READ: Final = 0
EXIT_NONE_READ: Final = 2
EXIT_ENUMERATION: Final = 3
EXIT_USAGE: Final = 64
_MEDIUM: Final = re.compile(r"disk[0-9]{1,3}", re.ASCII)
_LOCATIONS: Final = frozenset({"Internal", "External"})


def _signed(value: int) -> int:
    """An IOReturn or HRESULT, as the signed 32-bit integer ctypes hands back."""
    return value - (1 << 32) if value & (1 << 31) else value


# IOKit's returns (IOReturn.h) and COM's E_NOINTERFACE: only the first and the last mean the
# controller offers no SMART interface; another client holding it is only busy for a while.
# IOCreatePlugInInterfaceForService reports a held client as NoResources (no candidate
# plug-in started, observed as 0xE00002BE); Busy and ExclusiveAccess are kept in the set
# in case another macOS reports it their way.
IO_RETURN_UNSUPPORTED: Final = _signed(0xE00002C7)
IO_RETURN_BUSY: Final = _signed(0xE00002D5)
IO_RETURN_NO_RESOURCES: Final = _signed(0xE00002BE)
IO_RETURN_EXCLUSIVE_ACCESS: Final = _signed(0xE00002C5)
E_NOINTERFACE: Final = _signed(0x80000004)
_BUSY: Final = frozenset({IO_RETURN_BUSY, IO_RETURN_NO_RESOURCES, IO_RETURN_EXCLUSIVE_ACCESS})
# The waits before the second and third attempt to open a busy client, well inside C28's
# 15 s deadline. SMARTReadData itself is still called once.
_BUSY_WAITS: Final = (0.25, 0.5)

# kIONVMeSMARTUserClientTypeID and kIONVMeSMARTInterfaceID (NVMeSMARTLibExternal.h), and
# kIOCFPlugInInterfaceID (IOCFPlugIn.h), as their 16 bytes.
SMART_USER_CLIENT_ID: Final = bytes.fromhex("AA0FA6F9C2D6457FB10B59A13253292F")
SMART_INTERFACE_ID: Final = bytes.fromhex("CCD1DB19FD9A4DAFBF9512454B230AB6")
CF_PLUGIN_INTERFACE_ID: Final = bytes.fromhex("C244E858109C11D491D40050E4C6426F")


class NVMeSMARTData(Structure):
    """The NVM Express SMART / Health Information log page (02h), 512 bytes, packed."""

    _pack_ = 1
    _layout_ = "ms"  # what _pack_ has always meant; Python 3.14 asks for it to be stated
    _fields_ = [
        ("CRITICAL_WARNING", c_uint8),
        ("TEMPERATURE", c_uint16),
        ("AVAILABLE_SPARE", c_uint8),
        ("AVAILABLE_SPARE_THRESHOLD", c_uint8),
        ("PERCENTAGE_USED", c_uint8),
        ("RESERVED1", c_uint8 * 26),
        ("DATA_UNITS_READ", c_uint64 * 2),
        ("DATA_UNITS_WRITTEN", c_uint64 * 2),
        ("HOST_READ_COMMANDS", c_uint64 * 2),
        ("HOST_WRITE_COMMANDS", c_uint64 * 2),
        ("CONTROLLER_BUSY_TIME", c_uint64 * 2),
        ("POWER_CYCLES", c_uint64 * 2),
        ("POWER_ON_HOURS", c_uint64 * 2),
        ("UNSAFE_SHUTDOWNS", c_uint64 * 2),
        ("MEDIA_ERRORS", c_uint64 * 2),
        ("NUM_ERROR_INFO_LOG_ENTRIES", c_uint64 * 2),
        ("RESERVED2", c_uint8 * 320),
    ]


class CFUUIDBytes(Structure):
    _fields_ = [("bytes", c_uint8 * 16)]


def _uuid_bytes(value: bytes) -> CFUUIDBytes:
    return CFUUIDBytes((c_uint8 * 16)(*value))


QueryInterfaceFn = CFUNCTYPE(c_int32, c_void_p, CFUUIDBytes, POINTER(c_void_p))
ReleaseFn = CFUNCTYPE(c_uint32, c_void_p)
StopFn = CFUNCTYPE(c_int32, c_void_p)
SMARTReadDataFn = CFUNCTYPE(c_int32, c_void_p, POINTER(NVMeSMARTData))


class PlugInVtbl(Structure):
    """IOCFPlugInInterface (IOCFPlugIn.h). AddRef, Probe and Start are never called."""

    _fields_ = [
        ("_reserved", c_void_p),
        ("QueryInterface", QueryInterfaceFn),
        ("AddRef", c_void_p),
        ("Release", ReleaseFn),
        ("version", c_uint16),
        ("revision", c_uint16),
        ("Probe", c_void_p),
        ("Start", c_void_p),
        ("Stop", StopFn),
    ]


class SMARTVtbl(Structure):
    """IONVMeSMARTInterface, natural alignment. Only SMARTReadData and Release are callable."""

    _fields_ = [
        ("_reserved", c_void_p),
        ("QueryInterface", c_void_p),
        ("AddRef", c_void_p),
        ("Release", ReleaseFn),
        ("version", c_uint16),
        ("revision", c_uint16),
        ("SMARTReadData", SMARTReadDataFn),
        ("GetIdentifyData", c_void_p),
        ("reserved0", c_uint64),
        ("reserved1", c_uint64),
        ("GetLogPage", c_void_p),
    ]


def _vtable(interface: c_void_p, layout: type[Structure]) -> Structure:
    """The vtable a COM interface pointer points to, read through ``layout``."""
    return ctypes.cast(ctypes.cast(interface, POINTER(c_void_p))[0], POINTER(layout)).contents


def read_smart(plugin: c_void_p) -> dict[str, str]:
    """One controller's SMART log through its plug-in: QueryInterface, SMARTReadData, and
    the plug-in's Stop and Release, which IODestroyPlugInInterface makes, so the SMART user
    client is closed at once rather than when the process exits."""
    plugin_vtbl = _vtable(plugin, PlugInVtbl)
    smart = c_void_p()
    try:
        found = plugin_vtbl.QueryInterface(plugin, _uuid_bytes(SMART_INTERFACE_ID), byref(smart))
        if found == E_NOINTERFACE:
            return {"status": "error", "error": "interface_unavailable"}
        if found != 0 or not smart.value:
            return {"status": "error", "error": "smart_read_failed"}
        vtbl = _vtable(smart, SMARTVtbl)
        data = NVMeSMARTData()
        try:
            status = vtbl.SMARTReadData(smart, byref(data))
        finally:
            vtbl.Release(smart)
        if status != 0:
            return {"status": "error", "error": "smart_read_failed"}
        return {"status": "ok", "smart_hex": bytes(data).hex()}
    finally:
        try:
            plugin_vtbl.Stop(plugin)
        finally:
            plugin_vtbl.Release(plugin)


def open_outcome(status: int) -> str:
    """What an IOCreatePlugInInterfaceForService status means for the record."""
    if status == 0:
        return "ok"
    if status == IO_RETURN_UNSUPPORTED:
        return "interface_unavailable"
    return "busy" if status in _BUSY else "smart_read_failed"


def open_plugin(
    create: Callable[[], tuple[int, c_void_p]], sleep: Callable[[float], object] = time.sleep
) -> tuple[str, c_void_p | None]:
    """Open the controller's plug-in, trying a busy one again a few times."""
    waits = iter(_BUSY_WAITS)
    while True:
        status, plugin = create()
        outcome = open_outcome(status)
        if outcome == "ok" and plugin.value:
            return "ok", plugin
        wait = next(waits, None)
        if outcome != "busy" or wait is None:
            return ("smart_read_failed" if outcome in ("ok", "busy") else outcome), None
        sleep(wait)


class EnumerationFailed(Exception):
    """IOKit could not list the NVMe controllers at all."""


class Registry(Protocol):
    def services(self) -> Sequence[object]: ...
    def location(self, service: object) -> str: ...
    def whole_media(self, service: object) -> Sequence[str | None]: ...
    def read(self, service: object) -> dict[str, str]: ...


def document(controllers: list[dict[str, object]]) -> str:
    return json.dumps({"schema": SCHEMA, "controllers": controllers}, ensure_ascii=True) + "\n"


def report(registry: Registry) -> tuple[str, int]:
    """The contract's document and exit status, for whatever the registry lists."""
    try:
        services = list(registry.services())[:MAX_CONTROLLERS]
    except EnumerationFailed:
        return document([]), EXIT_ENUMERATION
    controllers: list[dict[str, object]] = []
    for service in services:
        location = registry.location(service)
        names = list(registry.whole_media(service))
        media = [name for name in names if name is not None and _MEDIUM.fullmatch(name)]
        # A whole disk the child cannot name, or more than it may list, would make the
        # controller look like it carries fewer disks than it does: the record fails closed.
        whole = len(media) == len(names) and len(media) <= MAX_MEDIA
        controllers.append(
            {
                "location": location if location in _LOCATIONS else "Unknown",
                "media": media[:MAX_MEDIA],
                **(
                    registry.read(service)
                    if whole
                    else {"status": "error", "error": "smart_read_failed"}
                ),
            }
        )
    read = any(controller["status"] == "ok" for controller in controllers)
    return document(controllers), EXIT_READ if read else EXIT_NONE_READ


# --- IOKit, loaded only when the child runs ----------------------------------------------------

_UTF8: Final = 0x08000100
# How far below a controller the walk goes before it stops looking for its whole disks.
_MAX_DEPTH: Final = 8


class IOKitRegistry:
    """The real registry: IOKit and CoreFoundation through ctypes, macOS only."""

    def __init__(self) -> None:
        self._iokit = ctypes.CDLL("/System/Library/Frameworks/IOKit.framework/IOKit")
        self._cf = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
        self._bind()
        self._owned: list[int] = []

    def _bind(self) -> None:
        cf, io = self._cf, self._iokit
        cf.CFStringCreateWithCString.restype = c_void_p
        cf.CFStringCreateWithCString.argtypes = [c_void_p, c_char_p, c_uint32]
        cf.CFStringGetCString.restype = c_bool
        cf.CFStringGetCString.argtypes = [c_void_p, c_char_p, c_long, c_uint32]
        cf.CFGetTypeID.restype = c_long
        cf.CFGetTypeID.argtypes = [c_void_p]
        cf.CFStringGetTypeID.restype = c_long
        cf.CFBooleanGetTypeID.restype = c_long
        cf.CFDictionaryGetTypeID.restype = c_long
        cf.CFBooleanGetValue.restype = c_bool
        cf.CFBooleanGetValue.argtypes = [c_void_p]
        cf.CFDictionaryGetValue.restype = c_void_p
        cf.CFDictionaryGetValue.argtypes = [c_void_p, c_void_p]
        cf.CFDictionaryCreateMutable.restype = c_void_p
        cf.CFDictionaryCreateMutable.argtypes = [c_void_p, c_long, c_void_p, c_void_p]
        cf.CFDictionarySetValue.restype = None
        cf.CFDictionarySetValue.argtypes = [c_void_p, c_void_p, c_void_p]
        cf.CFUUIDGetConstantUUIDWithBytes.restype = c_void_p
        cf.CFUUIDGetConstantUUIDWithBytes.argtypes = [c_void_p] + [c_uint8] * 16
        cf.CFRelease.restype = None
        cf.CFRelease.argtypes = [c_void_p]
        io.IOServiceGetMatchingServices.restype = c_int32
        io.IOServiceGetMatchingServices.argtypes = [c_uint32, c_void_p, POINTER(c_uint32)]
        io.IOIteratorNext.restype = c_uint32
        io.IOIteratorNext.argtypes = [c_uint32]
        io.IOIteratorIsValid.restype = c_int32
        io.IOIteratorIsValid.argtypes = [c_uint32]
        io.IOObjectRelease.restype = c_int32
        io.IOObjectRelease.argtypes = [c_uint32]
        io.IOObjectConformsTo.restype = c_bool
        io.IOObjectConformsTo.argtypes = [c_uint32, c_char_p]
        io.IORegistryEntryGetChildIterator.restype = c_int32
        io.IORegistryEntryGetChildIterator.argtypes = [c_uint32, c_char_p, POINTER(c_uint32)]
        io.IORegistryEntryCreateCFProperty.restype = c_void_p
        io.IORegistryEntryCreateCFProperty.argtypes = [c_uint32, c_void_p, c_void_p, c_uint32]
        io.IOCreatePlugInInterfaceForService.restype = c_int32
        io.IOCreatePlugInInterfaceForService.argtypes = [
            c_uint32,
            c_void_p,
            c_void_p,
            POINTER(c_void_p),
            POINTER(c_int32),
        ]

    def _string(self, text: str) -> int:
        return cast(int, self._cf.CFStringCreateWithCString(None, text.encode("ascii"), _UTF8))

    def _property(self, entry: int, key: str) -> int | None:
        name = self._string(key)
        try:
            return self._iokit.IORegistryEntryCreateCFProperty(entry, name, None, 0) or None
        finally:
            self._cf.CFRelease(name)

    def _text(self, ref: int | None) -> str | None:
        if not ref or self._cf.CFGetTypeID(ref) != self._cf.CFStringGetTypeID():
            return None
        buffer = create_string_buffer(256)
        return (
            buffer.value.decode("utf-8", "replace")
            if self._cf.CFStringGetCString(ref, buffer, 256, _UTF8)
            else None
        )

    def services(self) -> list[int]:
        cf = self._cf
        # The addresses of CoreFoundation's two callback structs, as the C API takes them.
        keys = ctypes.addressof(c_uint8.in_dll(cf, "kCFTypeDictionaryKeyCallBacks"))
        values = ctypes.addressof(c_uint8.in_dll(cf, "kCFTypeDictionaryValueCallBacks"))
        matching = cf.CFDictionaryCreateMutable(None, 0, keys, values)
        wanted = cf.CFDictionaryCreateMutable(None, 0, keys, values)
        capable = self._string("NVMe SMART Capable")
        match_key = self._string("IOPropertyMatch")
        cf.CFDictionarySetValue(wanted, capable, c_void_p.in_dll(cf, "kCFBooleanTrue"))
        cf.CFDictionarySetValue(matching, match_key, wanted)
        cf.CFRelease(wanted)
        cf.CFRelease(capable)
        cf.CFRelease(match_key)
        iterator = c_uint32(0)
        # IOServiceGetMatchingServices consumes one reference to the matching dictionary.
        if self._iokit.IOServiceGetMatchingServices(0, matching, byref(iterator)) != 0:
            raise EnumerationFailed
        found: list[int] = []
        while len(found) < MAX_CONTROLLERS:
            service = self._iokit.IOIteratorNext(iterator)
            if not service:
                break
            found.append(service)
        self._iokit.IOObjectRelease(iterator)
        self._owned.extend(found)
        return found

    def location(self, service: object) -> str:
        """Physical Interconnect Location from Protocol Characteristics, or Unknown. The
        drive's other characteristics dictionary carries its serial and is never read."""
        assert isinstance(service, int)  # noqa: S101 - an io_service_t from services()
        characteristics = self._property(service, "Protocol Characteristics")
        if characteristics is None:
            return "Unknown"
        try:
            if self._cf.CFGetTypeID(characteristics) != self._cf.CFDictionaryGetTypeID():
                return "Unknown"
            name = self._string("Physical Interconnect Location")
            try:
                value = self._text(self._cf.CFDictionaryGetValue(characteristics, name))
            finally:
                self._cf.CFRelease(name)
            return value or "Unknown"
        finally:
            self._cf.CFRelease(characteristics)

    def whole_media(self, service: object, depth: int = 0) -> list[str | None]:
        """BSD names of the whole IOMedia at the first IOMedia level below ``service``.

        None stands for a whole disk with no name yet, and for anything the walk could not
        see: a listing IOKit could not make or invalidated mid-walk, or a branch deeper than
        the walk goes. Each makes the record fail closed rather than undercount.
        """
        found: list[str | None] = []
        children, complete = self._children(service)
        for child in children:
            try:
                if self._is_media(child):
                    if self._whole(child):
                        found.append(self._bsd_name(child))
                elif depth < _MAX_DEPTH:
                    found.extend(self.whole_media(child, depth + 1))
                else:
                    found.append(None)
            finally:
                self._release(child)
        if not complete:
            found.append(None)
        return found

    def _children(self, entry: object) -> tuple[list[object], bool]:
        """The entry's children in the IOService plane, and whether the listing held."""
        assert isinstance(entry, int)  # noqa: S101 - an io_registry_entry_t
        io = self._iokit
        iterator = c_uint32(0)
        if io.IORegistryEntryGetChildIterator(entry, b"IOService", byref(iterator)) != 0:
            return [], False
        children: list[object] = []
        while True:
            child = io.IOIteratorNext(iterator)
            if not child:
                break
            children.append(child)
        complete = bool(io.IOIteratorIsValid(iterator))
        io.IOObjectRelease(iterator)
        return children, complete

    def _is_media(self, entry: object) -> bool:
        return bool(self._iokit.IOObjectConformsTo(entry, b"IOMedia"))

    def _whole(self, entry: object) -> bool:
        assert isinstance(entry, int)  # noqa: S101 - an io_registry_entry_t
        whole = self._property(entry, "Whole")
        if whole is None:
            return False
        try:
            cf = self._cf
            return cf.CFGetTypeID(whole) == cf.CFBooleanGetTypeID() and bool(
                cf.CFBooleanGetValue(whole)
            )
        finally:
            self._cf.CFRelease(whole)

    def _bsd_name(self, entry: object) -> str | None:
        assert isinstance(entry, int)  # noqa: S101 - an io_registry_entry_t
        bsd = self._property(entry, "BSD Name")
        try:
            return self._text(bsd)
        finally:
            if bsd is not None:
                self._cf.CFRelease(bsd)

    def _release(self, entry: object) -> None:
        self._iokit.IOObjectRelease(entry)

    def read(self, service: object) -> dict[str, str]:
        assert isinstance(service, int)  # noqa: S101 - an io_service_t from services()
        cf = self._cf
        user_client = cf.CFUUIDGetConstantUUIDWithBytes(None, *SMART_USER_CLIENT_ID)
        plugin_type = cf.CFUUIDGetConstantUUIDWithBytes(None, *CF_PLUGIN_INTERFACE_ID)

        def create() -> tuple[int, c_void_p]:
            plugin = c_void_p()
            score = c_int32()
            status = self._iokit.IOCreatePlugInInterfaceForService(
                service, user_client, plugin_type, byref(plugin), byref(score)
            )
            return int(status), plugin

        outcome, opened = open_plugin(create)
        if opened is None:
            return {"status": "error", "error": outcome}
        return read_smart(opened)

    def close(self) -> None:
        for service in self._owned:
            self._iokit.IOObjectRelease(service)
        self._owned.clear()


def main(
    argv: Sequence[str] | None = None, registry_type: Callable[[], Registry] | None = None
) -> int:
    """Print the contract's document; refuse any argument."""
    if list(sys.argv[1:] if argv is None else argv):
        return EXIT_USAGE
    try:
        registry = (registry_type or IOKitRegistry)()
    except (OSError, AttributeError, ValueError):  # IOKit or CoreFoundation would not load
        sys.stdout.write(document([]))
        return EXIT_ENUMERATION
    try:
        text, code = report(registry)
    finally:
        close = getattr(registry, "close", None)
        if close is not None:
            close()
    sys.stdout.write(text)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
