"""The SMART log decode (docs/VOLTRY_MAC_SPEC.md, the C28 layout table, pinned to
NVMeSMARTLibExternal.h in the MacOSX26.5 SDK and to the NVM Express SMART / Health
Information log page, and Test strategy part 1's "SMART decoding goldens").

Every multi-byte field is little-endian; every 128-bit counter is two 64-bit words, low
word first; the struct is packed. The parent decodes with the table and never with ctypes;
the child's ctypes struct must agree with the same table.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from voltry_mac import numbers, smart

M5_LOG = Path(__file__).resolve().parent / "fixtures" / "smart" / "m5-laptop-2026-09-26.hex"

LAYOUT = {
    "critical_warning": (0, 1),
    "composite_temperature": (1, 2),
    "available_spare": (3, 1),
    "available_spare_threshold": (4, 1),
    "percentage_used": (5, 1),
    "data_units_read": (32, 16),
    "data_units_written": (48, 16),
    "host_read_commands": (64, 16),
    "host_write_commands": (80, 16),
    "controller_busy_time": (96, 16),
    "power_cycles": (112, 16),
    "power_on_hours": (128, 16),
    "unsafe_shutdowns": (144, 16),
    "media_errors": (160, 16),
    "error_log_entries": (176, 16),
}


def test_the_layout_is_the_headers():
    assert smart.LOG_SIZE == 512
    assert dict(smart.LAYOUT) == LAYOUT


def test_the_childs_struct_agrees_with_the_layout():
    # The child is the only module that may use ctypes; importing it loads no framework.
    import ctypes

    from voltry_mac import smart_iokit

    assert ctypes.sizeof(smart_iokit.NVMeSMARTData) == 512
    names = {
        "critical_warning": "CRITICAL_WARNING",
        "composite_temperature": "TEMPERATURE",
        "available_spare": "AVAILABLE_SPARE",
        "available_spare_threshold": "AVAILABLE_SPARE_THRESHOLD",
        "percentage_used": "PERCENTAGE_USED",
        "data_units_read": "DATA_UNITS_READ",
        "data_units_written": "DATA_UNITS_WRITTEN",
        "host_read_commands": "HOST_READ_COMMANDS",
        "host_write_commands": "HOST_WRITE_COMMANDS",
        "controller_busy_time": "CONTROLLER_BUSY_TIME",
        "power_cycles": "POWER_CYCLES",
        "power_on_hours": "POWER_ON_HOURS",
        "unsafe_shutdowns": "UNSAFE_SHUTDOWNS",
        "media_errors": "MEDIA_ERRORS",
        "error_log_entries": "NUM_ERROR_INFO_LOG_ENTRIES",
    }
    for field, (offset, size) in LAYOUT.items():
        member = getattr(smart_iokit.NVMeSMARTData, names[field])
        assert (member.offset, member.size) == (offset, size), field


def _log(**fields: int) -> bytes:
    raw = bytearray(512)
    for field, value in fields.items():
        offset, size = LAYOUT[field]
        raw[offset : offset + size] = value.to_bytes(size, "little")
    return bytes(raw)


HIGH = 1 << 64


def test_a_distinct_value_at_every_field_decodes_exactly():
    raw = bytearray(
        _log(
            critical_warning=0b0001_0101,
            composite_temperature=325,
            available_spare=7,
            available_spare_threshold=10,
            percentage_used=150,
            data_units_read=HIGH * 2 + 1,
            data_units_written=HIGH * 3 + 2,
            host_read_commands=HIGH * 4 + 3,
            host_write_commands=HIGH * 5 + 4,
            controller_busy_time=HIGH * 6 + 5,
            power_cycles=HIGH * 7 + 6,
            power_on_hours=HIGH * 8 + 7,
            unsafe_shutdowns=HIGH * 9 + 8,
            media_errors=HIGH * 10 + 9,
            error_log_entries=HIGH * 11 + 10,
        )
    )
    raw[6:32] = b"\xaa" * 26  # reserved: ignored
    raw[192:512] = b"\xbb" * 320  # reserved in the SDK header: ignored
    assert smart.decode(bytes(raw)) == {
        "critical_warning_byte": 0b0001_0101,
        "spare_below_threshold": True,
        "temperature_warning": False,
        "reliability_degraded": True,
        "read_only_mode": False,
        "volatile_backup_failed": True,
        "unknown_warning_bits": False,
        "composite_temperature_k": 325,
        "available_spare_percent": 7,
        "available_spare_threshold_percent": 10,
        "percentage_used": 150,
        "data_units_read": str(HIGH * 2 + 1),
        "data_units_written": str(HIGH * 3 + 2),
        "power_cycles": str(HIGH * 7 + 6),
        "power_on_hours": str(HIGH * 8 + 7),
        "unsafe_shutdowns": str(HIGH * 9 + 8),
        "media_errors": str(HIGH * 10 + 9),
        "error_log_entries": str(HIGH * 11 + 10),
    }


def test_the_m5_log_decodes_to_the_spikes_values():
    raw = bytes.fromhex(M5_LOG.read_text().strip())
    assert smart.decode(raw) == {
        "critical_warning_byte": 0,
        "spare_below_threshold": False,
        "temperature_warning": False,
        "reliability_degraded": False,
        "read_only_mode": False,
        "volatile_backup_failed": False,
        "unknown_warning_bits": False,
        "composite_temperature_k": 330,
        "available_spare_percent": 100,
        "available_spare_threshold_percent": 99,
        "percentage_used": 1,
        "data_units_read": "45102746",
        "data_units_written": "28928900",
        "power_cycles": "152",
        "power_on_hours": "454",
        "unsafe_shutdowns": "5",
        "media_errors": "0",
        "error_log_entries": "0",
    }


@pytest.mark.parametrize(("kelvin", "read"), [(249, False), (250, True), (400, True), (401, False)])
def test_a_temperature_outside_250_to_400_kelvin_fails_closed(kelvin, read):
    decoded = smart.decode(_log(composite_temperature=kelvin))
    assert decoded["composite_temperature_k"] == (kelvin if read else smart.UNREAD)


@pytest.mark.parametrize("field", ["available_spare", "available_spare_threshold"])
def test_a_spare_above_100_percent_fails_closed(field):
    key = f"{field}_percent"
    assert smart.decode(_log(**{field: 100}))[key] == 100
    assert smart.decode(_log(**{field: 101}))[key] is smart.UNREAD


def test_percentage_used_may_exceed_100_as_the_standard_allows():
    assert smart.decode(_log(percentage_used=255))["percentage_used"] == 255


@pytest.mark.parametrize("byte", [0x20, 0x40, 0x80, 0xE0, 0x3F])
def test_an_unknown_warning_bit_is_never_ignored(byte):
    decoded = smart.decode(_log(critical_warning=byte))
    assert decoded["critical_warning_byte"] == byte
    assert decoded["unknown_warning_bits"] is True
    assert decoded["spare_below_threshold"] is bool(byte & 1)


def test_a_counter_at_its_cap_round_trips_as_a_digit_string():
    top = (1 << 128) - 1
    decoded = smart.decode(_log(data_units_written=top))
    assert decoded["data_units_written"] == str(top)
    assert numbers.is_u128(decoded["data_units_written"])
    assert numbers.is_bytes128(str(numbers.data_units_to_bytes(top)))


@pytest.mark.parametrize("size", [0, 511, 513, 1024])
def test_a_log_of_another_size_is_refused(size):
    with pytest.raises(ValueError):
        smart.decode(bytes(size))


@pytest.mark.parametrize("bit", range(8))
def test_each_warning_bit_is_its_own_flag(bit):
    decoded = smart.decode(_log(critical_warning=1 << bit))
    flags = {
        0: "spare_below_threshold",
        1: "temperature_warning",
        2: "reliability_degraded",
        3: "read_only_mode",
        4: "volatile_backup_failed",
    }
    for position, flag in flags.items():
        assert decoded[flag] is (position == bit), flag
    assert decoded["unknown_warning_bits"] is (bit >= 5)
