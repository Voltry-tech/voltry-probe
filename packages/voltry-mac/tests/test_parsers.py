"""The user-read parsers, C1 to C9 and C11 to C27 (docs/VOLTRY_MAC_SPEC.md, Test strategy
part 1: "Each parser: fixture in, expected value out; an unexpected shape gives unavailable
with source_changed; a test injects identifier-looking keys and asserts they never reach
the model").

The fixtures under fixtures/commands/m5-laptop are the M5's own output, captured through
the chokepoint by tools/voltry_mac_capture.py with every identifier replaced. A parser
returns only the fields the registry keeps; a field the source omitted or garbled comes
back as UNREAD, and output that is not the command's shape at all raises SourceChanged.
"""

from __future__ import annotations

import json
import plistlib
import re
from pathlib import Path

import pytest

from voltry_mac import parsers as p

M5 = Path(__file__).resolve().parent / "fixtures" / "commands" / "m5-laptop"
CANARY = "CANARY-7f3a9"


def m5(command_id: str) -> str:
    return (M5 / f"{command_id}.out").read_text(encoding="utf-8")


def _json(document: object) -> str:
    return json.dumps(document, indent=2, separators=(",", " : ")) + "\n"


# --- the M5, fixture in and expected value out ------------------------------------------------


def test_the_parsers_cover_the_26_user_reads():
    assert sorted(p.PARSERS, key=lambda cid: int(cid[1:])) == [
        *(f"C{n}" for n in range(1, 10)),
        *(f"C{n}" for n in range(11, 28)),
    ]


def test_c1_os_version():
    assert p.os_version(m5("C1")) == {
        "product_name": "macOS",
        "product_version": "26.6.2",
        "build_version": "25G83",
    }


def test_c2_hardware_overview_and_firmware():
    assert p.hardware(m5("C2")) == {
        "machine_name": "MacBook Pro",
        "machine_model": "Mac17,2",
        "model_number": "MDE34LL/A",
        "chip_type": "Apple M5",
        "physical_memory_text": "24 GB",
        "serial_number": "C02XK1ZQK7Q2",
        "activation_lock_enabled": True,
        "boot_rom_version": "18000.161.10",
        "os_loader_version": "18000.161.10",
    }


def test_c3_nvme_devices():
    assert p.nvme(m5("C3")) == {
        "entry_count": 1,
        "entries": (
            {
                "bsd_name": "disk0",
                "device_model": "APPLE SSD AP1024Z",
                "device_revision": "2973.120",
                "size_text": "1 TB",
                "size_bytes": 1000555581440,
                "smart_status": "Verified",
                "trim_support": True,
            },
        ),
    }


def test_c4_gpu_configuration():
    assert p.gpu(m5("C4")) == {"core_count": 10, "metal_family": "Metal 4"}


def test_c5_memory_configuration():
    assert p.memory(m5("C5")) == {
        "memory_type": "LPDDR5",
        "manufacturer": "Micron",
        "size_text": "24 GB",
    }


def test_c6_battery_health():
    assert p.battery_health(m5("C6")) == {
        "condition": "Good",
        "maximum_capacity_percent": 99,
        "cycle_count": 58,
        "state_of_charge_percent": 100,
        "fully_charged": True,
        "is_charging": False,
        "charger_connected": False,
        "gauge_device_name": "bq40z651",
        "gauge_firmware_version": "0b00",
        "gauge_hardware_revision": "0100",
    }


def test_c7_battery_gauge():
    assert p.battery_gauge(m5("C7")) == {
        "cycle_count": 58,
        "design_cycle_count": 1000,
        "design_capacity_mah": 6249,
        "full_charge_capacity_mah": 5910,
        "temperature_centi_c": 3029,
        "permanent_failure": False,
    }


def test_c8_thermal_warning_level():
    assert p.thermal(m5("C8")) == {"thermal_warning_recorded": False}


def test_c9_memory_pressure():
    assert p.memory_pressure(m5("C9")) == {"free_percent": 63}


def test_c11_startup_disk():
    assert p.startup_disk(m5("C11")) == {
        "physical_stores": ("disk0s2",),
        "internal": True,
        "solid_state": True,
    }


@pytest.mark.parametrize(
    ("parse", "command_id", "expected"),
    [
        (p.sip, "C12", {"enabled": True}),
        (p.gatekeeper, "C13", {"assessments_enabled": True}),
        (p.filevault, "C14", {"enabled": True}),
        (p.boot_time, "C27", {"boot_epoch_seconds": 1787929257}),
    ],
)
def test_the_status_reads_and_the_boot_time(parse, command_id, expected):
    assert parse(m5(command_id)) == expected


@pytest.mark.parametrize(
    ("command_id", "expected"),
    [
        ("C15", "Mac17,2"),
        ("C16", "J704AP"),
        ("C17", 25769803776),
        ("C18", 10),
        ("C19", "Apple M5"),
        ("C20", True),
        ("C21", 2),
        ("C22", "Super"),
        ("C23", 4),
        ("C24", "Efficiency"),
        ("C25", 6),
        ("C26", False),
    ],
)
def test_each_sysctl_read(command_id, expected):
    assert p.sysctl(command_id, m5(command_id)) == expected


def test_parsers_reach_the_same_values_through_the_table():
    # Each ID is wired to its own parser, not to a neighbour's shape.
    named = {
        "C1": p.os_version,
        "C2": p.hardware,
        "C3": p.nvme,
        "C4": p.gpu,
        "C5": p.memory,
        "C6": p.battery_health,
        "C7": p.battery_gauge,
        "C8": p.thermal,
        "C9": p.memory_pressure,
        "C11": p.startup_disk,
        "C12": p.sip,
        "C13": p.gatekeeper,
        "C14": p.filevault,
        "C27": p.boot_time,
    }
    for command_id, parse in p.PARSERS.items():
        text = m5(command_id)
        expected = named[command_id](text) if command_id in named else p.sysctl(command_id, text)
        assert parse(text) == expected, command_id


# --- shapes the M5 did not show ----------------------------------------------------------------


def test_c8_a_recorded_warning_carries_its_level():
    text = (
        "2026-09-23 14:05:31 -0700 Thermal Warning Level = 70\n"
        "Note: No performance warning level has been recorded\n"
        "Note: No CPU power status has been recorded\n"
    )
    assert p.thermal(text) == {"thermal_warning_recorded": True, "thermal_warning_level": 70}


@pytest.mark.parametrize(
    "text",
    [
        "Error:Failed to get thermal warning level with error code 0xe00002c2\n",
        "Thermal Warning Level = seventy\n",
        "",
    ],
)
def test_c8_anything_else_is_a_changed_source(text):
    with pytest.raises(p.SourceChanged):
        p.thermal(text)


@pytest.mark.parametrize(
    ("parse", "text", "expected"),
    [
        (p.sip, "System Integrity Protection status: disabled.\n", {"enabled": False}),
        (p.gatekeeper, "assessments disabled\n", {"assessments_enabled": False}),
        (p.filevault, "FileVault is Off.\n", {"enabled": False}),
        (
            p.filevault,
            "FileVault is On.\nEncryption in progress: Percent completed = 12.3\n",
            {"enabled": True},
        ),
    ],
)
def test_the_other_states_of_the_status_reads(parse, text, expected):
    assert parse(text) == expected


@pytest.mark.parametrize(
    ("parse", "text"),
    [
        (p.sip, "System Integrity Protection status: unknown (Custom Configuration).\n"),
        (p.sip, ""),
        (p.gatekeeper, "assessments maybe\n"),
        (p.filevault, "FileVault is sort of on.\n"),
        (p.memory_pressure, "System-wide memory free percentage: lots\n"),
        (p.memory_pressure, ""),
        (p.boot_time, "Fri Aug 28 08:00:57 2026\n"),
        (p.os_version, "no keys here\n"),
    ],
)
def test_an_unrecognized_text_is_a_changed_source(parse, text):
    with pytest.raises(p.SourceChanged):
        parse(text)


def test_c1_a_missing_line_is_unread_and_an_extra_one_ignored():
    text = "ProductName:\t\tmacOS\nProductVersion:\t\t26.6.2\nProductVersionExtra:\t(a)\n"
    assert p.os_version(text) == {
        "product_name": "macOS",
        "product_version": "26.6.2",
        "build_version": p.UNREAD,
    }


@pytest.mark.parametrize(
    ("parse", "text"),
    [
        (p.hardware, "not json\n"),
        (p.hardware, _json({"SPSoftwareDataType": []})),
        (p.nvme, "[]\n"),
        (p.gpu, _json({"SPDisplaysDataType": []})),
        (p.memory, _json({"SPMemoryDataType": "24 GB"})),
        (p.battery_health, "{\n"),
        (p.battery_gauge, '<?xml version="1.0"?><plist><dict></plist>'),
        (p.startup_disk, "not a plist\n"),
    ],
)
def test_a_document_that_is_not_the_commands_shape_is_a_changed_source(parse, text):
    with pytest.raises(p.SourceChanged):
        parse(text)


def test_a_missing_or_garbled_field_is_unread_and_the_rest_still_read():
    document = json.loads(m5("C2"))
    entry = document["SPHardwareDataType"][0]
    del entry["chip_type"]
    entry["activation_lock_status"] = "activation_lock_sometimes"
    hardware = p.hardware(_json(document))
    assert hardware["chip_type"] is p.UNREAD and hardware["activation_lock_enabled"] is p.UNREAD
    assert hardware["machine_model"] == "Mac17,2"


def test_a_field_of_the_wrong_type_is_unread():
    document = json.loads(m5("C6"))
    document["SPPowerDataType"][0]["sppower_battery_health_info"][
        "sppower_battery_cycle_count"
    ] = "58"
    assert p.battery_health(_json(document))["cycle_count"] is p.UNREAD
    document = json.loads(m5("C3"))
    document["SPNVMeDataType"][0]["_items"][0]["size_in_bytes"] = "1 TB"
    assert p.nvme(_json(document))["entries"][0]["size_bytes"] is p.UNREAD


def test_c3_every_entry_is_kept_in_order():
    document = json.loads(m5("C3"))
    items = document["SPNVMeDataType"][0]["_items"]
    second = dict(items[0], bsd_name="disk4", device_model="Other SSD")
    items.append(second)
    parsed = p.nvme(_json(document))
    assert parsed["entry_count"] == 2
    assert [entry["bsd_name"] for entry in parsed["entries"]] == ["disk0", "disk4"]


def test_c4_metal_families_and_an_unknown_one():
    document = json.loads(m5("C4"))
    document["SPDisplaysDataType"][0]["spdisplays_mtlgpufamilysupport"] = "spdisplays_metal3"
    assert p.gpu(_json(document))["metal_family"] == "Metal 3"
    document["SPDisplaysDataType"][0][
        "spdisplays_mtlgpufamilysupport"
    ] = "spdisplays_mtlgpufamilymac2"
    assert p.gpu(_json(document))["metal_family"] is p.UNREAD


def test_c6_and_c7_on_a_mac_without_a_battery_are_not_applicable():
    desktop = json.loads(m5("C6"))
    desktop["SPPowerDataType"] = [
        entry for entry in desktop["SPPowerDataType"] if entry["_name"] != "spbattery_information"
    ]
    assert p.battery_health(_json(desktop)) is p.NOT_APPLICABLE
    assert p.battery_gauge("") is p.NOT_APPLICABLE
    assert p.battery_gauge(plistlib.dumps([]).decode()) is p.NOT_APPLICABLE


def test_c7_a_permanent_failure_is_read():
    gauge = plistlib.loads(m5("C7").encode())
    gauge[0]["PermanentFailureStatus"] = 1
    assert p.battery_gauge(plistlib.dumps(gauge).decode())["permanent_failure"] is True


def test_c11_two_stores_are_both_kept():
    disk = plistlib.loads(m5("C11").encode())
    disk["APFSPhysicalStores"].append({"APFSPhysicalStore": "disk1s2"})
    assert p.startup_disk(plistlib.dumps(disk).decode())["physical_stores"] == (
        "disk0s2",
        "disk1s2",
    )
    del disk["APFSPhysicalStores"]
    assert p.startup_disk(plistlib.dumps(disk).decode())["physical_stores"] is p.UNREAD


@pytest.mark.parametrize(
    ("command_id", "text"),
    [
        ("C17", "25 GB\n"),
        ("C18", "-10\n"),
        ("C20", "yes\n"),
        ("C15", ""),
        ("C15", "Mac17,2\nMac17,3\n"),
        ("C26", "2\n"),
    ],
)
def test_a_sysctl_value_in_another_shape_is_unread(command_id, text):
    assert p.sysctl(command_id, text) is p.UNREAD


# --- identifiers never reach the model -------------------------------------------------------


def _inject(node: object) -> None:
    """Plant the canary under identifier-looking keys at every level of a document."""
    if isinstance(node, dict):
        for value in list(node.values()):
            _inject(value)
        for key in ("serial", "serial_number_2", "platform_UUID", "provisioning_UDID"):
            node.setdefault(key, CANARY)
        node["volumes"] = [{"_name": CANARY, "bsd_name": CANARY}]
        node["_spdisplays_display-serial-number"] = CANARY
    elif isinstance(node, list):
        for value in node:
            _inject(value)


@pytest.mark.parametrize("command_id", ["C2", "C3", "C4", "C5", "C6"])
def test_identifier_keys_planted_in_json_never_reach_the_model(command_id):
    document = json.loads(m5(command_id))
    _inject(document)
    parsed = p.PARSERS[command_id](_json(document))
    assert CANARY not in repr(parsed)


@pytest.mark.parametrize("command_id", ["C7", "C11"])
def test_identifier_keys_planted_in_a_plist_never_reach_the_model(command_id):
    document = plistlib.loads(m5(command_id).encode())
    _inject(document)
    parsed = p.PARSERS[command_id](plistlib.dumps(document).decode())
    assert CANARY not in repr(parsed)


def test_names_in_text_output_never_reach_the_model():
    # fdesetup names the account in a deferred-enablement line; pmset and memory_pressure
    # print nothing personal, but a planted line must not travel either.
    assert CANARY not in repr(
        p.filevault(
            f"FileVault is On.\nDeferred enablement appears to be active for user '{CANARY}'.\n"
        )
    )
    assert CANARY not in repr(
        p.memory_pressure(f"{CANARY}\nSystem-wide memory free percentage: 63%\n")
    )


@pytest.mark.parametrize(
    ("parse", "text"),
    [
        (p.nvme, _json({"SPNVMeDataType": [{"_name": "Apple SSD Controller"}]})),
        (p.memory, _json({"SPMemoryDataType": ["24 GB"]})),
        (p.battery_gauge, plistlib.dumps({"CycleCount": 58}).decode()),
        (p.battery_gauge, plistlib.dumps(["not a dict"]).decode()),
        (p.startup_disk, plistlib.dumps(["not a dict"]).decode()),
    ],
)
def test_a_document_of_the_right_kind_in_the_wrong_shape_is_a_changed_source(parse, text):
    with pytest.raises(p.SourceChanged):
        parse(text)


def test_a_percentage_without_its_sign_is_unread():
    document = json.loads(m5("C6"))
    health = document["SPPowerDataType"][0]["sppower_battery_health_info"]
    health["sppower_battery_health_maximum_capacity"] = "99"
    assert p.battery_health(_json(document))["maximum_capacity_percent"] is p.UNREAD


def test_a_store_that_is_not_named_is_unread_and_the_list_still_counts():
    # The count is the storage trunk's first link (spec, the storage dependency table): a
    # list that can be counted keeps its length, and only the garbled name is unread.
    disk = plistlib.loads(m5("C11").encode())
    disk["APFSPhysicalStores"] = [{"APFSPhysicalStore": "disk0s2"}, {"APFSPhysicalStore": 7}]
    assert p.startup_disk(plistlib.dumps(disk).decode())["physical_stores"] == (
        "disk0s2",
        p.UNREAD,
    )
    disk["APFSPhysicalStores"] = ["disk0s2"]
    assert p.startup_disk(plistlib.dumps(disk).decode())["physical_stores"] == (p.UNREAD,)


@pytest.mark.parametrize("stores", [[], "disk0s2", {"APFSPhysicalStore": "disk0s2"}])
def test_a_store_list_that_cannot_be_counted_is_unread(stores):
    disk = plistlib.loads(m5("C11").encode())
    disk["APFSPhysicalStores"] = stores
    assert p.startup_disk(plistlib.dumps(disk).decode())["physical_stores"] is p.UNREAD


def test_the_markers_name_themselves():
    assert (repr(p.UNREAD), repr(p.NOT_APPLICABLE)) == ("UNREAD", "NOT_APPLICABLE")


# --- the #343 review, round 1 ------------------------------------------------------------------

JSON_PARSERS = [
    ("C2", p.hardware, "SPHardwareDataType"),
    ("C3", p.nvme, "SPNVMeDataType"),
    ("C4", p.gpu, "SPDisplaysDataType"),
    ("C5", p.memory, "SPMemoryDataType"),
    ("C6", p.battery_health, "SPPowerDataType"),
]
PLIST_PARSERS = [("C7", p.battery_gauge), ("C11", p.startup_disk)]


@pytest.mark.parametrize(
    ("parse", "top"),
    [(parse, top) for _, parse, top in JSON_PARSERS],
    ids=[c for c, _, _ in JSON_PARSERS],
)
def test_json_nested_past_the_recursion_limit_is_a_changed_source(parse, top):
    text = '{"' + top + '": ' + "[" * 100_000 + "]" * 100_000 + "}"
    with pytest.raises(p.SourceChanged):
        parse(text)


BROKEN_PLISTS = {
    "a date plistlib cannot read": '<?xml version="1.0" encoding="UTF-8"?>'
    '<plist version="1.0"><dict><key>d</key><date>not a date</date></dict></plist>',
    "a key outside any dict": '<?xml version="1.0" encoding="UTF-8"?>'
    '<plist version="1.0"><array><key>k</key></array></plist>',
    "an unknown encoding": '<?xml version="1.0" encoding="x-unknown-8"?>'
    '<plist version="1.0"><array/></plist>',
}


@pytest.mark.parametrize("text", list(BROKEN_PLISTS.values()), ids=list(BROKEN_PLISTS))
@pytest.mark.parametrize(("command_id", "parse"), PLIST_PARSERS, ids=["C7", "C11"])
def test_any_plist_the_reader_cannot_read_is_a_changed_source(command_id, parse, text):
    with pytest.raises(p.SourceChanged):
        parse(text)


@pytest.mark.parametrize(
    "store",
    ["disk0", "/dev/disk0s2", "disk0s2 ", "disk0s2s1", "Jane's Photos", "disk1234s2", "DISK0S2"],
)
def test_c11_a_store_outside_the_grammar_is_unread(store):
    # docs/VOLTRY_MAC_SPEC.md: "the parser treats a store in any other form as garbled".
    disk = plistlib.loads(m5("C11").encode())
    disk["APFSPhysicalStores"] = [{"APFSPhysicalStore": store}]
    assert p.startup_disk(plistlib.dumps(disk).decode())["physical_stores"] == (p.UNREAD,)


def test_c11_more_stores_than_a_volume_can_have_cannot_be_counted():
    disk = plistlib.loads(m5("C11").encode())
    disk["APFSPhysicalStores"] = [{"APFSPhysicalStore": f"disk{n}s2"} for n in range(9)]
    assert p.startup_disk(plistlib.dumps(disk).decode())["physical_stores"] is p.UNREAD


def test_c3_an_empty_nvme_list_has_no_entries():
    # system_profiler prints an empty list for a data type with no devices, as a VM may.
    assert p.nvme(_json({"SPNVMeDataType": []})) == {"entry_count": 0, "entries": ()}


def test_c3_more_entries_than_a_mac_has_is_a_changed_source():
    document = json.loads(m5("C3"))
    items = document["SPNVMeDataType"][0]["_items"]
    document["SPNVMeDataType"][0]["_items"] = items * 17
    with pytest.raises(p.SourceChanged):
        p.nvme(_json(document))


@pytest.mark.parametrize("value", [10**30, -(2**63) - 1, 2**63, 58.0, True, "58"])
def test_an_integer_field_takes_only_a_64_bit_integer(value):
    document = json.loads(m5("C6"))
    battery = next(
        e for e in document["SPPowerDataType"] if e.get("_name") == "spbattery_information"
    )
    battery["sppower_battery_health_info"]["sppower_battery_cycle_count"] = value
    assert p.battery_health(_json(document))["cycle_count"] is p.UNREAD


def test_a_plist_integer_past_64_bits_or_a_real_is_unread():
    # plistlib reads a hex integer of any size (it cannot write one), so edit the text.
    huge = re.sub(
        r"(<key>CycleCount</key>\s*<integer>)58(</integer>)",
        r"\g<1>0x" + "f" * 20_000 + r"\g<2>",
        m5("C7"),
    )
    assert huge != m5("C7")
    assert p.battery_gauge(huge)["cycle_count"] is p.UNREAD
    gauge = plistlib.loads(m5("C7").encode())
    gauge[0]["CycleCount"] = 58.0
    assert p.battery_gauge(plistlib.dumps(gauge).decode())["cycle_count"] is p.UNREAD


def test_an_absent_permanent_failure_flag_is_unread_not_false():
    gauge = plistlib.loads(m5("C7").encode())
    del gauge[0]["PermanentFailureStatus"]
    assert p.battery_gauge(plistlib.dumps(gauge).decode())["permanent_failure"] is p.UNREAD


@pytest.mark.parametrize(
    "entries",
    [
        [1, "x", None],
        [{"_name": "spbattery_information_v2"}],
        [{"no name": True}],
    ],
    ids=["not entries", "a renamed battery entry", "an entry without a name"],
)
def test_c6_says_no_battery_only_for_a_document_it_recognizes(entries):
    with pytest.raises(p.SourceChanged):
        p.battery_health(_json({"SPPowerDataType": entries}))


def test_c6_a_desktops_power_report_has_no_battery():
    entries = [{"_name": "sppower_information"}, {"_name": "sppower_ac_charger_information"}]
    assert p.battery_health(_json({"SPPowerDataType": entries})) is p.NOT_APPLICABLE


def test_a_string_with_a_control_or_bidirectional_character_is_unread():
    document = json.loads(m5("C2"))
    document["SPHardwareDataType"][0]["machine_name"] = "MacBook\u202ePro"
    assert p.hardware(_json(document))["machine_name"] is p.UNREAD
    text = m5("C1").replace("macOS", "mac\x07OS")
    assert p.os_version(text)["product_name"] is p.UNREAD


@pytest.mark.parametrize(
    ("command_id", "text"),
    [("C15", "Mac17,2\nextra\n"), ("C19", "Apple\x07M5\n"), ("C17", "25769803776 bytes\n")],
)
def test_a_sysctl_value_takes_one_clean_line_of_its_shape(command_id, text):
    assert p.sysctl(command_id, text) is p.UNREAD


# A sysctl line is printable as Python 3.12 says, by the character table, on every Python:
# str.isprintable() follows the running Python's Unicode database, so "Apple M5" with a mark
# Unicode 15.0.0 added was unread on 3.11, and one with a capital 16.0.0 added was read on
# 3.14 (the pass-3 pre-audit, P3-output-04).
SYSCTL_CHARACTERS = {
    "a mark Unicode 15.0.0 added": (0x0CF3, True),
    "a capital Unicode 16.0.0 added": (0xA7CB, False),
    "a combining acute": (0x0301, True),
    "a CJK ideograph": (0x4E09, True),
    "an emoji": (0x1F600, True),
    "a no-break space": (0x00A0, False),
    "an ideographic space": (0x3000, False),
    "a zero width space": (0x200B, False),
    "a byte order mark": (0xFEFF, False),
    "private use": (0xE000, False),
    "unassigned": (0x0378, False),
}


@pytest.mark.parametrize(("point", "read"), SYSCTL_CHARACTERS.values(), ids=list(SYSCTL_CHARACTERS))
def test_a_sysctl_value_is_printable_by_the_character_table(point, read):
    value = f"Apple{chr(point)}M5"
    found = p.sysctl("C19", f"{value}\n")
    if read:
        assert found == value
    else:
        assert found is p.UNREAD


def test_a_digit_count_with_words_after_it_is_unread():
    document = json.loads(m5("C4"))
    document["SPDisplaysDataType"][0]["sppci_cores"] = "10 cores"
    assert p.gpu(_json(document))["core_count"] is p.UNREAD


def test_a_status_line_with_words_after_it_is_a_changed_source():
    with pytest.raises(p.SourceChanged):
        p.memory_pressure("System-wide memory free percentage: 63% (plenty)\n")


def test_the_off_states_of_activation_lock_and_trim():
    document = json.loads(m5("C2"))
    document["SPHardwareDataType"][0]["activation_lock_status"] = "activation_lock_disabled"
    assert p.hardware(_json(document))["activation_lock_enabled"] is False
    document = json.loads(m5("C3"))
    document["SPNVMeDataType"][0]["_items"][0]["spnvme_trim_support"] = "No"
    assert p.nvme(_json(document))["entries"][0]["trim_support"] is False


@pytest.mark.parametrize(
    ("parse", "top"),
    [
        (p.gpu, "SPDisplaysDataType"),
        (p.hardware, "SPHardwareDataType"),
        (p.memory, "SPMemoryDataType"),
    ],
)
def test_an_entry_that_is_not_an_object_is_a_changed_source(parse, top):
    with pytest.raises(p.SourceChanged):
        parse(_json({top: ["not an entry"]}))


# --- the #343 review, round 2 ------------------------------------------------------------------

# Arabic-Indic digits: int() reads them, so a pattern that took them would read a number.
FOREIGN_TEN = chr(0x0661) + chr(0x0660)


def _gauge(**changes: object) -> str:
    gauge = plistlib.loads(m5("C7").encode())
    gauge[0].update(changes)
    return plistlib.dumps(gauge).decode()


def _power(**changes: object) -> str:
    document = json.loads(m5("C6"))
    battery = next(
        e for e in document["SPPowerDataType"] if e.get("_name") == "spbattery_information"
    )
    battery.update(changes)
    return _json(document)


def test_a_negative_integer_is_read():
    assert p.battery_gauge(_gauge(Temperature=-250))["temperature_centi_c"] == -250


@pytest.mark.parametrize("value", [2**63 - 1, -(2**63)])
def test_an_integer_at_either_64_bit_bound_is_read(value):
    health = {"sppower_battery_cycle_count": value}
    assert p.battery_health(_power(sppower_battery_health_info=health))["cycle_count"] == value


@pytest.mark.parametrize(("value", "read"), [("", False), ("m" * 256, True), ("m" * 257, False)])
def test_a_string_is_one_to_256_characters(value, read):
    document = json.loads(m5("C2"))
    document["SPHardwareDataType"][0]["machine_name"] = value
    found = p.hardware(_json(document))["machine_name"]
    assert found == value if read else found is p.UNREAD


def test_exactly_16_nvme_entries_are_read():
    document = json.loads(m5("C3"))
    items = document["SPNVMeDataType"][0]["_items"]
    document["SPNVMeDataType"][0]["_items"] = items * 16
    assert p.nvme(_json(document))["entry_count"] == 16


def test_exactly_8_stores_are_read():
    disk = plistlib.loads(m5("C11").encode())
    disk["APFSPhysicalStores"] = [{"APFSPhysicalStore": f"disk{n}s2"} for n in range(8)]
    stores = p.startup_disk(plistlib.dumps(disk).decode())["physical_stores"]
    assert stores == tuple(f"disk{n}s2" for n in range(8))


def test_a_key_at_the_top_of_a_plist_is_a_changed_source():
    # Round 1's IndexError came from this shape; the in-array key raised ValueError.
    text = '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><key>k</key></plist>'
    for parse in (p.battery_gauge, p.startup_disk):
        with pytest.raises(p.SourceChanged):
            parse(text)


class _Odd(Exception):
    """An error of a kind no list of plistlib's errors would name."""


def test_any_error_from_the_plist_reader_is_a_changed_source(monkeypatch):
    def broken(_data: bytes) -> object:
        raise _Odd("the reader failed in a new way")

    monkeypatch.setattr(p.plistlib, "loads", broken)
    for parse in (p.battery_gauge, p.startup_disk):
        with pytest.raises(p.SourceChanged):
            parse(m5("C7") if parse is p.battery_gauge else m5("C11"))


def test_c7_an_empty_dictionary_is_not_a_mac_without_a_battery():
    text = '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict/></plist>'
    with pytest.raises(p.SourceChanged):
        p.battery_gauge(text)


def test_c3_a_controller_that_is_not_an_object_is_a_changed_source():
    with pytest.raises(p.SourceChanged):
        p.nvme(_json({"SPNVMeDataType": ["not a controller"]}))


def test_c3_an_item_that_is_not_an_object_is_an_entry_with_nothing_read():
    found = p.nvme(_json({"SPNVMeDataType": [{"_items": ["not an entry"]}]}))
    assert found["entry_count"] == 1
    assert set(found["entries"][0].values()) == {p.UNREAD}


def test_c4_a_metal_family_that_is_not_text_is_unread():
    document = json.loads(m5("C4"))
    document["SPDisplaysDataType"][0]["spdisplays_mtlgpufamilysupport"] = 4
    document["SPDisplaysDataType"][0]["sppci_cores"] = 10
    assert p.gpu(_json(document)) == {"core_count": p.UNREAD, "metal_family": p.UNREAD}


def test_c6_battery_blocks_that_are_not_objects_are_unread():
    found = p.battery_health(
        _power(
            sppower_battery_health_info=[],
            sppower_battery_charge_info="charging",
            sppower_battery_model_info=1,
        )
    )
    assert found["condition"] is found["maximum_capacity_percent"] is p.UNREAD
    assert found["cycle_count"] is found["state_of_charge_percent"] is p.UNREAD
    assert found["fully_charged"] is found["is_charging"] is p.UNREAD
    assert found["gauge_device_name"] is p.UNREAD


def test_a_choice_that_cannot_be_looked_up_is_unread():
    document = json.loads(m5("C2"))
    document["SPHardwareDataType"][0]["activation_lock_status"] = ["activation_lock_enabled"]
    assert p.hardware(_json(document))["activation_lock_enabled"] is p.UNREAD


def test_only_ascii_digits_are_read_as_numbers():
    document = json.loads(m5("C4"))
    document["SPDisplaysDataType"][0]["sppci_cores"] = FOREIGN_TEN
    assert p.gpu(_json(document))["core_count"] is p.UNREAD
    assert p.sysctl("C18", FOREIGN_TEN + "\n") is p.UNREAD
    with pytest.raises(p.SourceChanged):
        p.memory_pressure(f"System-wide memory free percentage: {FOREIGN_TEN}%\n")
    with pytest.raises(p.SourceChanged):
        p.boot_time("{ sec = " + FOREIGN_TEN + ", usec = 0 } Fri Aug 28 08:00:54 2026\n")
    disk = plistlib.loads(m5("C11").encode())
    disk["APFSPhysicalStores"] = [{"APFSPhysicalStore": "disk" + FOREIGN_TEN + "s2"}]
    assert p.startup_disk(plistlib.dumps(disk).decode())["physical_stores"] == (p.UNREAD,)


def test_c1_a_value_longer_than_256_characters_is_unread_not_cut():
    text = m5("C1").replace("macOS", "m" * 300)
    found = p.os_version(text)
    assert found["product_name"] is p.UNREAD
    assert found["product_version"] is not p.UNREAD


def test_a_permanent_failure_status_past_64_bits_is_unread():
    huge = re.sub(
        r"(<key>PermanentFailureStatus</key>\s*<integer>)0(</integer>)",
        r"\g<1>0x" + "f" * 40 + r"\g<2>",
        m5("C7"),
    )
    assert huge != m5("C7")
    assert p.battery_gauge(huge)["permanent_failure"] is p.UNREAD


# --- found by the #345 review ------------------------------------------------------------------

# Characters str.splitlines() breaks on besides the newline: vertical tab, form feed, the
# file, group and record separators, next line, and the line and paragraph separators.
BREAKS = ["\x0b", "\x0c", "\x1c", "\x1d", "\x1e", chr(0x85), chr(0x2028), chr(0x2029)]


@pytest.mark.parametrize("mark", BREAKS, ids=[f"U+{ord(c):04X}" for c in BREAKS])
def test_only_a_newline_ends_a_line_of_text_output(mark):
    # A value is not cut at the mark, and a status line with words after it is no match.
    found = p.os_version(m5("C1").replace("macOS", "mac" + mark + "OS"))
    assert found["product_name"] is p.UNREAD
    with pytest.raises(p.SourceChanged):
        p.sip("System Integrity Protection status: enabled." + mark + "or not\n")


# --- the GPT audit, pass 1, G1-02: one value given twice ----------------------------------------

# Every line, record and key a parser reads is one the source gives once. Given twice, with
# the same value or not, the output is not the command's shape, and taking the first or the
# last would be a guess (the Architecture's parser row: an unexpected shape becomes
# unavailable with source_changed). No macOS the M5's captures come from prints one twice.


@pytest.mark.parametrize(
    ("parse", "text"),
    [
        (
            p.sip,
            "System Integrity Protection status: enabled.\n"
            "System Integrity Protection status: disabled.\n",
        ),
        (
            p.sip,
            "System Integrity Protection status: enabled.\n"
            "System Integrity Protection status: enabled.\n",
        ),
        (p.gatekeeper, "assessments enabled\nassessments disabled\n"),
        (p.filevault, "FileVault is On.\nFileVault is Off.\n"),
        (
            p.memory_pressure,
            "System-wide memory free percentage: 10%\nSystem-wide memory free percentage: 90%\n",
        ),
        (
            p.boot_time,
            "{ sec = 1787929257, usec = 563642 } Fri Aug 28 08:00:57 2026\n"
            "{ sec = 1, usec = 0 } Thu Jan  1 00:00:01 1970\n",
        ),
        (
            p.thermal,
            "Note: No thermal warning level has been recorded\nThermal Warning Level = 70\n",
        ),
        (p.thermal, "Thermal Warning Level = 0\nThermal Warning Level = 3\n"),
    ],
    ids=["C12", "C12 the same twice", "C13", "C14", "C9", "C27", "C8 none and one", "C8 two"],
)
def test_a_status_line_given_twice_is_a_changed_source(parse, text):
    with pytest.raises(p.SourceChanged):
        parse(text)


def test_c1_a_key_given_twice_is_a_changed_source():
    with pytest.raises(p.SourceChanged):
        p.os_version(m5("C1") + "ProductVersion:\t\t15.0\n")


def _twice(text: str, line: str, again: str) -> str:
    """The text with a line given again, with another value, just after it."""
    assert text.count(line) == 1
    return text.replace(line, line + "\n" + again)


@pytest.mark.parametrize(
    ("parse", "command_id", "line", "again"),
    [
        (p.hardware, "C2", '      "chip_type" : "Apple M5",', '      "chip_type" : "Apple M4",'),
        (
            p.hardware,
            "C2",
            '      "activation_lock_status" : "activation_lock_enabled",',
            '      "activation_lock_status" : "activation_lock_disabled",',
        ),
        (
            p.nvme,
            "C3",
            '          "size_in_bytes" : 1000555581440,',
            '          "size_in_bytes" : 1,',
        ),
        (p.gpu, "C4", '      "sppci_cores" : "10",', '      "sppci_cores" : "40",'),
        (p.memory, "C5", '      "dimm_type" : "LPDDR5",', '      "dimm_type" : "DDR4",'),
        (
            p.battery_health,
            "C6",
            '        "sppower_battery_cycle_count" : 58,',
            '        "sppower_battery_cycle_count" : 999,',
        ),
    ],
    ids=["C2 chip", "C2 activation lock", "C3", "C4", "C5", "C6"],
)
def test_a_json_key_given_twice_is_a_changed_source(parse, command_id, line, again):
    with pytest.raises(p.SourceChanged):
        parse(_twice(m5(command_id), line, again))


@pytest.mark.parametrize(
    ("parse", "top"), [(p.hardware, "SPHardwareDataType"), (p.gpu, "SPDisplaysDataType")]
)
def test_a_json_top_key_given_twice_is_a_changed_source(parse, top):
    text = m5("C2" if parse is p.hardware else "C4")
    body = text.strip()[1:-1]
    with pytest.raises(p.SourceChanged):
        parse("{" + body + "," + body + "}\n")


@pytest.mark.parametrize(
    ("parse", "command_id", "top"),
    [
        (p.hardware, "C2", "SPHardwareDataType"),
        (p.gpu, "C4", "SPDisplaysDataType"),
        (p.memory, "C5", "SPMemoryDataType"),
    ],
)
def test_a_second_entry_where_a_mac_has_one_is_a_changed_source(parse, command_id, top):
    document = json.loads(m5(command_id))
    entry = document[top][0]
    document[top] = [entry, entry]
    with pytest.raises(p.SourceChanged):
        parse(_json(document))


@pytest.mark.parametrize("name", ["spbattery_information", "sppower_ac_charger_information"])
def test_c6_a_battery_or_charger_given_twice_is_a_changed_source(name):
    document = json.loads(m5("C6"))
    entry = next(e for e in document["SPPowerDataType"] if e.get("_name") == name)
    document["SPPowerDataType"].append(entry)
    with pytest.raises(p.SourceChanged):
        p.battery_health(_json(document))


def test_c7_a_second_battery_is_a_changed_source():
    gauge = plistlib.loads(m5("C7").encode())
    with pytest.raises(p.SourceChanged):
        p.battery_gauge(plistlib.dumps([gauge[0], {**gauge[0], "CycleCount": 999}]).decode())


@pytest.mark.parametrize(
    ("parse", "command_id", "key", "line"),
    [
        (p.battery_gauge, "C7", "CycleCount", "\t\t<integer>999</integer>"),
        (p.startup_disk, "C11", "Internal", "\t<false/>"),
    ],
    ids=["C7", "C11"],
)
def test_a_plist_key_given_twice_is_a_changed_source(parse, command_id, key, line):
    text = m5(command_id)
    # The key at the top of its record: the last line that names it.
    at = text.rindex(f"<key>{key}</key>")
    end = text.index("\n", text.index("\n", at) + 1)
    twice = text[: end + 1] + text[at : text.index("\n", at)] + "\n" + line + text[end:]
    assert twice.count(f"<key>{key}</key>") == text.count(f"<key>{key}</key>") + 1
    with pytest.raises(p.SourceChanged):
        parse(twice)


# --- the review of #326, round 1, N1 ------------------------------------------------------------


@pytest.mark.parametrize(
    "first",
    ["ProductVersion:", "ProductVersion:\t\t" + "9" * 300, "ProductVersion:\t\t\x0b"],
    ids=["no value", "a value past 256 characters", "no value but a control"],
)
def test_c1_a_key_given_twice_is_a_changed_source_whatever_its_first_value(first):
    # The key counted only when its value fitted, so a garbled first line let the second
    # through.
    text = f"ProductName:\t\tmacOS\n{first}\nProductVersion:\t\t26.6.2\nBuildVersion:\t\t25G83\n"
    with pytest.raises(p.SourceChanged):
        p.os_version(text)


def test_c1_a_key_given_once_with_a_garbled_value_is_unread():
    text = "ProductName:\t\tmacOS\nProductVersion:\nBuildVersion:\t\t25G83\n"
    assert p.os_version(text) == {
        "product_name": "macOS",
        "product_version": p.UNREAD,
        "build_version": "25G83",
    }


def test_c11_a_store_listed_twice_is_a_changed_source():
    # One store listed twice counted as two, and the report said the startup volume spans
    # more than one physical store.
    store = (
        "\t\t<dict>\n\t\t\t<key>APFSPhysicalStore</key>\n"
        "\t\t\t<string>disk0s2</string>\n\t\t</dict>\n"
    )
    text = m5("C11")
    assert text.count(store) == 1
    with pytest.raises(p.SourceChanged):
        p.startup_disk(text.replace(store, store * 2))
    two = text.replace(store, store + store.replace("disk0s2", "disk1s2"))
    assert p.startup_disk(two)["physical_stores"] == ("disk0s2", "disk1s2")
