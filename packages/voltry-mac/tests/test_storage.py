"""The storage identity chain (docs/VOLTRY_MAC_SPEC.md, Decision 8's storage dependency
table, and Test strategy part 1's "Storage identity fixtures").

One trunk, two branches. C11 names the startup volume's physical stores; with exactly
one, its whole disk is that store without its final s and digits. The chain forks there:
C3's one entry carrying the whole disk's name is the NVMe profile, and C28's one
controller listing it is the SMART log. A failure closes only the branch where it
occurs. Every fixture keeps every storage fact on one device, or marks the affected
branch unavailable with the stated reason and leaves the other branch as it is.
"""

from __future__ import annotations

import json
import plistlib
from pathlib import Path

import pytest

from voltry_mac import availability, registry, smart, spawn, storage

Unavailable = availability.Unavailable

TESTS = Path(__file__).resolve().parent
M5 = TESTS / "fixtures" / "commands" / "m5-laptop"
LOG = bytes.fromhex((TESTS / "fixtures" / "smart" / "m5-laptop-2026-09-26.hex").read_text())
HEX = LOG.hex()


def ran(command_id: str, stdout: str, code: int = 0) -> spawn.Result:
    return spawn.Result(command_id, spawn.Ending.EXITED, code, stdout, "", 20, False, True)


def ended(command_id: str, ending: spawn.Ending, *, missing: bool = False) -> spawn.Result:
    code = None if ending is spawn.Ending.NOT_STARTED else -15
    return spawn.Result(command_id, ending, code, "", "", 10, missing, True)


def c11(*stores: object) -> spawn.Result:
    disk = plistlib.loads((M5 / "C11.out").read_bytes())
    disk["APFSPhysicalStores"] = [{"APFSPhysicalStore": store} for store in stores]
    return ran("C11", plistlib.dumps(disk).decode())


def c3(*bsd_names: object) -> spawn.Result:
    document = json.loads((M5 / "C3.out").read_text())
    template = document["SPNVMeDataType"][0]["_items"][0]
    document["SPNVMeDataType"][0]["_items"] = [dict(template, bsd_name=name) for name in bsd_names]
    return ran("C3", json.dumps(document))


def c28(*controllers: dict) -> spawn.Result:
    read = any(controller["status"] == "ok" for controller in controllers)
    document = {"schema": "voltry-mac-smart/0", "controllers": list(controllers)}
    return ran("C28", json.dumps(document), 0 if read else 2)


def ok(*media: str, log: str = HEX) -> dict:
    return {"location": "Internal", "media": list(media), "status": "ok", "smart_hex": log}


def failed(*media: str) -> dict:
    return {
        "location": "Internal",
        "media": list(media),
        "status": "error",
        "error": "smart_read_failed",
    }


M5_C11 = ran("C11", (M5 / "C11.out").read_text())
M5_C3 = ran("C3", (M5 / "C3.out").read_text())
M5_C28 = c28(ok("disk0"))
ENTRY = {
    "bsd_name": "disk0",
    "device_model": "APPLE SSD AP1024Z",
    "device_revision": "2973.120",
    "size_text": "1 TB",
    "size_bytes": 1000555581440,
    "smart_status": "Verified",
    "trim_support": True,
}
DECODED = smart.decode(LOG)
HEALTH = {key: DECODED[key] for key in storage.HEALTH_KEYS}
WEAR = {key: DECODED[key] for key in storage.WEAR_KEYS}


def entry_keys(reason: str) -> dict:
    return {key: Unavailable(reason) for key in ENTRY}


def smart_surfaces(chain: storage.Chain) -> tuple[object, object]:
    return chain.smart_health_snapshot, chain.smart_wear_attributes


# --- the key sets ------------------------------------------------------------------------------


def test_the_chain_fills_every_read_key_and_leaves_the_computed_ones_to_the_model():
    def keys(surface: str) -> set[str]:
        return {value.name for value in registry.BY_KEY[surface].values}

    assert set(storage.HEALTH_KEYS) == keys("smart_health_snapshot") - {"composite_temperature_c"}
    assert set(storage.WEAR_KEYS) == keys("smart_wear_attributes") - {"bytes_read", "bytes_written"}
    assert set(storage.ENTRY_KEYS) == keys("nvme_devices") - {"entry_count"} == set(ENTRY)
    assert set(storage.HEALTH_KEYS) | set(storage.WEAR_KEYS) == set(DECODED)


# --- every fact on one device ------------------------------------------------------------------


def test_the_m5_keeps_every_storage_fact_on_disk0():
    chain = storage.chain(M5_C11, M5_C3, M5_C28)
    assert chain.startup_disk == {
        "physical_store_count": 1,
        "physical_store": "disk0s2",
        "whole_disk": "disk0",
        "internal": True,
        "solid_state": True,
    }
    assert chain.nvme_devices == {"entry_count": 1, **ENTRY}
    assert smart_surfaces(chain) == (HEALTH, WEAR)
    assert chain.c28_failed_run is False


def test_the_startup_disk_on_the_second_controller():
    worn = bytearray(LOG)
    worn[5] = 42  # percentage used: this controller's log, not the first one's
    chain = storage.chain(
        c11("disk4s2"), c3("disk0", "disk4"), c28(ok("disk0"), ok("disk4", log=bytes(worn).hex()))
    )
    assert chain.startup_disk["whole_disk"] == "disk4"
    assert chain.nvme_devices == {"entry_count": 2, **ENTRY, "bsd_name": "disk4"}
    assert chain.smart_wear_attributes["percentage_used"] == 42


# --- each row of the dependency table ----------------------------------------------------------


def test_an_external_startup_disk_with_no_nvme_record():
    chain = storage.chain(c11("disk4s2"), c3("disk0"), c28(ok("disk0")))
    assert chain.startup_disk["whole_disk"] == "disk4"
    assert chain.nvme_devices == Unavailable("source_absent")
    assert smart_surfaces(chain) == (Unavailable("source_absent"),) * 2
    assert chain.c28_failed_run is False


def test_a_startup_disk_whose_name_matches_nothing():
    chain = storage.chain(c11("disk7s1"), M5_C3, M5_C28)
    assert chain.nvme_devices == Unavailable("source_absent")
    assert smart_surfaces(chain) == (Unavailable("source_absent"),) * 2


def test_a_startup_volume_on_two_physical_stores():
    chain = storage.chain(c11("disk0s2", "disk1s2"), M5_C3, M5_C28)
    assert chain.startup_disk["physical_store_count"] == 2
    assert chain.startup_disk["physical_store"] == Unavailable("unsupported")
    assert chain.startup_disk["whole_disk"] == Unavailable("unsupported")
    assert chain.nvme_devices == {"entry_count": 1, **entry_keys("unsupported")}
    assert smart_surfaces(chain) == (Unavailable("unsupported"),) * 2


def test_two_nvme_entries_with_the_startup_disks_name_beside_a_valid_log():
    chain = storage.chain(M5_C11, c3("disk0", "disk0"), M5_C28)
    assert chain.nvme_devices == Unavailable("source_changed")
    assert smart_surfaces(chain) == (HEALTH, WEAR), "the SMART branch still reads"


def test_a_failed_c3_beside_a_valid_log():
    chain = storage.chain(M5_C11, ran("C3", "", 1), M5_C28)
    assert chain.nvme_devices == Unavailable("tool_error")
    assert smart_surfaces(chain) == (HEALTH, WEAR)


def test_a_failed_c28_beside_an_available_nvme_entry():
    chain = storage.chain(M5_C11, M5_C3, ended("C28", spawn.Ending.DEADLINE))
    assert chain.nvme_devices == {"entry_count": 1, **ENTRY}
    assert smart_surfaces(chain) == (Unavailable("timeout"),) * 2
    assert chain.c28_failed_run is True


def test_a_garbled_store_leaves_the_surface_and_closes_both_branches():
    chain = storage.chain(c11("Macintosh HD"), M5_C3, M5_C28)
    assert chain.startup_disk == {
        "physical_store_count": 1,
        "physical_store": Unavailable("source_changed"),
        "whole_disk": Unavailable("source_changed"),
        "internal": True,
        "solid_state": True,
    }
    assert chain.nvme_devices == {"entry_count": 1, **entry_keys("source_changed")}
    assert smart_surfaces(chain) == (Unavailable("source_changed"),) * 2
    assert chain.c28_failed_run is False


@pytest.mark.parametrize("store", [7, "", "disk0", "disk0s", "disk1234s2", "disk0s2 "])
def test_every_store_outside_its_grammar_is_garbled(store):
    chain = storage.chain(c11(store), M5_C3, M5_C28)
    assert chain.startup_disk["physical_store_count"] == 1
    assert chain.startup_disk["whole_disk"] == Unavailable("source_changed")


def test_one_garbled_store_of_two_still_counts_two():
    chain = storage.chain(c11("disk0s2", 7), M5_C3, M5_C28)
    assert chain.startup_disk["physical_store_count"] == 2
    assert chain.startup_disk["whole_disk"] == Unavailable("unsupported")


@pytest.mark.parametrize(
    "stores",
    [None, [], "disk0s2", [{"APFSPhysicalStore": f"disk{n}s2"} for n in range(9)]],
    ids=["missing", "empty", "not a list", "nine stores"],
)
def test_a_store_list_that_cannot_be_counted_closes_the_trunk(stores):
    disk = plistlib.loads((M5 / "C11.out").read_bytes())
    if stores is None:
        del disk["APFSPhysicalStores"]
    else:
        disk["APFSPhysicalStores"] = stores
    chain = storage.chain(ran("C11", plistlib.dumps(disk).decode()), M5_C3, M5_C28)
    for name in ("physical_store_count", "physical_store", "whole_disk"):
        assert chain.startup_disk[name] == Unavailable("source_changed"), name
    assert chain.startup_disk["internal"] is True
    assert chain.nvme_devices == {"entry_count": 1, **entry_keys("source_changed")}
    assert smart_surfaces(chain) == (Unavailable("source_changed"),) * 2


def test_one_controller_listing_the_startup_disk_and_another_medium():
    chain = storage.chain(M5_C11, M5_C3, c28(ok("disk0", "disk1")))
    assert smart_surfaces(chain) == (Unavailable("unsupported"),) * 2
    assert chain.nvme_devices == {"entry_count": 1, **ENTRY}
    assert chain.c28_failed_run is False


def test_two_controllers_listing_the_startup_disk_break_the_contract():
    chain = storage.chain(M5_C11, M5_C3, c28(ok("disk0"), failed("disk0")))
    assert smart_surfaces(chain) == (Unavailable("source_changed"),) * 2
    assert chain.c28_failed_run is True
    assert chain.nvme_devices == {"entry_count": 1, **ENTRY}


# --- C11 that did not read ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("c11_result", "reason"),
    [
        (ended("C11", spawn.Ending.DEADLINE), "timeout"),
        (ended("C11", spawn.Ending.NOT_STARTED, missing=True), "source_absent"),
        (ended("C11", spawn.Ending.NOT_STARTED), "tool_error"),
        (ended("C11", spawn.Ending.OUTPUT_CAP), "source_changed"),
        (ended("C11", spawn.Ending.SIGNALED), "tool_error"),
        (ran("C11", "", 1), "tool_error"),
        (ran("C11", "not a plist"), "source_changed"),
        (ran("C11", plistlib.dumps(["a list"]).decode()), "source_changed"),
    ],
    ids=[
        "deadline",
        "missing",
        "failed start",
        "output cap",
        "signal",
        "exit 1",
        "not a plist",
        "not a volume record",
    ],
)
def test_a_c11_that_did_not_read_passes_its_reason_down_both_branches(c11_result, reason):
    chain = storage.chain(c11_result, M5_C3, M5_C28)
    assert chain.startup_disk == Unavailable(reason)
    assert chain.nvme_devices == {"entry_count": 1, **entry_keys(reason)}
    assert smart_surfaces(chain) == (Unavailable(reason),) * 2
    assert chain.c28_failed_run is False, "C28 ran and read; only the chain is closed"


def test_c3_itself_decides_before_the_trunk():
    chain = storage.chain(ran("C11", "", 1), ended("C3", spawn.Ending.DEADLINE), M5_C28)
    assert chain.nvme_devices == Unavailable("timeout")


def test_c28s_failed_run_counts_while_the_trunk_is_closed():
    chain = storage.chain(ran("C11", "", 1), M5_C3, ended("C28", spawn.Ending.NOT_STARTED))
    assert smart_surfaces(chain) == (Unavailable("tool_error"),) * 2  # the whole disk's reason
    assert chain.c28_failed_run is True


# --- values the sources garbled ----------------------------------------------------------------


def test_an_nvme_field_the_source_garbled_is_source_changed_on_that_value():
    document = json.loads((M5 / "C3.out").read_text())
    del document["SPNVMeDataType"][0]["_items"][0]["device_model"]
    chain = storage.chain(M5_C11, ran("C3", json.dumps(document)), M5_C28)
    assert chain.nvme_devices == {
        "entry_count": 1,
        **ENTRY,
        "device_model": Unavailable("source_changed"),
    }


def test_an_entry_whose_name_is_garbled_fails_the_match_closed():
    # It may be the startup disk's; the chain does not guess.
    chain = storage.chain(M5_C11, c3("disk4", 7), M5_C28)
    assert chain.nvme_devices == Unavailable("source_changed")
    assert smart_surfaces(chain) == (HEALTH, WEAR)


def test_the_entry_and_store_counts_at_their_edges():
    sixteen = storage.chain(M5_C11, c3("disk0", *(f"disk{n}" for n in range(10, 25))), M5_C28)
    assert sixteen.nvme_devices == {"entry_count": 16, **ENTRY}
    seventeen = storage.chain(M5_C11, c3("disk0", *(f"disk{n}" for n in range(10, 26))), M5_C28)
    assert seventeen.nvme_devices == Unavailable("source_changed"), "C3's parser refuses more"
    eight = storage.chain(c11(*(f"disk{n}s2" for n in range(8))), M5_C3, M5_C28)
    assert eight.startup_disk["physical_store_count"] == 8
    assert eight.startup_disk["whole_disk"] == Unavailable("unsupported")


def test_a_startup_disk_flag_the_source_garbled_is_source_changed():
    disk = plistlib.loads((M5 / "C11.out").read_bytes())
    disk["SolidState"] = "yes"
    chain = storage.chain(ran("C11", plistlib.dumps(disk).decode()), M5_C3, M5_C28)
    assert chain.startup_disk["solid_state"] == Unavailable("source_changed")
    assert chain.startup_disk["whole_disk"] == "disk0"


def test_a_log_field_outside_its_bound_is_source_changed_on_that_value():
    raw = bytearray(LOG)
    raw[1:3] = (401).to_bytes(2, "little")
    chain = storage.chain(M5_C11, M5_C3, c28(ok("disk0", log=bytes(raw).hex())))
    assert chain.smart_health_snapshot == {
        **HEALTH,
        "composite_temperature_k": Unavailable("source_changed"),
    }
    assert chain.smart_wear_attributes == WEAR


def test_a_store_count_outside_its_range_closes_the_trunk_whatever_the_parser_gave(monkeypatch):
    # The parser caps the list at 8; the chain holds the range on its own all the same.
    from voltry_mac import parsers

    nine = {
        "physical_stores": tuple(f"disk{n}s2" for n in range(9)),
        "internal": True,
        "solid_state": True,
    }
    monkeypatch.setattr(parsers, "startup_disk", lambda text: nine)
    chain = storage.chain(M5_C11, M5_C3, M5_C28)
    assert chain.startup_disk["physical_store_count"] == Unavailable("source_changed")
    assert chain.startup_disk["whole_disk"] == Unavailable("source_changed")
