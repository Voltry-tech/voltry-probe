"""The report model's core (docs/VOLTRY_MAC_SPEC.md, Decision 6's two labels and
collection status, Decision 8's value and surface objects and the collapse rule, and
Failure modes' save gate and exit codes).

Every value is a JSON object with its availability, and an available one its provenance
from the registry. A surface is available when at least one of its values is; when none
is, the model makes it unavailable with the reason of its first value in registry order.
The collection block is computed once from the surfaces, and the exit code is the first
that applies in the order 5, 3, 2, 130, 4, 6, 1, 0.
"""

from __future__ import annotations

import copy
import itertools
from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal

import pytest
import voltry_mac_test_reports as r

from voltry_mac import availability, model, parsers, registry
from voltry_mac import validate as v

Unavailable = availability.Unavailable
KEYS = {spec.key: spec for spec in registry.SURFACES}


def spec_of(surface: str, name: str) -> registry.ValueKey:
    return next(value for value in KEYS[surface].values if value.name == name)


# --- value objects ----------------------------------------------------------------------------


def test_an_available_value_carries_the_registrys_provenance():
    assert model.value_object(spec_of("memory_pressure", "free_percent"), 38) == {
        "availability": "available",
        "value": 38,
        "provenance": "measured",
    }
    assert model.value_object(spec_of("boot_time", "days_since_boot"), 26)["provenance"] == (
        "derived"
    )


def test_an_unavailable_value_carries_only_its_reason():
    assert model.value_object(
        spec_of("memory_pressure", "free_percent"), Unavailable("source_changed")
    ) == {"availability": "unavailable", "reason": "source_changed"}


def test_decimals_are_written_canonically_and_never_as_floats():
    mean = spec_of("power_and_thermal_samples", "cpu_power_mw_mean")
    assert model.value_object(mean, Decimal("1612.30"))["value"] == "1612.3"
    series = spec_of("power_and_thermal_samples", "sample_cpu_power_mw")
    values = [Decimal("2675.490"), Decimal("0"), Decimal("6.95445e-05")]
    assert model.value_object(series, values)["value"] == ["2675.49", "0.0", "0.0000695445"]
    with pytest.raises(TypeError):
        model.value_object(mean, 1612.3)


# --- surface objects and the collapse rule ------------------------------------------------------


def test_a_surface_carries_its_registry_row():
    surface = model.surface_object("memory_pressure", {"free_percent": 38})
    assert surface == {
        "key": "memory_pressure",
        "interface": "memory_pressure -Q (C9)",
        "privilege": "user",
        "temporal_class": "instant",
        "availability": "available",
        "values": {
            "free_percent": {"availability": "available", "value": 38, "provenance": "measured"}
        },
    }


def test_an_unavailable_surface_has_a_reason_and_no_values():
    surface = model.surface_object("memory_pressure", Unavailable("timeout"))
    assert (surface["availability"], surface["reason"], surface["values"]) == (
        "unavailable",
        "timeout",
        {},
    )
    assert "detail" not in surface


def test_only_the_elevated_surfaces_carry_a_detail():
    ledger = model.surface_object(
        "memory_error_ledger", Unavailable("declined"), detail="not_attempted"
    )
    assert (ledger["reason"], ledger["detail"]) == ("declined", "not_attempted")
    with pytest.raises(ValueError):
        model.surface_object("memory_pressure", Unavailable("timeout"), detail="not_attempted")
    with pytest.raises(ValueError):
        model.surface_object("memory_error_ledger", Unavailable("declined"))


def test_only_the_battery_surfaces_are_not_applicable():
    for key in ("battery_health", "battery_gauge"):
        assert model.surface_object(key, parsers.NOT_APPLICABLE) == {
            "key": key,
            "interface": KEYS[key].interface,
            "privilege": "user",
            "temporal_class": KEYS[key].temporal_class,
            "availability": "not_applicable",
            "values": {},
        }
    with pytest.raises(ValueError):
        model.surface_object("memory_pressure", parsers.NOT_APPLICABLE)


def test_a_surface_whose_values_all_failed_takes_its_first_values_reason_in_registry_order():
    # Given out of registry order, with mixed reasons: the first in registry order decides.
    values = {
        "build_version": Unavailable("timeout"),
        "product_version": Unavailable("source_changed"),
        "product_name": Unavailable("tool_error"),
    }
    surface = model.surface_object("os_version", values)
    assert (surface["availability"], surface["reason"], surface["values"]) == (
        "unavailable",
        "tool_error",
        {},
    )


def test_one_available_value_keeps_the_surface_available():
    surface = model.surface_object(
        "os_version",
        {
            "product_name": Unavailable("source_changed"),
            "product_version": "26.6.2",
            "build_version": Unavailable("source_changed"),
        },
    )
    assert surface["availability"] == "available"
    assert surface["values"]["product_name"] == {
        "availability": "unavailable",
        "reason": "source_changed",
    }


def test_a_surface_takes_exactly_the_registrys_keys():
    with pytest.raises(ValueError):
        model.surface_object("memory_pressure", {})  # a required key is missing
    with pytest.raises(ValueError):
        model.surface_object("memory_pressure", {"free_percent": 38, "extra": 1})
    # An optional key is present exactly when given.
    thermal = model.surface_object("thermal_warning_level", {"thermal_warning_recorded": False})
    assert set(thermal["values"]) == {"thermal_warning_recorded"}


def test_the_ecc_statement_is_always_unavailable_and_unsupported():
    assert model.surface_object("ecc_ras_telemetry", Unavailable("unsupported"))["reason"] == (
        "unsupported"
    )
    with pytest.raises(ValueError):
        model.surface_object("ecc_ras_telemetry", {})


def test_a_reason_outside_the_surfaces_domain_is_refused():
    with pytest.raises(ValueError):
        model.surface_object("memory_pressure", Unavailable("declined"))


# --- the collection block ---------------------------------------------------------------------


@pytest.mark.parametrize("name", r.NAMES)
def test_the_collection_block_of_each_complete_fixture(name):
    document = r.load(name)
    assert model.collection(document["surfaces"]) == document["collection"]


def test_a_declined_run_is_partial_with_two_skipped_and_nothing_unexpected():
    document = r.load("m5-laptop")
    r.unavailable(document, "memory_error_ledger", "declined", "not_attempted")
    r.unavailable(document, "power_and_thermal_samples", "declined", "not_attempted")
    assert model.collection(document["surfaces"]) == {
        "status": "partial",
        "read": 20,
        "skipped": 2,
        "unavailable": 1,
        "not_applicable": 0,
        "unexpected_reasons": [],
    }


def test_a_value_missing_inside_an_available_surface_makes_the_run_partial():
    document = r.load("m5-laptop")
    r.value_unavailable(
        document, "power_and_thermal_samples", "gpu_power_mw_mean", "source_changed"
    )
    block = model.collection(document["surfaces"])
    assert (block["status"], block["read"], block["unexpected_reasons"]) == (
        "partial",
        22,
        ["source_changed"],
    )


def test_unexpected_reasons_are_the_sorted_distinct_codes_on_surfaces_and_values():
    document = r.load("m5-laptop")
    r.unavailable(document, "memory_pressure", "tool_error")
    r.unavailable(document, "sip_status", "source_changed")
    r.value_unavailable(document, "os_version", "build_version", "source_changed")
    r.unavailable(document, "panic_report_count", "no_admin")
    block = model.collection(document["surfaces"])
    assert block["unexpected_reasons"] == ["source_changed", "tool_error"]
    assert (block["skipped"], block["unavailable"]) == (1, 3)


def test_unsupported_alone_keeps_a_run_complete():
    document = r.load("m5-laptop")
    r.unavailable(document, "smart_health_snapshot", "unsupported")
    r.unavailable(document, "smart_wear_attributes", "unsupported")
    block = model.collection(document["surfaces"])
    assert (block["status"], block["unavailable"], block["unexpected_reasons"]) == (
        "complete",
        3,
        [],
    )


# --- the save gate --------------------------------------------------------------------------


FIVE = ("os_version", "firmware_and_boot", "gpu_configuration", "memory_configuration")
MORE = ("memory_pressure", "sip_status", "gatekeeper_status", "filevault_status")


def _only(*keys: str) -> list[dict]:
    """The M5 fixture with only these surfaces available."""
    document = r.load("m5-laptop")
    for surface in document["surfaces"]:
        if surface["availability"] == "available" and surface["key"] not in keys:
            r.unavailable(document, surface["key"], sorted(KEYS[surface["key"]].reasons)[0])
    return document["surfaces"]


@pytest.mark.parametrize(
    ("keys", "saves"),
    [
        (("hardware_overview", *FIVE, *MORE[:3]), True),
        (("kernel_and_platform", *FIVE, *MORE[:3]), True),
        (("hardware_overview", "kernel_and_platform", *FIVE, *MORE[:1]), False),
        ((*FIVE, *MORE), False),
        (tuple(KEYS), True),
    ],
    ids=["8 with the overview", "8 with the kernel", "7", "8 with neither", "all"],
)
def test_the_save_gate(keys, saves):
    surfaces = _only(*keys)
    assert sum(s["availability"] == "available" for s in surfaces) == min(len(keys), 22)
    assert model.save_gate(surfaces) is saves


# --- exit codes -----------------------------------------------------------------------------

CONDITIONS = (
    "root",
    "unsupported",
    "usage",
    "interrupted",
    "not_saved",
    "clear_failed",
    "unexpected",
)
ORDER = {
    "root": 5,
    "unsupported": 3,
    "usage": 2,
    "interrupted": 130,
    "not_saved": 4,
    "clear_failed": 6,
    "unexpected": 1,
}


@pytest.mark.parametrize(
    "present",
    [combo for n in range(len(CONDITIONS) + 1) for combo in itertools.combinations(CONDITIONS, n)],
    ids=lambda combo: "+".join(combo) or "none",
)
def test_the_exit_code_is_the_first_that_applies(present):
    expected = next((ORDER[name] for name in CONDITIONS if name in present), 0)
    assert model.exit_code(**dict.fromkeys(present, True)) == expected


def test_the_spec_examples_of_precedence():
    assert model.exit_code(interrupted=True, clear_failed=True) == 130
    assert model.exit_code(not_saved=True, clear_failed=True) == 4
    assert model.exit_code(clear_failed=True, unexpected=True) == 6


def test_an_unexpected_reason_or_an_unverified_stop_makes_exit_1():
    document = r.load("m5-laptop")
    assert not model.unexpected(document)
    r.unavailable(document, "memory_error_ledger", "declined", "not_attempted")
    assert not model.unexpected(document), "a skip is expected"
    document = r.load("m5-laptop")
    document["collection"]["unexpected_reasons"] = ["timeout"]
    assert model.unexpected(document)
    for cleanup in ("survivor", "listing_failed"):
        document = r.load("m5-laptop")
        document["elevation"]["power"]["cleanup"] = cleanup
        assert model.unexpected(document), cleanup
    document = r.load("m5-laptop")
    document["elevation"]["count"]["cleanup"] = "not_applicable"
    assert not model.unexpected(document)


# --- the document -----------------------------------------------------------------------------

TOOL = {
    "name": "voltry-mac",
    "version": "0.1.0",
    "renderer_version": "1",
    "python": "3.12.11",
    "architecture": "arm64",
    "rosetta": False,
}


@pytest.mark.parametrize("name", r.NAMES)
def test_the_document_rebuilds_each_complete_fixture(name):
    fixture = r.load(name)
    local = datetime.fromisoformat(fixture["collected_at_local"])
    document = model.document(
        tool=fixture["tool"],
        collected_at=local,
        time_zone=fixture["time_zone"],
        validated=fixture["platform"]["validated"],
        elevation=fixture["elevation"],
        surfaces=copy.deepcopy(fixture["surfaces"]),
        commands=fixture["commands"],
        paper=fixture["render"]["paper"],
    )
    assert document == fixture
    v.validate(document)


def test_the_times_denote_one_instant_in_whole_seconds():
    fixture = r.load("m5-laptop")
    instant = datetime(2026, 9, 23, 21, 5, 31, 734000, tzinfo=UTC)
    for offset, local in (
        (timedelta(hours=-7), "2026-09-23T14:05:31-07:00"),
        (timedelta(hours=5, minutes=30), "2026-09-24T02:35:31+05:30"),
        (timedelta(0), "2026-09-23T21:05:31+00:00"),
    ):
        document = model.document(
            tool=TOOL,
            collected_at=instant.astimezone(timezone(offset)),
            time_zone="unknown",
            validated=True,
            elevation=fixture["elevation"],
            surfaces=fixture["surfaces"],
            commands=fixture["commands"],
            paper="a4",
        )
        assert document["collected_at_utc"] == "2026-09-23T21:05:31Z"
        assert document["collected_at_local"] == local


def test_a_naive_time_is_refused():
    fixture = r.load("m5-laptop")
    with pytest.raises(ValueError):
        model.document(
            tool=TOOL,
            collected_at=datetime(2026, 9, 23, 14, 5, 31),  # noqa: DTZ001 - the case under test
            time_zone="unknown",
            validated=True,
            elevation=fixture["elevation"],
            surfaces=fixture["surfaces"],
            commands=fixture["commands"],
            paper="a4",
        )


def test_an_array_is_written_as_a_list_in_capture_order():
    names = spec_of("kernel_and_platform", "perf_level_names")
    assert model.value_object(names, ("Performance", "Efficiency"))["value"] == [
        "Performance",
        "Efficiency",
    ]


def test_a_surface_takes_only_values_unavailable_or_not_applicable():
    with pytest.raises(TypeError):
        model.surface_object("memory_pressure", 38)


def test_an_available_elevated_surface_carries_no_detail():
    values = dict.fromkeys(r.values(r.load("m5-laptop"), "memory_error_ledger"), 0)
    assert model.surface_object("memory_error_ledger", values)["availability"] == "available"
    with pytest.raises(ValueError):
        model.surface_object("memory_error_ledger", values, detail="parse_failed")


# --- the #345 review --------------------------------------------------------------------------


@pytest.mark.parametrize("payload", ["count", "power"])
@pytest.mark.parametrize("cleanup", ["survivor", "listing_failed"])
def test_an_unverified_stop_of_either_payload_makes_exit_1(payload, cleanup):
    document = r.load("m5-laptop")
    document["elevation"][payload]["cleanup"] = cleanup
    assert model.unexpected(document)


def test_not_applicable_takes_no_detail():
    with pytest.raises(ValueError):
        model.surface_object("battery_health", parsers.NOT_APPLICABLE, detail="not_attempted")


def test_a_detail_outside_the_specs_list_is_refused():
    with pytest.raises(ValueError):
        model.surface_object("memory_error_ledger", Unavailable("declined"), detail="gone")
