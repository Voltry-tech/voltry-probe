"""The PDF's appendices as data (docs/VOLTRY_MAC_SPEC.md, "Page by page", pages 5 and on;
the field inventory's Appendix A values and its metadata table; Decision 4's render rules).

Appendix A: every surface tried, with its result and reason code, how it was read and as
whom, and why any part of it was not read; then the values the field inventory assigns to
Appendix A, each with its label chip. Appendix B: the versions that made the report and the
renderer that drew the PDF when it is another, the macOS build, the collection time in UTC
and local time with the zone, the validated flag, the full elevation record, each command's
runs, failures and total time with its fixed template from the producing version's manifest
(or the IDs alone, with a note), the characters replaced, the full report ID and the public
source at that version.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
import voltry_mac_test_reports as r

from voltry_mac import allowlist, appendices, phrases, registry

TEMPLATES = {command.id: allowlist.display(command.template) for command in allowlist.COMMANDS}


def report(document: dict) -> phrases.Report:
    return phrases.Report(document)


def edited(name: str, *edits) -> dict:
    document = r.load(name)
    for edit in edits:
        edit(document)
    return r.finish(document)


# --- Appendix A: every surface tried --------------------------------------------------------------


def test_every_surface_is_listed_once_in_registry_order():
    tried = appendices.tried(report(r.load("m5-laptop")))
    assert [row.key for row in tried] == [spec.key for spec in registry.SURFACES]
    assert len({row.name for row in tried}) == len(registry.SURFACES)


def test_a_read_surface_says_how_it_was_read_and_as_whom():
    first = appendices.tried(report(r.load("m5-laptop")))[0]
    assert (first.name, first.result, first.how, first.why) == (
        "macOS version",
        "available",
        "sw_vers (C1), as you",
        "",
    )


@pytest.mark.parametrize(
    ("key", "how"),
    [
        (
            "panic_report_count",
            "count of .panic names under /Library/Logs/DiagnosticReports (R1), as you, from "
            "a folder only administrator accounts can read",
        ),
        (
            "memory_error_ledger",
            "sqlite3 on Apple's private store, as _mmaintenanced (S3), through sudo, " "sandboxed",
        ),
        ("power_and_thermal_samples", "powermetrics (S4), as root, through sudo, sandboxed"),
        ("ecc_ras_telemetry", "none: the fixed statement that macOS has no public interface"),
    ],
)
def test_each_privilege_says_as_whom(key, how):
    (row,) = [t for t in appendices.tried(report(r.load("m5-laptop"))) if t.key == key]
    assert row.how == how


def test_an_unread_surface_gives_its_reason_code_and_its_words():
    tried = appendices.tried(report(r.load("concerning-desktop")))
    (pressure,) = [t for t in tried if t.key == "memory_pressure"]
    assert (pressure.result, pressure.why) == (
        "unavailable: source_changed",
        "Could not read: macOS returned a format this version does not recognize",
    )
    (ecc,) = [t for t in tried if t.key == "ecc_ras_telemetry"]
    assert (ecc.result, ecc.why) == (
        "unavailable: unsupported",
        "Unavailable: macOS has no public interface",
    )


def test_an_available_surface_names_each_value_it_could_not_read_once():
    tried = appendices.tried(report(r.load("concerning-desktop")))
    (power,) = [t for t in tried if t.key == "power_and_thermal_samples"]
    # Each value that was not read names its own reason code, as a surface's result does.
    assert (power.result, power.why) == (
        "available",
        "GPU power (source_changed): not reported by macOS.",
    )


def test_the_elevated_surfaces_say_why_they_were_not_read():
    document = r.history(
        "m5-laptop",
        r.declined_record("no"),
        ("declined", "not_attempted"),
        ("declined", "not_attempted"),
    )
    tried = appendices.tried(report(document))
    (ledger,) = [t for t in tried if t.key == "memory_error_ledger"]
    assert (ledger.result, ledger.why) == (
        "unavailable: declined",
        "Not read: needs administrator access (you chose not to allow it)",
    )


def test_a_desktop_battery_is_not_applicable():
    tried = appendices.tried(report(r.load("concerning-desktop")))
    for key in ("battery_health", "battery_gauge"):
        (battery,) = [t for t in tried if t.key == key]
        assert (battery.result, battery.why) == ("not applicable", "This Mac has no battery.")


# --- Appendix A: the values the inventory assigns to it -------------------------------------------


def test_the_appendix_values_on_the_m5():
    values = appendices.values(report(r.load("m5-laptop")))
    shown = {value.label: (value.text, value.chip, value.availability) for value in values}
    assert shown == {
        "Metal support": ("Metal 4", "reported", None),
        "OS loader version": ("18000.161.10", "reported", None),
        "Model identifier (sysctl)": ("Mac17,2", "reported", None),
        "Board ID": ("J714sAP", "reported", None),
        "CPU brand": ("Apple M5", "reported", None),
        "Apple silicon": ("yes", "reported", None),
        "CPU count": ("10", "reported", None),
        "Memory total": ("25,769,803,776 bytes", "reported", None),
        "Drive firmware revision": ("1001.160.2", "reported", None),
        "TRIM support": ("yes", "reported", None),
        "Drive capacity": ("1,000,555,581,440 bytes", "reported", None),
        "Drive entries": ("1", "derived", None),
        "Physical stores": ("1", "derived", None),
        "Physical store": ("disk0s2", "reported", None),
        "Battery gauge chip": ("bq40z651", "reported", None),
        "Battery gauge firmware": ("0c02", "reported", None),
        "Battery gauge hardware": ("0100", "reported", None),
        "Memory size (memory profile)": ("24 GB", "reported", None),
        "Charge cycles (power report)": ("57", "measured", None),
        "Virtual machine": ("no", "measured", None),
    }


def test_each_value_chip_is_the_registrys_provenance():
    provenance = {
        (spec.key, value.name): value.provenance
        for spec in registry.SURFACES
        for value in spec.values
    }
    for value in appendices.values(report(r.load("m5-laptop"))):
        assert value.chip == provenance[(value.key, value.name)], value.label


def test_an_unread_value_shows_its_words_and_an_availability_chip():
    document = edited(
        "m5-laptop",
        lambda d: r.unavailable(d, "gpu_configuration", "timeout"),
        lambda d: r.value_unavailable(d, "kernel_and_platform", "cpu_brand", "tool_error"),
    )
    shown = {v.label: (v.text, v.chip, v.availability) for v in appendices.values(report(document))}
    assert shown["Metal support"] == ("Not read: timed out after 10 seconds", None, "unavailable")
    assert shown["CPU brand"] == ("Not read: sysctl returned an error", None, "unavailable")


def test_a_desktops_battery_values_are_not_applicable():
    shown = {
        v.label: (v.text, v.chip, v.availability)
        for v in appendices.values(report(r.load("concerning-desktop")))
    }
    for label in ("Battery gauge chip", "Charge cycles (power report)"):
        assert shown[label] == (
            "Not applicable: this Mac has no battery.",
            None,
            "not applicable",
        )


# --- Appendix B: how this report was made ---------------------------------------------------------


def made(document: dict, **options) -> dict[str, str]:
    options.setdefault("renderer", "1")
    options.setdefault("replaced", 0)
    return {line.label: line.text for line in appendices.made(report(document), **options)}


def test_the_versions_times_and_flags():
    shown = made(r.load("m5-laptop"))
    assert shown["Made by"] == "voltry-mac 0.1.0, renderer 1, Python 3.12.11, arm64"
    assert shown["macOS"] == "macOS 26.6.2 (25G83)"
    assert shown["Collected, UTC"] == "2026-09-23T21:05:31Z"
    assert shown["Collected, local time"] == "2026-09-23T14:05:31-07:00 (America/Los_Angeles)"
    assert shown["Validated configuration"] == "yes"
    assert shown["Characters replaced"] == "none"
    assert shown["Report ID"] == r.load("m5-laptop")["report_id"]
    assert shown["Source"] == (
        "https://github.com/Voltry-tech/voltry-probe/tree/voltry-mac-v0.1.0/packages/voltry-mac"
    )
    # The Release plan's Provenance: the PyPI page of the exact version, beside the tag.
    assert shown["PyPI"] == "https://pypi.org/project/voltry-mac/0.1.0/"
    assert "Note" not in shown


def test_appendix_b_says_the_one_thing_the_run_changes():
    # Decision 2: "The README and Appendix B say so, so the claim stays literally true."
    shown = made(r.load("m5-laptop"))
    assert shown["What it changes"] == appendices.SUDO
    assert "clears the sudo authorization remembered for your account" in appendices.SUDO
    assert "before and after the administrator reads" in appendices.SUDO
    labels = list(shown)
    assert labels.index("Final clear (sudo -k)") + 1 == labels.index("What it changes")


def test_an_unknown_time_zone_prints_the_offset_alone():
    # Decision 8: the zone is unknown "when the link is absent or malformed, in which case
    # the PDF prints the offset alone" (the #352 review, round 2).
    document = r.load("m5-laptop")
    document["time_zone"] = "unknown"
    assert made(r.rehash(document))["Collected, local time"] == "2026-09-23T14:05:31-07:00"


def _history(key: str) -> dict:
    record, count, power = r.LEGAL[key]
    return r.history("m5-laptop", record, count, power)


@pytest.mark.parametrize(
    "key",
    ["declined at the question", "--no-root", "not an administrator", "the listing failed"],
)
def test_a_run_that_never_prepared_sudo_says_it_changed_nothing(key):
    shown = made(_history(key))
    assert shown["Prepare (sudo -k)"] == "not_run"
    assert shown["What it changes"] == appendices.UNCHANGED
    assert appendices.UNCHANGED.startswith("Nothing")


@pytest.mark.parametrize("key", ["sudo -k failed", "authentication denied at S2"])
def test_a_run_that_prepared_sudo_says_it_cleared_it(key):
    assert made(_history(key))["What it changes"] == appendices.SUDO


def test_the_full_id_and_the_links_are_set_across_the_page():
    lines = appendices.made(report(r.load("m5-laptop")), renderer="1", replaced=0)
    assert {line.label for line in lines if line.wide} == {"Report ID", "Source", "PyPI"}


def test_rosetta_is_said():
    document = r.load("m5-laptop")
    document["tool"]["rosetta"] = True
    document["tool"]["architecture"] = "x86_64"
    assert made(r.finish(document))["Made by"].endswith("x86_64, under Rosetta")


def test_another_renderer_says_so():
    shown = made(r.load("m5-laptop"), renderer="2")
    assert shown["Made by"] == "voltry-mac 0.1.0, renderer 1, Python 3.12.11, arm64"
    assert shown["Note"] == (
        "This PDF was drawn by voltry-mac 0.1.0, renderer 2; the report was made by "
        "voltry-mac 0.1.0, renderer 1, so this file may differ from the original PDF."
    )


def test_another_package_version_says_so_with_both_versions():
    # Failure modes, render row: "A line naming both versions".
    shown = made(r.load("m5-laptop"), drawn_by="0.2.0")
    assert shown["Made by"] == "voltry-mac 0.1.0, renderer 1, Python 3.12.11, arm64"
    assert shown["Note"] == (
        "This PDF was drawn by voltry-mac 0.2.0, renderer 1; the report was made by "
        "voltry-mac 0.1.0, renderer 1, so this file may differ from the original PDF."
    )


@pytest.mark.parametrize("drawn_by", [None, "0.1.0"])
def test_the_version_that_made_the_report_adds_no_note(drawn_by):
    assert "Note" not in made(r.load("m5-laptop"), drawn_by=drawn_by)


def test_replaced_characters_are_counted():
    assert made(r.load("m5-laptop"), replaced=1)["Characters replaced"] == (
        "1 character outside the PDF's character set was printed as ?"
    )
    assert made(r.load("m5-laptop"), replaced=3)["Characters replaced"] == (
        "3 characters outside the PDF's character set were printed as ?"
    )


def test_an_unread_macos_version_gives_its_words():
    document = edited("m5-laptop", lambda d: r.unavailable(d, "os_version", "timeout"))
    assert made(document)["macOS"] == "Not read: timed out after 10 seconds"


@pytest.mark.parametrize("key", list(r.LEGAL), ids=list(r.LEGAL))
def test_the_full_elevation_record_is_printed(key):
    record, count, power = r.LEGAL[key]
    document = r.history("m5-laptop", record, count, power)
    shown = made(document)
    e = document["elevation"]
    assert shown["Consent"] == e["consent"] + (
        f", skip cause {e['skip_cause']}" if e["skip_cause"] else ""
    )
    assert shown["Mode"] == e["mode"]
    checks = e["checks"]
    assert shown["Service account"] == checks["service_account"]
    assert shown["Sandbox probe"] == checks["sandbox_probe"]
    assert shown["Process listing"] == checks["listing"]
    assert shown["Prepare (sudo -k)"] == e["prepare"]
    assert shown["Authenticate (sudo -v)"] == e["authenticate"]
    for label, name in (("Memory-error step", "count"), ("Power and thermal step", "power")):
        step = e[name]
        assert shown[label] == f"{step['ending']}, cleanup {step['cleanup']}"
    assert shown["Final clear (sudo -k)"] == e["cleared"] + (
        f", {e['clear_error']}" if e["clear_error"] else ""
    )


def test_the_codes_are_monospaced_and_the_prose_is_not():
    lines = appendices.made(report(r.load("m5-laptop")), renderer="1", replaced=0)
    mono = {line.label for line in lines if line.mono}
    assert {"Report ID", "Source", "Consent", "Mode", "Memory-error step"} <= mono
    assert not {"Made by", "macOS", "Characters replaced"} & mono


# --- Appendix B: the commands ---------------------------------------------------------------------


def test_each_command_that_ran_with_its_template():
    document = r.load("m5-laptop")
    commands = appendices.commands(report(document), TEMPLATES)
    assert [c.id for c in commands] == [record["id"] for record in document["commands"]]
    first = commands[0]
    record = document["commands"][0]
    assert (first.runs, first.failed, first.time) == (
        str(record["runs"]),
        str(record["failed_runs"]),
        f"{record['duration_ms']:,} ms",
    )
    assert first.template == "/usr/bin/sw_vers"
    for command in commands:
        assert command.template == TEMPLATES[command.id]


def test_no_template_prints_an_interpreter_or_an_output_path():
    for command in appendices.commands(report(r.load("m5-laptop")), TEMPLATES):
        assert "/python" not in command.template and ".pdf" not in command.template


def test_an_unknown_producing_version_lists_the_ids_alone_with_a_note():
    commands = appendices.commands(report(r.load("m5-laptop")), None)
    assert all(command.template == "" for command in commands)
    assert appendices.unknown_templates("0.9.0") == (
        "This renderer does not know the command templates of voltry-mac 0.9.0, so the "
        "commands are listed by ID alone."
    )


def test_a_command_the_manifest_lacks_says_so():
    commands = appendices.commands(report(r.load("m5-laptop")), {"C1": "/usr/bin/sw_vers"})
    assert commands[0].template == "/usr/bin/sw_vers"
    assert {command.template for command in commands[1:]} == {
        "(not in the manifest of voltry-mac 0.1.0)"
    }


def test_the_appendices_read_no_clock_file_process_or_network():
    tree = ast.parse(Path(appendices.__file__).read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
    assert imported <= {"__future__", "collections.abc", "dataclasses", "typing", "voltry_mac"}
