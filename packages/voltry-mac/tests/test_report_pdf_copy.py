"""The report PDF's copy and privacy (docs/VOLTRY_MAC_SPEC.md, Decision 6's copy policy, the
Threat model's privacy row and the field inventory's "Read but never kept").

No page carries a verdict, a grade or score, a certificate, a price or resale figure or a
prediction of remaining life, outside the fixed lines that say what the report does not do,
and no page carries an em or en dash; checked over every legal elevation history and every
gap the terminal's tests build. And no identifier macOS returns reaches the PDF: a canary
planted in every key of the command outputs that carries a serial number, a UUID or a UDID,
at every depth, is found nowhere in the file, though the serial's last four characters are
the report's own.
"""

from __future__ import annotations

import copy
import io
import json
import plistlib
import re
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pypdf
import pytest
import voltry_mac_test_pdf_pages as pages
import voltry_mac_test_reports as r

from voltry_mac import assemble, model, payloads, report_pdf, spawn, validate, wording

T = pages.terminal_tests()
DOCUMENTS = list(T.DOCUMENTS) + [(f"gap {label}", document) for label, document in T.GAP_DOCUMENTS]
# The fixed lines that say what the report does not do: the only place the prohibited
# constructions appear.
FIXED = (
    wording.DISCLAIMER,
    *wording.FIXED_NOTES.values(),
    "Value or price. Voltry does not assess either.",
    "how it was used, or how long it will last.",
)


def _words(document: dict) -> str:
    made, _ = pages.composed(document)
    words = " ".join(pages.page_words(page) for page in made.pages)
    footers = " ".join(d.text for page in made.pages for d in pages.texts(page))
    return f"{words} {footers}"


@pytest.mark.parametrize(("label", "document"), DOCUMENTS, ids=[d[0] for d in DOCUMENTS])
def test_no_prohibited_construction_or_dash_on_any_page(label, document):
    said = _words(document)
    assert "–" not in said and "—" not in said
    for fixed in FIXED:
        said = said.replace(fixed, " ")
    for pattern in T.PROHIBITED:
        assert re.search(pattern, said, re.IGNORECASE) is None, (pattern, label)


@pytest.mark.parametrize(
    "rows",
    [
        [
            {"class": "correctable", "reported_count": 0},
            {"class": "uncorrectable", "reported_count": 0},
        ],
        [{"class": "correctable", "reported_count": 0}, {"class": "uncorrectable"}],
    ],
    ids=["the log's own counts", "one of them"],
)
def test_the_logs_own_zero_counts_make_no_clean_claim_on_the_page_or_in_the_terminal(rows):
    # S3's rows with no record counts and the log's own counts at 0 gave "counts 0
    # correctable and 0 uncorrectable errors" at a glance, on the page and in the terminal
    # alike (the pass-3 pre-audit, P3-output-02).
    values = assemble._elevated_values("memory_error_ledger", payloads.ledger(json.dumps(rows)))
    document = r.load("m5-laptop")
    document["surfaces"][r.index(document, "memory_error_ledger")] = model.surface_object(
        "memory_error_ledger", values
    )
    document = r.finish(document)
    said = _words(document)
    for fixed in FIXED:
        said = said.replace(fixed, " ")
    assert "macOS's private memory error log counts 0 correctable" in said
    for pattern in T.PROHIBITED:
        assert re.search(pattern, said, re.IGNORECASE) is None, pattern
    assert T.prohibited(T.summary(document)) == []


# --- privacy canaries --------------------------------------------------------------------------

TESTS = Path(__file__).resolve().parent
M5 = TESTS / "fixtures" / "commands" / "m5-laptop"
LOG_HEX = (TESTS / "fixtures" / "smart" / "m5-laptop-2026-09-26.hex").read_text().strip()
USER_IDS = [f"C{n}" for n in range(1, 10)] + [f"C{n}" for n in range(11, 29)]
IDENTIFYING = re.compile(r"serial|uuid|udid", re.IGNORECASE)
# A value shaped like a UUID is an identifier whatever its key is called: C11's
# APFSVolumeGroupID, for one (the #352 review, round 3).
UUID_SHAPED = re.compile(
    r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
)
# The outputs that carry identifiers: system_profiler's JSON (C2 to C6), ioreg's and
# diskutil's plists (C7, C11).
JSON_OUTPUTS = {"C2", "C3", "C4", "C5", "C6"}
PLIST_OUTPUTS = {"C7", "C11"}
SAMPLES = {
    "sample_elapsed_ns": [1006543000, 1011719875, 1008502124, 1011962250, 1011879791],
    "sample_thermal_pressure": ["Nominal"] * 5,
    "sample_cpu_power_mw": [Decimal(v) for v in ("2675.49", "2513.54", "1641.05", "566.227")]
    + [Decimal("665.099")],
    "sample_gpu_power_mw": [Decimal(v) for v in ("50.6685", "50.4092", "60.4857", "55.338")]
    + [Decimal("54.3543")],
    "sample_ane_power_mw": [Decimal("0")] * 5,
    "sample_combined_power_mw": [Decimal(v) for v in ("2726.16", "2563.95", "1701.53")]
    + [Decimal("621.565"), Decimal("719.453")],
}
LEDGER = dict.fromkeys(
    (
        "correctable_event_rows",
        "correctable_reported_count",
        "uncorrectable_event_rows",
        "uncorrectable_reported_count",
    ),
    0,
)


class Planter:
    """Plants one canary per identifying key, each ending in the same four characters, so
    only the serial's last four, which the report keeps, may appear."""

    def __init__(self) -> None:
        self.planted: dict[str, str] = {}

    def canary(self, key: str) -> str:
        found = f"CANARY{len(self.planted):03d}ZZZZ"
        self.planted[found] = key
        return found

    def plant(self, node: object) -> object:
        if isinstance(node, dict):
            for key, value in node.items():
                shaped = isinstance(value, str) and UUID_SHAPED.fullmatch(value) is not None
                if isinstance(value, str) and (IDENTIFYING.search(key) or shaped):
                    node[key] = self.canary(key)
                else:
                    self.plant(value)
        elif isinstance(node, list):
            for item in node:
                self.plant(item)
        return node


def _result(command_id: str, stdout: str) -> spawn.Result:
    return spawn.Result(command_id, spawn.Ending.EXITED, 0, stdout, "", 20, False, True)


def _planted_outputs(planter: Planter) -> dict[str, spawn.Result]:
    results = {}
    for command_id in USER_IDS[:-1]:
        text = (M5 / f"{command_id}.out").read_text()
        if command_id in JSON_OUTPUTS:
            text = json.dumps(planter.plant(json.loads(text)))
        elif command_id in PLIST_OUTPUTS:
            data = planter.plant(plistlib.loads(text.encode()))
            text = plistlib.dumps(data, fmt=plistlib.FMT_XML).decode()
        results[command_id] = _result(command_id, text)
    controller = {"location": "Internal", "media": ["disk0"], "status": "ok", "smart_hex": LOG_HEX}
    smart = {"schema": "voltry-mac-smart/0", "controllers": [controller]}
    results["C28"] = _result("C28", json.dumps(smart))
    return results


def _document(results: dict[str, spawn.Result]) -> dict:
    fixture = r.load("m5-laptop")
    collected = assemble.Collected(
        results=results,
        panic=0,
        ledger=assemble.Elevated(values=LEDGER),
        power=assemble.Elevated(values=SAMPLES),
        collected_at=datetime(2026, 9, 26, 12, 0, 0, tzinfo=UTC),
    )
    records = [
        {
            "id": command_id,
            "runs": 1,
            "failed_runs": int(assemble.failed_run(command_id, results[command_id])),
            "duration_ms": 20,
        }
        for command_id in USER_IDS
    ]
    elevated = [record for record in fixture["commands"] if record["id"][0] in "XPS"]
    document = model.document(
        tool=fixture["tool"],
        collected_at=collected.collected_at,
        time_zone="America/Los_Angeles",
        validated=True,
        elevation=fixture["elevation"],
        surfaces=assemble.surfaces(collected),
        commands=records + elevated,
        paper="letter",
    )
    validate.validate(document)
    return document


def test_privacy_canaries_planted_in_the_command_output_never_reach_the_pdf():
    planter = Planter()
    document = _document(_planted_outputs(planter))
    keys = set(planter.planted.values())
    # The plant reached the identifiers macOS really returns, not only keys no parser reads.
    for key in (
        "serial_number",
        "platform_UUID",
        "provisioning_UDID",
        "device_serial",
        "sppower_battery_serial_number",
    ):
        assert key in keys, key
    assert len(planter.planted) >= 8
    assert "APFSVolumeGroupID" in keys  # planted by its value's shape
    # The report keeps the serial's last four, and nothing else of any canary.
    serial = [value for value in document["surfaces"] if value["key"] == "hardware_overview"][0]
    assert serial["values"]["serial_last4"]["value"] == "ZZZZ"
    data = report_pdf.render(document, pages.templates())
    reader = pypdf.PdfReader(io.BytesIO(data), strict=True)
    said = " ".join(page.extract_text() for page in reader.pages)
    for canary in planter.planted:
        stem = canary[: -len("ZZZZ")]
        assert stem not in said, planter.planted[canary]
        assert stem.encode() not in data, planter.planted[canary]
    assert "ending in ZZZZ" in " ".join(said.split())


def test_the_canary_check_sees_a_canary_that_reaches_the_pdf():
    planter = Planter()
    document = _document(_planted_outputs(planter))
    leaked = copy.deepcopy(document)
    canary = next(iter(planter.planted))
    r.set_value(leaked, "nvme_devices", "device_revision", canary)
    leaked = r.finish(leaked)
    data = report_pdf.render(leaked, pages.templates())
    assert canary[: -len("ZZZZ")].encode() in data
