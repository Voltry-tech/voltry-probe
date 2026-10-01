"""The report's PDF: its pages, laid out by layout.py and written by pdf.py.

docs/VOLTRY_MAC_SPEC.md, "Report outline and PDF layout", Decision 4 (the metadata, and the
PDF as a pure function of the JSON and the renderer version), Decision 6 and the field
inventory. Page 1 holds the title block, At a glance and what the report cannot tell you;
page 2 This Mac, Security settings, System records and Storage health and wear; page 3
Battery and Memory; page 4 the Power and thermal check with its sample table and bar chart;
the two appendices follow. The words are sections.py's, details.py's and appendices.py's,
as the terminal's are, with the rows the field inventory prints in the PDF alone. Every
value shows its provenance chip, or, when it is unavailable or not applicable, an
availability chip, and a number keeps its unit on its line. Pure: the bytes are a function
of the report document, the producing version's command templates, RENDERER and the package
version drawing the PDF, which prints only when it is not the version that made the report
(Failure modes' render row), so a report drawn by its own version is the same bytes on
every run.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from decimal import ROUND_HALF_UP, Context, Decimal, localcontext
from typing import Final

from voltry_mac import appendices, details, layout, pdf, phrases, sections, wording

# The version of this renderer, recorded in every report JSON; it moves whenever the PDF
# bytes for a fixed input change (Release plan, Versioning), and the goldens move with it.
RENDERER: Final = "1"
# Spike MAC 2.4 (#311): the plain content streams fit the size budget, so the pages are not
# compressed and the bytes do not depend on the zlib build.
COMPRESS: Final = False

TITLE: Final = layout.Style(pdf.HELVETICA_BOLD, 16, 22, layout.GREEN)
GLANCE_LABEL: Final = 70.0
DETAIL_LABEL: Final = 130.0
APPENDIX_LABEL: Final = 140.0
CHART_HEIGHT: Final = 60.0
SPACE: Final = layout.BODY.leading / 2

_EXACT: Final = Context(prec=60, rounding=ROUND_HALF_UP)
_NOT_REPORTED: Final = phrases.NOT_REPORTED[0].upper() + phrases.NOT_REPORTED[1:]
_NBSP: Final = " "
# A space between a number and a unit the report prints after it.
_UNIT: Final = re.compile(r"(?<=[0-9]) (?=(?:TB|PB|GB|MB|B|W|°C|K|mAh|ms|bytes)(?![A-Za-z0-9]))")

# Each table's columns: title, share of the body's width, right-aligned, Courier.
Spec = tuple[str, float, bool, bool]
_SAMPLES: Final[tuple[Spec, ...]] = (
    ("Sample", 0.10, False, False),
    ("Seconds", 0.12, True, False),
    ("Thermal pressure", 0.19, False, False),
    ("CPU W", 0.13, True, False),
    ("GPU W", 0.13, True, False),
    ("Neural Engine W", 0.18, True, False),
    ("Combined W", 0.15, True, False),
)
_TRIED: Final[tuple[Spec, ...]] = (
    ("Item", 0.21, False, False),
    ("Result", 0.20, False, True),
    ("How it is read", 0.32, False, False),
    ("Why not read", 0.27, False, False),
)
_RAN: Final[tuple[Spec, ...]] = (
    ("ID", 0.08, False, True),
    ("Runs", 0.08, True, False),
    ("Failed", 0.09, True, False),
    ("Time", 0.13, True, False),
    ("Command", 0.62, False, True),
)


def tied(text: str) -> str:
    """text with a no-break space between each number and the unit after it, so a line
    never ends between them."""
    return _UNIT.sub(_NBSP, text)


def _chip(chip: str | None, availability: str = "available") -> layout.Chip | None:
    """A provenance chip for an available value; an availability chip, in its own color,
    for one that is not."""
    if availability == "not_applicable":
        return layout.Chip(appendices.NOT_APPLICABLE, layout.UNAVAILABLE)
    if availability == "unavailable":
        return layout.Chip(appendices.UNAVAILABLE, layout.UNAVAILABLE)
    return None if chip is None else layout.Chip(chip)


def _row(row: details.Row, source: str | None = None) -> layout.Row:
    availability = "unavailable" if row.unavailable else "available"
    return layout.Row(
        row.label, tied(row.text), _chip(row.chip, availability), row.notes, source=source
    )


def _columns(width: float, spec: Sequence[Spec]) -> list[layout.Column]:
    """Columns filling width, each its share of the whole spec."""
    whole = sum(share for _, share, _, _ in spec)
    return [
        layout.Column(title, share / whole * width, right=right, mono=mono)
        for title, share, right, mono in spec
    ]


def _table(made: layout.Composer, spec: Sequence[Spec], rows: Sequence[Sequence[str]]) -> None:
    made.table(_columns(made.width, spec), [[tied(cell) for cell in row] for row in rows])


# --- page 1 ----------------------------------------------------------------------------------


def _title_block(made: layout.Composer, report: phrases.Report, version: str) -> None:
    *who, report_id = sections.identity(report)
    made.lines(wording.TITLE, TITLE)
    made.lines(wording.DISCLAIMER)
    made.space(SPACE)
    made.lines(" ".join(who))
    made.lines(f"{report_id}, voltry-mac {version}", layout.MONO)
    made.lines(" ".join(sections.collection(report)))
    unexpected = phrases.unexpected(report)
    if unexpected:
        made.lines(unexpected)
    made.lines(f"Administrator reads: {sections.elevation(report)}")
    made.lines(sections.validated(report))


def _glance(made: layout.Composer, report: phrases.Report) -> None:
    made.heading(wording.SECTIONS[0])
    made.rows(
        [
            layout.Row(entry.topic, tied(entry.text), _chip(entry.chip, entry.availability))
            for entry in sections.glance(report)
        ],
        label_width=GLANCE_LABEL,
    )
    made.heading(wording.SECTIONS[1])
    made.bullets(sections.limits(report))


# --- pages 2 to 4 ----------------------------------------------------------------------------


def _heading(made: layout.Composer, section: details.Section) -> None:
    title = section.title + (f" {section.subtitle}" if section.subtitle else "")
    made.heading(title, section.source)


def _section(made: layout.Composer, section: details.Section, *notes: str) -> None:
    """A detail section: its heading and source line, its rows (a source line inside it
    set above the row it names), or its one line when it has no rows, then its notes."""
    _heading(made, section)
    if section.text is not None:
        chip = _chip(None, section.availability)
        made.rows([layout.Row("", tied(section.text), chip)], label_width=DETAIL_LABEL)
    else:
        rows, source = [], None
        for item in section.items:
            if isinstance(item, details.Source):
                source = item.text
                continue
            rows.append(_row(item, source))
            source = None
        made.rows(rows, label_width=DETAIL_LABEL)
    for note in (section.note, *notes):
        if note is not None:
            made.lines(note, layout.NOTE)


def _seconds(nanoseconds: object) -> str:
    """A sample's length, stored in nanoseconds, printed in seconds to the millisecond."""
    with localcontext(_EXACT):
        return phrases.decimal(Decimal(int(str(nanoseconds))).scaleb(-9), 3)


def _series(report: phrases.Report, name: str) -> list[object] | None:
    found = report.get("power_and_thermal_samples", name)
    return found if isinstance(found, list) else None


def _watts(report: phrases.Report, kind: str, count: int) -> list[str]:
    """A power series as watts, each sample at the precision Decision 6 gives the row that
    sums it up, decided on the lowest, highest and average, so a sample prints as the row
    does."""
    key = "power_and_thermal_samples"
    series = _series(report, f"sample_{kind}_power_mw")
    low, high, mean = (report.decimal(key, f"{kind}_power_mw_{stat}") for stat in _STATS)
    if series is None or low is None or high is None or mean is None:
        return [_NOT_REPORTED] * count
    values = [Decimal(str(value)) for value in series]
    return phrases.watts(values, phrases.watt_places([low, high, mean]))


_STATS: Final = ("min", "max", "mean")


def _samples(made: layout.Composer, report: phrases.Report) -> None:
    """Page 4's sample table and the bar chart of combined power per sample."""
    count = report.number("power_and_thermal_samples", "sample_count") or 5
    elapsed = _series(report, "sample_elapsed_ns")
    pressure = _series(report, "sample_thermal_pressure")
    cpu, gpu, ane, combined = (
        _watts(report, kind, count) for kind in ("cpu", "gpu", "ane", "combined")
    )
    rows = [
        [
            str(index + 1),
            _NOT_REPORTED if elapsed is None else _seconds(elapsed[index]),
            _NOT_REPORTED if pressure is None else report.shown(str(pressure[index])),
            cpu[index],
            gpu[index],
            ane[index],
            combined[index],
        ]
        for index in range(count)
    ]
    made.lines(
        f"The {count} samples: each length measured, each thermal pressure and power as "
        "macOS reports it.",
        layout.NOTE,
    )
    _table(made, _SAMPLES, rows)
    values = _series(report, "sample_combined_power_mw")
    if values is None:
        return
    made.space(SPACE)
    made.lines("Combined processor power per sample", layout.NOTE)
    made.chart(
        [
            layout.Bar(f"Sample {index + 1}", Decimal(str(value)), tied(f"{combined[index]} W"))
            for index, value in enumerate(values)
        ],
        height=CHART_HEIGHT,
    )


def _power(made: layout.Composer, report: phrases.Report) -> None:
    """Page 4: the check's rows and macOS's own warning level, which prints whether or not
    the check ran, under its own source line; then the samples, the chart, which of the
    values are estimates, and the fixed note."""
    section = details.power(report)
    warning = _row(details.warning_level(report), WARNING_SOURCE)
    _heading(made, section)
    if section.text is not None:
        chip = _chip(None, section.availability)
        made.rows([layout.Row("", tied(section.text), chip), warning], label_width=DETAIL_LABEL)
        return
    rows = [_row(item) for item in section.items if isinstance(item, details.Row)]
    made.rows([*rows, warning], label_width=DETAIL_LABEL)
    made.space(SPACE)
    _samples(made, report)
    total = report.number("power_and_thermal_samples", "sample_count") or 5
    made.lines(details.power_labels(total), layout.NOTE)
    made.lines(wording.FIXED_NOTES["power_and_thermal"], layout.NOTE)


# pmset -g therm (C8), not the power sample the rows above it come from.
WARNING_SOURCE: Final = "from macOS's thermal warning (pmset)"


# --- the appendices --------------------------------------------------------------------------

_AVAILABILITY: Final = {
    None: "available",
    appendices.UNAVAILABLE: "unavailable",
    appendices.NOT_APPLICABLE: "not_applicable",
}


def _appendix_a(made: layout.Composer, report: phrases.Report) -> None:
    made.heading(wording.SECTIONS[-2])
    _table(made, _TRIED, [[t.name, t.result, t.how, t.why] for t in appendices.tried(report)])
    made.heading("Other values")
    made.rows(
        [
            layout.Row(
                value.label,
                tied(value.text),
                _chip(value.chip, _AVAILABILITY[value.availability]),
            )
            for value in appendices.values(report)
        ],
        label_width=APPENDIX_LABEL,
    )


def _appendix_b(
    made: layout.Composer,
    report: phrases.Report,
    templates: Mapping[str, str] | None,
    replaced: int,
    version: str,
    drawn_by: str | None,
) -> None:
    made.heading(wording.SECTIONS[-1])
    lines = appendices.made(report, renderer=RENDERER, replaced=replaced, drawn_by=drawn_by)
    made.rows(
        [layout.Row(line.label, tied(line.text), mono=line.mono, wide=line.wide) for line in lines],
        label_width=APPENDIX_LABEL,
    )
    made.heading("Commands")
    ran = appendices.commands(report, templates)
    if templates is None:
        made.lines(appendices.unknown_templates(version), layout.NOTE)
        _table(made, _RAN[:-1], [[c.id, c.runs, c.failed, c.time] for c in ran])
        return
    _table(made, _RAN, [[c.id, c.runs, c.failed, c.time, c.template] for c in ran])


# --- the document ----------------------------------------------------------------------------


def _paper(document: Mapping[str, object]) -> tuple[float, float]:
    render = document["render"]
    assert isinstance(render, Mapping)  # noqa: S101 - a validated document
    return pdf.A4 if render["paper"] == "a4" else pdf.LETTER


def _version(document: Mapping[str, object]) -> str:
    """The version that made the report: the footer's, /Producer's and Appendix B's."""
    tool = document["tool"]
    assert isinstance(tool, Mapping)  # noqa: S101 - a validated document
    return str(tool["version"])


def compose(
    document: Mapping[str, object],
    templates: Mapping[str, str] | None,
    *,
    replaced: int = 0,
    drawn_by: str | None = None,
) -> layout.Composer:
    """The report's pages, finished; replaced is the count Appendix B prints, and drawn_by
    the package version drawing them, None for the version that made the report. A drawing
    version that is not a version is refused before any page is laid out. The report is
    read the PDF's way: every character kept, for the encoder to print or count."""
    report = phrases.Report(document, pdf=True)
    version = _version(document)
    drawn_by = appendices.drawing(version, drawn_by)
    report_id = str(document["report_id"]).removeprefix("sha256:")
    made = layout.Composer(
        _paper(document),
        header=f"{wording.TITLE}, {sections.model(report)}",
        keep=f", ID {report_id[:12]}",
        version=f"voltry-mac {version}",
    )
    _title_block(made, report, version)
    _glance(made, report)
    made.page_break()
    _section(made, details.this_mac(report))
    _section(made, details.security(report))
    _section(made, details.system_records(report, full=True))
    _section(made, details.storage(report, full=True), wording.FIXED_NOTES["storage"])
    made.page_break()
    battery = details.battery(report, full=True)
    _section(made, battery, *([] if battery.text else [wording.FIXED_NOTES["battery"]]))
    _section(made, details.memory(report), wording.FIXED_NOTES["memory"])
    made.page_break()
    _power(made, report)
    made.page_break()
    _appendix_a(made, report)
    _appendix_b(made, report, templates, replaced, version, drawn_by)
    made.finish()
    return made


def render(
    document: Mapping[str, object],
    templates: Mapping[str, str] | None,
    *,
    drawn_by: str | None = None,
) -> bytes:
    """The PDF of a validated report document: the same document, templates, RENDERER and
    drawing version give the same bytes. drawn_by is the package version drawing it, named
    in Appendix B and /Producer only when it is not the version that made the report.
    Appendix B counts the characters printed as "?", so the pages are composed once to
    count them and again to print the count."""
    made = compose(document, templates, drawn_by=drawn_by)
    if made.replaced:
        counted = made.replaced
        made = compose(document, templates, replaced=counted, drawn_by=drawn_by)
        if made.replaced != counted:  # pragma: no cover - the count line is ASCII
            raise RuntimeError("the replaced count changed between compositions")
    report_id = str(document["report_id"]).removeprefix("sha256:")
    return pdf.document(
        made.pages,
        title=wording.TITLE,
        producer=f"voltry-mac {appendices.drawing(_version(document), drawn_by)}",
        created=pdf.creation_date(str(document["collected_at_local"])),
        identifier=bytes.fromhex(report_id),
        compress=COMPRESS,
    )
