"""The fixed honesty copy (docs/VOLTRY_MAC_SPEC.md, "Fixed notes (exact copy, pinned by
tests)", Decision 6's section order, and the title block).

The report model hands every renderer the same fixed strings, so the terminal, the PDF
and a later render say exactly the same thing. The notes are the spec's words, pinned here
literally; tests/ci/test_voltry_mac_spec_wording.py in core compares them with the spec.
"""

from __future__ import annotations

from voltry_mac import wording


def test_the_title_and_the_line_under_it():
    assert wording.TITLE == "Mac hardware observation report"
    assert (
        wording.DISCLAIMER == "Point-in-time observations, not a diagnosis, grade or certificate."
    )


def test_the_four_fixed_notes_are_the_specs_words():
    assert dict(wording.FIXED_NOTES) == {
        "memory": (
            "These numbers come from a private Apple log that is not documented. Apple does "
            "not say how long it keeps records, or which Macs keep them. Zero means none are "
            "recorded there now. It does not mean the memory has never had an error. Macs "
            "offer no public memory error counter."
        ),
        "storage": (
            "Endurance used is the SSD controller's own estimate, not a prediction of "
            "remaining life. Unsafe shutdowns count sudden power losses the drive saw; they "
            "are not proof of damage. Zero media errors means the controller reports none, "
            "not that the storage is perfect."
        ),
        "battery": (
            "Maximum capacity is macOS's own figure. The gauge readings in mAh move with "
            "temperature and recent use."
        ),
        "power_and_thermal": (
            "A 5-second look while the Mac did its usual background work. macOS estimates "
            "these values. They are not wall power, not a stress test, and not comparable "
            "between Macs."
        ),
    }


def test_the_sections_come_in_decision_6s_order():
    assert wording.SECTIONS == (
        "At a glance",
        "What this report cannot tell you",
        "This Mac",
        "Security settings",
        "System records",
        "Storage health and wear",
        "Battery",
        "Memory",
        "Power and thermal check",
        "Appendix A: everything this report tried to read",
        "Appendix B: how this report was made",
    )
    assert (
        wording.SECTIONS.index("What this report cannot tell you") == 1
    ), "the limits come right after At a glance, before every detail section"


def test_the_copy_is_plain_ascii_with_no_dash_of_either_kind():
    for text in (
        wording.TITLE,
        wording.DISCLAIMER,
        *wording.FIXED_NOTES.values(),
        *wording.SECTIONS,
    ):
        assert text.isascii() and "\u2013" not in text and "\u2014" not in text
