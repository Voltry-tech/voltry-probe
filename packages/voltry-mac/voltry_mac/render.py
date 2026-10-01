"""`voltry-mac render`: a saved report JSON back to its PDF, collecting nothing.

docs/VOLTRY_MAC_SPEC.md, Decision 4's render rules and Failure modes' render rows. The
file's bytes are read strictly (at most 4 MiB, no duplicate keys, nesting at most 32 deep)
and validated against the normative schema, relations and elevation records before anything
else, and a report ID that does not recompute is refused; a refusal names the field, never
its value (canonical.Invalid). The cap limits the bytes render is given: the render command
(MAC 3.10) reads at most one byte past it from the file, so a larger file is refused
without being read whole. The pages print what the JSON recorded, its local time included,
never the rendering machine's clock or zone; each command's template comes from the
manifest of the version that produced the report; and a PDF this package draws for a report
another version made names both versions. Saving and opening the PDF are the output
writer's (MAC 3.10), which gets the validated document with it. Pure: the file's bytes in,
the validated document and the PDF's bytes out.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from voltry_mac import __version__, manifests, report_pdf, validate


@dataclass(frozen=True)
class Rendered:
    """A saved report, read and validated, and its PDF. The document is the one validated,
    shared rather than copied: a caller reads it and never changes it, so the two always
    agree."""

    document: Mapping[str, object]
    pdf: bytes


def render(data: bytes) -> Rendered:
    """A saved report JSON's bytes, read and validated, and its PDF drawn by this
    package's version and renderer."""
    document = validate.read(data)
    tool = document["tool"]
    assert isinstance(tool, Mapping)  # noqa: S101 - a validated document
    templates = manifests.templates(str(tool["version"]))
    return Rendered(document, report_pdf.render(document, templates, drawn_by=__version__))
