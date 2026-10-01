"""`voltry-mac render` and the command manifests (docs/VOLTRY_MAC_SPEC.md, Decision 4's
render rules and Test strategy part 1's command manifest fixtures).

render rebuilds a PDF from a saved JSON and never collects anything: it reads the file
strictly (a 4 MiB cap, no duplicate keys, nesting at most 32 deep), validates it against
the normative schema before anything else, refuses a report ID that does not recompute,
prints the local time the JSON recorded, and prints each command's fixed template from the
manifest of the version that produced the report, or the IDs alone with a note when that
version is newer than any manifest the package knows, never a template from another
version. A released version's manifest is kept forever, unchanged. A PDF drawn by another
version than the one that made the report names both (Failure modes' render row); drawn by
the same version, it is the tool's own PDF, byte for byte. Saving and opening the PDF are
the output writer's (MAC 3.10), which gets the validated document with it.
"""

from __future__ import annotations

import ast
import dataclasses
import hashlib
import io
import json
import re
import time
from collections.abc import Mapping
from pathlib import Path

import pypdf
import pytest
import voltry_mac_test_pdf_goldens as goldens
import voltry_mac_test_reports as r

import voltry_mac
from voltry_mac import allowlist, canonical, manifests, render, report_pdf

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "reports"
CHANGELOG = Path(__file__).resolve().parents[1] / "CHANGELOG.md"
# The saved JSON of each golden, indented for reading; the tool writes the canonical form,
# which each golden is drawn from too. The fixtures say version 0.1.0.
SAVED = ("m5-laptop", "concerning-desktop", "m5-laptop-declined-a4")
MADE_BY = "0.1.0"
# The versions a release walks through: a development build, the release commit and the
# next development build. A test that takes `running` runs at each, so none depends on
# today's version string.
WALK = ("0.1.0.dev0", "0.1.0", "0.1.1.dev0")


@pytest.fixture(params=WALK)
def running(request, monkeypatch):
    """The package running at one version of a release's walk."""
    monkeypatch.setattr(manifests, "__version__", request.param)
    monkeypatch.setattr(render, "__version__", request.param)
    return request.param


def saved(name: str) -> bytes:
    return (FIXTURES / f"{name}.json").read_bytes()


def pdf_of(data: bytes) -> bytes:
    return render.render(data).pdf


def text_of(data: bytes) -> str:
    reader = pypdf.PdfReader(io.BytesIO(data), strict=True)
    return " ".join(
        " ".join(page.extract_text().replace(" ", " ").split()) for page in reader.pages
    )


def written(document: dict) -> bytes:
    return canonical.canonical_json(document).encode("ascii")


# --- the manifests ---------------------------------------------------------------------------


def test_the_running_version_uses_its_own_allow_list(running):
    found = manifests.templates(running)
    assert found == {
        command.id: allowlist.display(command.template) for command in allowlist.COMMANDS
    }


def test_the_version_being_built_has_its_manifest_and_it_is_the_allow_lists():
    # Each release ships the manifest of its own version: a version bump without one, or
    # an allow-list change without a new version, fails here.
    assert manifests.RELEASED[_base(voltry_mac.__version__)] == manifests.templates(
        voltry_mac.__version__
    )


def _base(version: str) -> str:
    found = re.match(r"[0-9]+\.[0-9]+\.[0-9]+", version)
    assert found is not None
    return found.group()


# Each released version's manifest, by the SHA-256 of its sorted JSON. A pin never moves
# once its voltry-mac-vX.Y.Z tag exists; 0.1.0's may move until that tag, with the
# allow-list, and never after.
PINNED = {"0.1.0": "ce2bf0721f2850fa20f346e60a74d40c5c1f544e8923d5c9dc20daa4b9866de2"}


def _digest(manifest: object) -> str:
    return hashlib.sha256(json.dumps(dict(manifest), sort_keys=True).encode()).hexdigest()


def _kept(released: Mapping[str, Mapping[str, str]], pinned: Mapping[str, str] = PINNED) -> None:
    """Fails unless every manifest is its pin's and every pin has its manifest."""
    assert set(released) == set(pinned), sorted(set(released) ^ set(pinned))
    for version, manifest in released.items():
        assert _digest(manifest) == pinned[version], version


def test_every_released_manifest_is_kept_as_released():
    # A released version's manifest never changes and is never dropped; a new allow-list
    # ships with a new version and its own pin.
    _kept(manifests.RELEASED)


NEVER = "9.9.9"  # a version this package never releases and never pins
CHANGES = ["changed", "dropped", "added"]


def _changed(released: Mapping[str, Mapping[str, str]], change: str) -> dict:
    changed = dict(released)
    if change == "changed":
        changed["0.1.0"] = dict(changed["0.1.0"], C1="/usr/bin/sw_vers -productVersion")
    elif change == "dropped":
        del changed["0.1.0"]
    else:
        # A version no release can have, so the case holds after every release too: at
        # 0.1.1.dev0 with no command changed, 0.1.1's manifest is 0.1.0's (the #353
        # review, round 3).
        changed[NEVER] = changed["0.1.0"]
    return changed


@pytest.mark.parametrize("change", CHANGES)
def test_a_changed_dropped_or_unpinned_manifest_fails_the_pins(change):
    with pytest.raises(AssertionError):
        _kept(_changed(manifests.RELEASED, change))


def _state(version: str) -> tuple[dict, dict, str]:
    """The manifests, pins and CHANGELOG as one commit of 0.1.0's release holds them: before
    its tag, at its release commit, or at the next development version, where with no
    command changed 0.1.1's manifest is 0.1.0's."""
    manifest = dict(manifests.RELEASED["0.1.0"])
    released = {"0.1.0": manifest}
    changelog = "# Changelog\n\n## [Unreleased]\n"
    if version != "0.1.0.dev0":
        changelog += "\n## [0.1.0] - 2026-10-01\n"
    if version == "0.1.1.dev0":
        released["0.1.1"] = dict(manifest)
    pinned = {each: _digest(found) for each, found in released.items()}
    return released, pinned, changelog


@pytest.mark.parametrize("version", WALK)
def test_each_state_of_a_release_passes_every_check_and_still_catches_a_change(version):
    # Version, manifest, pin and CHANGELOG heading together, as each commit of a release
    # holds them: no check goes red on the way, and none stops catching a change (the
    # #353 review, round 3).
    released, pinned, changelog = _state(version)
    _kept(released, pinned)
    _listed(changelog, released, version, pinned)
    for change in CHANGES:
        with pytest.raises(AssertionError):
            _kept(_changed(released, change), pinned)


# A released version's CHANGELOG heading, like the probe's "## [0.3.3] - 2026-09-25", the
# form the CHANGELOG's introduction states. A heading that names a version in any other
# form, at any level, is refused rather than skipped, and a fenced example is not a
# heading (the #353 review, round 3).
RELEASE_HEADING = re.compile(r"## \[([0-9]+\.[0-9]+\.[0-9]+)\] - [0-9]{4}-[0-9]{2}-[0-9]{2}")
HEADING_FORM = "## [X.Y.Z] - YYYY-MM-DD"
VERSION_LIKE = re.compile(r"[0-9]+\.[0-9]+")


def _releases(changelog: str) -> set[str]:
    listed: set[str] = set()
    fence = ""
    for line in changelog.splitlines():
        text = line.lstrip(" ")
        if fence:
            if text.startswith(fence):
                fence = ""
            continue
        if text.startswith(("```", "~~~")):
            fence = text[:3]
        elif text.startswith("#"):
            found = RELEASE_HEADING.fullmatch(line)
            if found is not None:
                listed.add(found.group(1))
            else:
                assert not VERSION_LIKE.search(line), f"not in the form {HEADING_FORM}: {line!r}"
    assert not fence, "a fence the CHANGELOG never closes"
    return listed


def _listed(
    changelog: str,
    released: Mapping[str, object],
    version: str,
    pinned: Mapping[str, str] = PINNED,
) -> None:
    """Fails unless every release the CHANGELOG lists has its manifest and its pin, and
    every manifest but the draft of the version being built has its release listed."""
    listed = _releases(changelog)
    assert listed <= set(released), sorted(listed - set(released))
    assert listed <= set(pinned), sorted(listed - set(pinned))
    assert set(released) - listed <= {_base(version)}, sorted(set(released) - listed)


@pytest.mark.parametrize(
    "heading",
    [
        "## 0.1.0 - 2026-10-01",
        "## [v0.1.0] - 2026-10-01",
        "## [0.1.0rc1] - 2026-10-01",
        "## [0.1.0]",
        "## [0.1.0] - 2026-10-01 ",
        "##\t[0.1.0] - 2026-10-01",
        "### [0.1.0] - 2026-10-01",
        "  ## [0.1.0] - 2026-10-01",
    ],
)
def test_a_release_heading_in_another_form_is_refused(heading):
    with pytest.raises(AssertionError, match="not in the form"):
        _releases(f"# Changelog\n\n## [Unreleased]\n\n{heading}\n")


def test_a_heading_without_a_version_is_not_a_release():
    changelog = "# Changelog\n\n## [Unreleased]\n\n### Added\n\n## Notes\n"
    assert _releases(changelog) == set()


@pytest.mark.parametrize("fence", ["```", "~~~", "  ````"])
def test_a_fenced_example_is_not_a_release(fence):
    example = f"{fence}\n## [9.9.9] - 2026-10-01\n## 9.9.9\n{fence}\n"
    assert _releases(f"## [Unreleased]\n\n{example}\n## [0.1.0] - 2026-10-01\n") == {"0.1.0"}
    with pytest.raises(AssertionError, match="never closes"):
        _releases(f"## [Unreleased]\n\n{fence}\n## [0.1.0] - 2026-10-01\n")


def test_the_changelog_states_its_heading_form():
    introduction = CHANGELOG.read_text(encoding="utf-8").split("## [Unreleased]")[0]
    assert f"`{HEADING_FORM}`" in introduction


def test_every_release_the_changelog_lists_keeps_its_manifest_and_its_pin():
    # A manifest dropped together with its pin still leaves its release in the CHANGELOG.
    _listed(CHANGELOG.read_text(encoding="utf-8"), manifests.RELEASED, voltry_mac.__version__)


@pytest.mark.parametrize(
    ("changelog", "released", "version"),
    [
        ("## [0.1.0] - 2026-10-01\n", {}, "0.1.1.dev0"),
        ("## [0.1.0] - 2026-10-01\n## [0.0.9] - 2026-09-01\n", {"0.1.0": {}}, "0.1.1.dev0"),
        ("## [Unreleased]\n", {"0.0.9": {}, "0.1.0": {}}, "0.1.0.dev0"),
    ],
    ids=["a listed release dropped", "an older release dropped", "an unlisted manifest"],
)
def test_a_release_and_its_manifest_are_dropped_only_together(changelog, released, version):
    with pytest.raises(AssertionError):
        _listed(changelog, released, version)


def test_the_draft_manifest_needs_no_heading_until_its_release():
    _listed("## [Unreleased]\n", {"0.1.0": {}}, "0.1.0.dev0")
    _listed("## [Unreleased]\n## [0.1.0] - 2026-10-01\n", {"0.1.0": {}}, "0.1.0")


def test_a_manifest_names_every_command_a_report_can_record():
    for version, manifest in manifests.RELEASED.items():
        recorded = set(r.ORDER)  # the 37 IDs a record can name; a report holds at most 34
        assert recorded <= set(manifest), version
        assert all(isinstance(template, str) and template for template in manifest.values())


def test_no_manifest_carries_an_interpreter_path_or_an_output_path():
    for manifest in manifests.RELEASED.values():
        for template in manifest.values():
            assert "/python" not in template.lower()
            assert "/Desktop/" not in template and "/Users/" not in template


def test_an_unknown_version_has_no_templates(running):
    assert manifests.templates("0.9.0") is None
    assert manifests.templates("0.1.0.dev1") is None


NEIGHBORS = ["0.1", "0.1.0.0", "0.1.0.post1", "0.1.0rc1", "0.1.0.dev3", "1!0.1.0", "0.1.1"]


def test_a_version_is_matched_exactly_never_by_its_neighbor(monkeypatch):
    # The released manifests' branch alone: with the running version set apart from all of
    # these, the test holds at every version a release walks through. The next test takes
    # the running version's branch, at a release.
    monkeypatch.setattr(manifests, "__version__", "9.9.9.dev0")
    monkeypatch.setattr(manifests, "RELEASED", {"0.1.0": {"C1": "old"}})
    assert manifests.templates("0.1.0") == {"C1": "old"}
    for version in NEIGHBORS:
        assert manifests.templates(version) is None, version


def test_the_running_version_is_matched_exactly_too(monkeypatch):
    # As at a release, when the running version is a final one.
    monkeypatch.setattr(manifests, "__version__", "0.1.0")
    monkeypatch.setattr(manifests, "RELEASED", {})
    assert manifests.templates("0.1.0") is not None
    for version in NEIGHBORS:
        assert manifests.templates(version) is None, version


def test_the_manifests_cannot_be_changed_at_run_time():
    with pytest.raises(TypeError):
        manifests.RELEASED["9.9.9"] = {}  # type: ignore[index]
    for manifest in manifests.RELEASED.values():
        with pytest.raises(TypeError):
            manifest["C1"] = "x"  # type: ignore[index]
        with pytest.raises(TypeError):
            del manifest["C1"]  # type: ignore[attr-defined]


def test_the_goldens_take_the_0_1_0_manifest_at_every_version(monkeypatch, running):
    # At exactly 0.1.0 the lookup takes the running allow-list; the goldens take 0.1.0's
    # manifest whatever the allow-list holds, so an allow-list edit never moves them.
    monkeypatch.setattr(manifests.allowlist, "display", lambda template: "edited")
    assert goldens.templates() == dict(manifests.RELEASED["0.1.0"])


# --- render ----------------------------------------------------------------------------------


@pytest.fixture
def at_0_1_0(monkeypatch):
    """The package draws the PDF as 0.1.0, the version the fixtures say made them, so the
    PDF is the tool's own. Only the drawing version is set: the templates stay 0.1.0's
    manifest, which at the release is the running allow-list (the manifest tests pin the
    two together). Setting the running version to 0.1.0 too would take whatever allow-list
    is current, and after the release that may be another one."""
    monkeypatch.setattr(render, "__version__", MADE_BY)


def test_each_saved_golden_holds_its_document():
    for name in SAVED:
        assert canonical.load(saved(name)) == goldens.DOCUMENTS[name](), name


@pytest.mark.parametrize("name", SAVED)
def test_a_saved_report_renders_to_its_golden_bytes(name, at_0_1_0):
    assert pdf_of(saved(name)) == goldens.render(name)


@pytest.mark.parametrize("name", SAVED)
def test_each_report_as_written_by_the_tool_renders_the_same(name, at_0_1_0):
    document = goldens.DOCUMENTS[name]()
    assert pdf_of(written(document)) == goldens.render(name)


def test_render_gives_the_validated_document_with_the_pdf():
    rendered = render.render(saved("m5-laptop"))
    assert rendered.document == r.load("m5-laptop")
    assert rendered.pdf.startswith(b"%PDF-1.4")


def test_the_rendered_pair_is_never_rebound():
    rendered = render.render(saved("m5-laptop"))
    with pytest.raises(dataclasses.FrozenInstanceError):
        rendered.pdf = b""  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        rendered.document = {}  # type: ignore[misc]


def test_a_report_carrying_the_running_version_renders_to_the_tools_own_pdf(running):
    # A report the running tool wrote: its own allow-list's templates and no note.
    document = r.load("m5-laptop")
    document["tool"]["version"] = running
    document = r.rehash(document)
    own = report_pdf.render(document, manifests.templates(running))
    assert pdf_of(written(document)) == own
    assert "This PDF was drawn by" not in text_of(own)


def test_a_report_from_another_version_names_both(monkeypatch, running):
    # Failure modes, render row: "A line naming both versions"; /Producer names the
    # version that drew the file.
    document = r.load("m5-laptop")
    document["tool"]["version"] = "0.0.9"
    monkeypatch.setattr(
        manifests, "RELEASED", {**manifests.RELEASED, "0.0.9": manifests.RELEASED["0.1.0"]}
    )
    data = pdf_of(written(r.rehash(document)))
    said = text_of(data)
    assert (
        f"This PDF was drawn by voltry-mac {running}, renderer 1; the report "
        "was made by voltry-mac 0.0.9, renderer 1, so this file may differ from the original "
        "PDF."
    ) in said
    info = pypdf.PdfReader(io.BytesIO(data), strict=True).metadata
    assert info["/Producer"] == f"voltry-mac {running}"


def test_an_older_version_prints_its_own_templates(monkeypatch):
    document = r.load("m5-laptop")
    document["tool"]["version"] = "0.0.9"
    older = dict(manifests.RELEASED["0.1.0"])
    older["C1"] = "/usr/bin/sw_vers -productVersion"
    monkeypatch.setattr(manifests, "RELEASED", {**manifests.RELEASED, "0.0.9": older})
    said = text_of(pdf_of(written(r.rehash(document))))
    assert "/usr/bin/sw_vers -productVersion" in said
    assert "does not know the command templates" not in said


def test_a_newer_version_prints_the_ids_alone_with_the_note(running):
    document = r.load("m5-laptop")
    document["tool"]["version"] = "0.9.0"
    said = text_of(pdf_of(written(r.rehash(document))))
    assert (
        "This renderer does not know the command templates of voltry-mac 0.9.0, so the "
        "commands are listed by ID alone." in said
    )
    assert f"This PDF was drawn by voltry-mac {running}" in said
    assert "/usr/bin/sw_vers" not in said


def test_the_local_time_is_the_reports_never_the_machines(monkeypatch):
    before = pdf_of(saved("m5-laptop"))
    monkeypatch.setenv("TZ", "Asia/Tokyo")
    time.tzset()
    try:
        assert pdf_of(saved("m5-laptop")) == before
    finally:
        monkeypatch.undo()
        time.tzset()
    assert "23 Sep 2026, 14:05 (UTC-7)" in text_of(before)


@pytest.mark.parametrize(
    ("data", "said"),
    [
        (b"{" + b" " * (4 * 1024 * 1024) + b"}", "larger than the 4 MiB limit"),
        (b'{"schema": "voltry-mac-report/0", "schema": "voltry-mac-report/0"}', "schema"),
        (b"[" * 40 + b"]" * 40, "nested deeper than 32 levels"),
        (b'{"a": 1.5}', "a: a float is not allowed"),
        (b"not json", "not well-formed JSON"),
    ],
    ids=["past 4 MiB", "a duplicate key", "nested past 32", "a float", "not JSON"],
)
def test_an_unreadable_file_is_refused(data, said):
    with pytest.raises(canonical.Invalid) as refused:
        render.render(data)
    assert said in str(refused.value)


def test_another_schema_is_refused_with_its_field_named():
    document = r.load("m5-laptop")
    document["schema"] = "voltry-mac-report/1"
    with pytest.raises(canonical.Invalid, match=r"^schema: must be voltry-mac-report/0"):
        render.render(written(r.rehash(document)))


def test_a_report_id_that_does_not_recompute_is_refused():
    document = r.load("m5-laptop")
    document["surfaces"][0]["values"]["product_version"]["value"] = "26.6.3"
    with pytest.raises(canonical.Invalid, match=r"^report_id: "):
        render.render(written(document))


def test_a_refusal_names_the_field_never_its_value():
    document = r.load("m5-laptop")
    document["platform"]["validated"] = "SECRET-VALUE"
    with pytest.raises(canonical.Invalid) as refused:
        render.render(written(r.rehash(document)))
    assert "SECRET-VALUE" not in str(refused.value)
    assert refused.value.path == "platform.validated"


def test_render_collects_nothing_and_reads_no_clock_file_process_or_network():
    for module in (render, manifests):
        tree = ast.parse(Path(module.__file__).read_text())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {alias.name for alias in node.names}
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module or "")
                if node.module == "voltry_mac":
                    assert {alias.name for alias in node.names} <= {
                        "__version__",
                        "allowlist",
                        "manifests",
                        "report_pdf",
                        "validate",
                    }, module.__name__
        assert imported <= {
            "__future__",
            "collections.abc",
            "dataclasses",
            "types",
            "typing",
            "voltry_mac",
        }, module.__name__
