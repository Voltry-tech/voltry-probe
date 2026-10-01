"""What voltry-mac prints, in the stream's own encoding (docs/VOLTRY_MAC_SPEC.md, Failure
modes: "A failed read costs that one item, never the report"; console.py's own contract:
any other failure to write stdout is said once on stderr, and the exit code stays the
run's).

console.write hands its text to the stream's binary layer itself, checked by count (the GPT
audit, pass 2, G2-06; those tests are in test_run.py), so it encodes the text itself too.
It did that with str.encode at each write, outside the stream's own encoder: a stdout that
cannot spell the summary's degree sign, as an ASCII locale gives Python, raised, and the run
said it could not finish and saved nothing; and an encoding with a byte-order mark wrote one
at each write (the pass-3 pre-audit, P3-output-01). Now each stream keeps one encoder, as
its text layer keeps its own, and a character it cannot encode is replaced, which stdout
says once on stderr. Every run here is the fake M5 behind the real chokepoint, O1 included.
"""

from __future__ import annotations

import codecs
import errno
import io
import os
import sys
from pathlib import Path

import pytest
from voltry_mac_test_fake_mac import PDF_NAME, build, result

from voltry_mac import cli, console, run, terminal


@pytest.fixture
def mac(monkeypatch, tmp_path):  # type: ignore[no-untyped-def]
    return build(monkeypatch, tmp_path)


def _summaries(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """The terminal summaries the run prints, as terminal.summary gives them."""
    found: list[str] = []
    real = terminal.summary

    def summary(document):  # type: ignore[no-untyped-def]
        found.append(real(document))
        return found[-1]

    monkeypatch.setattr(terminal, "summary", summary)
    return found


# --- a stdout that cannot spell every character ---------------------------------------------


@pytest.mark.parametrize(
    ("encoding", "errors", "degrees", "said"),
    [
        ("ascii", "strict", "?", True),
        ("ascii", "backslashreplace", "\\xb0", False),
        ("latin-1", "strict", "\N{DEGREE SIGN}", False),
    ],
    ids=[
        "an ASCII locale",
        "PYTHONIOENCODING=ascii:backslashreplace",
        "a Latin-1 locale",
    ],
)
@pytest.mark.parametrize("write_through", [False, True], ids=["buffered", "python -u"])
def test_the_report_is_saved_whatever_stdout_can_spell(
    mac, monkeypatch, encoding, errors, degrees, said, write_through
):
    # LC_CTYPE=en_US.US-ASCII, one of the locales macOS ships, gives Python an "ascii strict"
    # stdout. The whole report still prints, a character it cannot spell replaced, and
    # stderr says once that it is not in full; the report is saved and the exit code is the
    # run's. The stream's own error handler, where it has one, is kept.
    summaries = _summaries(monkeypatch)
    out, err = io.BytesIO(), io.StringIO()
    stdout = io.TextIOWrapper(out, encoding=encoding, errors=errors, write_through=write_through)
    with monkeypatch.context() as patch:
        patch.setattr(sys, "stdout", stdout)
        patch.setattr(sys, "stderr", err)
        code = cli.main(["--no-root"])
    assert (code, mac.saved()) == (0, [PDF_NAME])
    assert err.getvalue() == (f"{console.INCOMPLETE}\n" if said else "")
    (summary,) = summaries
    shown = out.getvalue()
    assert summary.encode(encoding, "replace" if errors == "strict" else errors) in shown
    text = shown.decode(encoding)
    assert f"  Temperature now     57 {degrees}C" in text
    assert text.startswith(f"{cli.HEADER}\n")
    assert text.endswith(f"Saved: ~/Desktop/{PDF_NAME}\n{run.OPENING}\n")


class _Disk(io.FileIO):
    """A file with ``room`` bytes left, then ``fails``: a full disk, or a reader that went
    away. Pointed at /dev/null, it takes everything, as /dev/null does."""

    def __init__(self, path: Path, room: int, fails: int) -> None:
        super().__init__(path, "w")
        self.room, self.fails = room, fails

    def write(self, data):  # type: ignore[no-untyped-def]
        if os.path.samestat(os.fstat(self.fileno()), os.stat(os.devnull)):
            return super().write(data)
        if self.room == 0:
            raise OSError(self.fails, os.strerror(self.fails))
        taken = super().write(bytes(data[: self.room]))
        self.room -= taken
        return taken


@pytest.mark.parametrize(
    ("fails", "room", "first", "then", "kept", "said"),
    [
        (errno.ENOSPC, 3, "35 \N{DEGREE SIGN}C\n", "one more line\n", b"35 ", True),
        (errno.ENOSPC, 0, "one line\n", "35 \N{DEGREE SIGN}C\n", b"", True),
        (errno.EPIPE, 0, "one line\n", "35 \N{DEGREE SIGN}C\n", b"", False),
    ],
    ids=[
        "a character it cannot spell, then a full disk",
        "a full disk, then a character",
        "a reader that went away, then a character",
    ],
)
def test_stdout_is_said_to_be_incomplete_once_whatever_the_cause(
    monkeypatch, tmp_path, fails, room, first, then, kept, said
):
    # An ASCII stdout sent to a disk that fills: two causes, one line on stderr. Once its
    # reader went away (voltry-mac | head), nothing more is said of it.
    disk = _Disk(tmp_path / "summary.txt", room, fails)
    err = io.StringIO()
    # The patch is undone before the file closes.
    with (
        io.TextIOWrapper(disk, encoding="ascii", write_through=True) as stdout,
        monkeypatch.context() as patch,
    ):
        patch.setattr(sys, "stdout", stdout)
        patch.setattr(sys, "stderr", err)
        console.write(stdout, first)
        console.write(stdout, then)
    assert err.getvalue() == (f"{console.INCOMPLETE}\n" if said else "")
    assert (tmp_path / "summary.txt").read_bytes() == kept


def test_a_stream_other_than_stdout_replaces_what_it_cannot_spell_and_says_nothing(
    monkeypatch,
):
    # Only stdout carries the report; a failure elsewhere is said nowhere, as a flush's is.
    raw, out = io.BytesIO(), io.StringIO()
    stderr = io.TextIOWrapper(raw, encoding="ascii", errors="strict")
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", stderr)
    console.write(stderr, "35 \N{DEGREE SIGN}C\n")
    console.write(stderr, "a second \N{DEGREE SIGN}\n")
    assert raw.getvalue() == b"35 ?C\na second ?\n"
    assert out.getvalue() == ""


# --- one encoder for each stream ------------------------------------------------------------

PIECES = (
    f"{console.HEADER}\n",
    "  Temperature now     35 \N{DEGREE SIGN}C\n",
    "Saved: ~/Desktop/Voltry Mac Report 2026-09-23 14.05.pdf\n",
)
ENCODINGS = [
    "utf-8",
    "utf-8-sig",
    "utf-16",
    "utf-16-be",
    "utf-32",
    "latin-1",
    "mac-roman",
    "shift_jis",
    "euc_jp",
    "gb18030",
    "iso2022_jp",
]


class _Pipe(io.BytesIO):
    """A stream that cannot seek, as a pipe or a terminal."""

    def seekable(self) -> bool:
        return False


def _stream(where: str, encoding: str) -> tuple[io.BytesIO, io.TextIOWrapper]:
    """A stream as Python opens stdout: on a new file, on a file it adds to (>>), or on a
    pipe."""
    if where == "a pipe":
        raw: io.BytesIO = _Pipe()
    else:
        raw = io.BytesIO(b"an earlier line\n" if where == "a file added to" else b"")
        raw.seek(0, io.SEEK_END)
    return raw, io.TextIOWrapper(raw, encoding=encoding)


@pytest.mark.parametrize("where", ["a file", "a file added to"])
@pytest.mark.parametrize("encoding", ENCODINGS)
def test_each_write_to_a_file_is_encoded_as_its_text_layer_would_encode_it(where, encoding):
    # PYTHONIOENCODING=utf-16 voltry-mac > summary.txt gave a byte-order mark at each write.
    # The text layer writes one where the file starts, and none in a file it adds to.
    theirs, layer = _stream(where, encoding)
    for piece in PIECES:
        layer.write(piece)
        layer.flush()
    ours, stream = _stream(where, encoding)
    for piece in PIECES:
        console.write(stream, piece)
    assert ours.getvalue() == theirs.getvalue()


@pytest.mark.parametrize("encoding", ENCODINGS)
def test_a_pipe_holds_the_text_as_one_encoding_of_it_gives_it(encoding):
    # One byte-order mark where the stream starts, as in a file. The text layer itself
    # writes none to a pipe for UTF-16 and UTF-32, and one for UTF-8 with a signature.
    ours, stream = _stream("a pipe", encoding)
    for piece in PIECES:
        console.write(stream, piece)
    assert ours.getvalue() == "".join(PIECES).encode(encoding)


def test_a_run_writes_one_byte_order_mark_where_each_stream_starts(mac, monkeypatch):
    # PYTHONIOENCODING=utf-16, and the final clear fails, so both streams carry text: each
    # starts with one mark and holds no other, as its text layer would write it.
    mac.results["S5"] = result("S5", 1)
    out, err = io.BytesIO(), io.BytesIO()
    stdout = io.TextIOWrapper(out, encoding="utf-16")
    stderr = io.TextIOWrapper(err, encoding="utf-16")
    with monkeypatch.context() as patch:
        patch.setattr(sys, "stdout", stdout)
        patch.setattr(sys, "stderr", stderr)
        code = cli.main([])
    assert code == 6
    for data in (out.getvalue(), err.getvalue()):
        assert data.startswith(codecs.BOM_UTF16)
        assert "\N{ZERO WIDTH NO-BREAK SPACE}" not in data.decode("utf-16")
    assert out.getvalue().decode("utf-16").startswith(f"{cli.HEADER}\n")
    assert err.getvalue().decode("utf-16") == f"{run.WARNING}\n{run.WARNING}\n"
