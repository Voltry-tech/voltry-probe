"""The voltry-mac command line (docs/VOLTRY_MAC_SPEC.md, "CLI transcripts").

::

    voltry-mac [--no-root] [--yes] [--output DIR] [--json] [--no-open]
               [--show-serial] [--paper letter|a4] [--debug]
    voltry-mac --dry-run           print every command it can run; run none
    voltry-mac render REPORT.json  rebuild the PDF from a saved JSON
    voltry-mac --version

The command parses every flag, answers ``--version`` and ``--dry-run`` on any platform
without the preflight, runs the preflight for every other run, ``--help`` and render
included (the root user, exit 5; a platform the spec does not cover, exit 3; a Ctrl-C
during it, exit 130), then refuses bad arguments and ``--yes`` together with ``--no-root``
(exit 2), prints the help, or hands a collecting run and render to run.py. A bad argument
is refused in the tool's own words, never argparse's, with one outcome and the same words
on every Python it supports: ``--`` and a word that starts with a dash and a digit, which
each Python reads in its own way, are refused before argparse reads the command line. An
argument a refusal names prints through the display path, the parts on either side of
each = as paths of their own.
"""

from __future__ import annotations

import argparse
import contextlib
import re
import sys
import textwrap
from collections.abc import Callable, Sequence
from typing import Final, NoReturn

from voltry_mac import __version__, allowlist, console, preflight, run, signals

EXIT_OK: Final = 0
EXIT_USAGE: Final = 2
EXIT_INTERRUPTED: Final = 130

YES_WITH_NO_ROOT: Final = "--yes and --no-root cannot be used together"
HEADER: Final = console.HEADER
python_version = console.python_version

_DRY_RUN_GROUPS: Final = (
    ("As you:", allowlist.USER_COMMAND_IDS),
    ("As you, only after you allow the two administrator reads:", ("X1", "P1")),
    ("As you, once, after the report is saved:", ("O1",)),
    (
        "Through sudo, only after you allow the two administrator reads:",
        ("S1", "S2", "S3", "S4", "S5"),
    ),
    (
        "Through sudo with no password prompt, only with --yes and no terminal:",
        ("S2n", "S3n", "S4n"),
    ),
)
_PAYLOAD_NOTE: Final = (
    "S3 and S3n run sqlite3 as macOS's memory-maintenance account, _mmaintenanced.\n"
    "S4 and S4n run powermetrics as root. Each runs inside the sandbox profile shown,\n"
    "which denies every file write and all network access.\n"
)
# Render's own refusal of an option only a collecting run takes.
RENDER_ONLY: Final = "render takes only REPORT.json, --output DIR and --no-open"
# The rest of the command line's own words for an argument it cannot take. argparse's differ
# between the Pythons the tool supports and echo what was typed as it is, a path with the
# account's name or a terminal's control sequence (the GPT audit, pass 2, G2-01). An
# argument a refusal names stands on a line of its own, as a path the owner typed.
NOT_TAKEN_ONE: Final = "voltry-mac does not take this argument here:"
NOT_TAKEN_MANY: Final = "voltry-mac does not take these arguments here:"
PAPER_SIZES: Final = "--paper takes letter or a4"
NEEDS_FOLDER: Final = "--output needs a folder"
NEEDS_REPORT: Final = "render needs REPORT.json"
NO_ARGUMENT: Final = "{option} takes no argument"
UNREAD: Final = "voltry-mac could not read this command line"
# An empty argument, as a refusal names it: on a line of its own it would show as nothing
# (the review of the audit fixes, round 3, n5).
EMPTY_ARGUMENT: Final = "(an empty argument)"
# The dry run's prose wraps at 80 columns; its command lines print whole, as they run.
_WIDTH: Final = 80
# A word that starts with a dash and a digit, or a dash, a dot and a digit, as "-1.json"
# does: Python 3.14 takes it for a value, and 3.11 to 3.13 for an option unless it is a
# plain number. The pattern is 3.14's own, which covers the older one (the review of the
# audit fixes, round 3, m1).
_DASH_DIGIT: Final = re.compile(r"-\.?\d")


_USAGE: Final = (
    "voltry-mac [--no-root] [--yes] [--output DIR] [--json] [--no-open]\n"
    "                  [--show-serial] [--paper letter|a4] [--debug]\n"
    "       voltry-mac --dry-run           print every command it can run; run none\n"
    "       voltry-mac render REPORT.json  rebuild the PDF from a saved JSON\n"
    "       voltry-mac --version"
)
_RENDER_USAGE: Final = "voltry-mac render REPORT.json [--output DIR] [--no-open]"
_EPILOG: Final = (
    "--yes skips Voltry's own question only. With a terminal, sudo may still ask for\n"
    "your password; without one, sudo cannot ask.\n"
    "--yes and --no-root contradict each other and are refused (exit 2)."
)
# The options that take no argument, as a refusal names one given an argument after =.
_FLAGS: Final = frozenset(
    {
        "--help",
        "--version",
        "--dry-run",
        "--no-root",
        "--yes",
        "--json",
        "--no-open",
        "--show-serial",
        "--debug",
    }
)


class UsageError(Exception):
    """An argument error, in the tool's own words, held until the preflight has run: when
    more than one applies, the exit code is the first of 5, 3 and 2 (spec, Failure modes).
    ``named`` are the arguments the words name, and ``render`` says whose usage comes
    first."""

    def __init__(self, words: str, named: Sequence[str] = (), *, render: bool = False) -> None:
        super().__init__(words)
        self.words = words
        self.named = tuple(named)
        self.usage = _RENDER_USAGE if render else _USAGE

    def report(self) -> int:
        """Print the usage and the words to stderr, never argparse's own; return exit code
        2. An argument the words name prints through the display path (_shown). With no
        stderr, nothing is printed."""
        if sys.stderr is not None:
            named = "".join(f"\n  {_shown(argument)}" for argument in self.named)
            console.write(sys.stderr, f"usage: {self.usage}\n{self.words}{named}\n")
        return EXIT_USAGE


def _shown(argument: str) -> str:
    """An argument a refusal names, as a folder the owner typed is shown: through the display
    path, controls, DEL and bidirectional characters escaped and the home folder as ~ (spec,
    the Architecture's renderers row). The parts on either side of each = are shown as paths
    of their own, since an option keeps its folder after =, where the home folder does not
    start the argument: --ouput=~/Reports (the pre-audit of the GPT audit's pass 3, control
    02). An empty argument is named in words."""
    if not argument:
        return EMPTY_ARGUMENT
    return "=".join(run.display_argument(part) for part in argument.split("="))


class Help(Exception):
    """``--help``, held until the preflight has run, as a usage error is: only ``--version``
    and ``--dry-run`` skip it (Decision 7; change record 2). ``text`` is the help of the
    parser it was asked of, the tool's or render's."""

    def __init__(self, text: str) -> None:
        super().__init__(text)
        self.text = text


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        # argparse's words never print. It hands parse() the argument at fault instead
        # (G2-01), and whatever still comes here is refused in the tool's words too.
        raise UsageError(UNREAD)

    def print_help(self, file: object = None) -> NoReturn:
        # argparse's help action prints here, then exits. The help waits for main() instead,
        # which prints it once the preflight has passed (Decision 7; change record 2).
        raise Help(self.format_help())


def _formatter(prog: str) -> argparse.HelpFormatter:
    # Option help wraps at a fixed 80 columns, so it reads the same in any terminal; the
    # usage block above it is the spec's, verbatim.
    return argparse.RawDescriptionHelpFormatter(prog, width=80)


def _parser() -> argparse.ArgumentParser:
    # An option is taken only as it is spelled in full, and an error comes back to parse() as
    # the argument it is about, for the tool's own words (the GPT audit, pass 2, G2-01).
    parser = _Parser(
        prog="voltry-mac",
        usage=_USAGE,
        description=(
            "A point-in-time hardware observation report for this Mac. Point-in-time\n"
            "observations, not a diagnosis, grade or certificate."
        ),
        epilog=_EPILOG,
        formatter_class=_formatter,
        allow_abbrev=False,
        exit_on_error=False,
    )
    # Python 3.14 colors help on a terminal, and wherever FORCE_COLOR or PYTHON_COLORS asks
    # for color; the tool prints plain text (spec, Failure modes), so --help is the same
    # bytes on every Python. Earlier Pythons have no color and never read this. It is set
    # here, before add_subparsers hands it on to render's parser, and again on render's (the
    # review of the audit fixes, round 3, n4).
    parser.color = False
    parser.add_argument("--version", action="store_true", help="print the version and exit")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print every command this version can run, and run none",
    )
    parser.add_argument("--no-root", action="store_true", help="skip the two administrator reads")
    parser.add_argument(
        "--yes",
        action="store_true",
        help="skip Voltry's own question; with no terminal, sudo cannot ask",
    )
    parser.add_argument(
        "--output",
        metavar="DIR",
        dest="collect_output",
        help="save the report in DIR, an existing folder, instead of the Desktop",
    )
    parser.add_argument(
        "--json", action="store_true", help="also save the report's JSON beside the PDF"
    )
    parser.add_argument(
        "--no-open", action="store_true", dest="collect_no_open", help="do not open the PDF"
    )
    parser.add_argument(
        "--show-serial",
        action="store_true",
        help="show the full serial number instead of its last four characters",
    )
    parser.add_argument(
        "--paper", choices=("letter", "a4"), help="paper size; by default, from your region"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="print each command's ID, template, exit code and duration to stderr",
    )
    # The usage block above documents render; the command list itself stays out of the
    # options, so render is not listed twice. argparse does not check the command's name:
    # it puts the word on the namespace, then finds no parser for one that is not render,
    # and parse() names that word in the tool's own words.
    commands = parser.add_subparsers(dest="command", help=argparse.SUPPRESS)
    commands.choices = None
    render = commands.add_parser(
        "render",
        prog="voltry-mac render",
        usage=_RENDER_USAGE,
        description="Rebuild the PDF from a saved JSON. Collects nothing.",
        formatter_class=_formatter,
        allow_abbrev=False,
        exit_on_error=False,
    )
    render.color = False
    # Optional to argparse, so parse() says in the tool's words when it is missing.
    render.add_argument("report", metavar="REPORT.json", nargs="?")
    render.add_argument("--output", metavar="DIR", dest="render_output", help="save the PDF in DIR")
    render.add_argument(
        "--no-open", action="store_true", dest="render_no_open", help="do not open the PDF"
    )
    return parser


def _not_taken(arguments: Sequence[str], *, render: bool) -> UsageError:
    if len(arguments) == 1:
        return UsageError(NOT_TAKEN_ONE, arguments, render=render)
    return UsageError(NOT_TAKEN_MANY, arguments, render=render)


def _set_aside(argv: Sequence[str], word: str) -> list[str]:
    """What argparse set aside before a first word it could not take, an option spelled
    wrong say: the command line up to that word, parsed again. The word stands at the
    first place it does where what comes before it parses whole with no command, so a
    folder of the same name after --output is not taken for it."""
    for index, each in enumerate(argv):
        if each == word:
            with contextlib.suppress(argparse.ArgumentError, UsageError):
                before, left = _parser().parse_known_args(list(argv[:index]))
                if before.command is None:
                    return left
    return []


def _refusal(argv: Sequence[str], argument: str | None, found: argparse.Namespace) -> UsageError:
    """The tool's own words for an error argparse found, by the argument it names, never by
    argparse's message: a first word that is not render, with what was set aside before
    it, an option missing its argument or given one it does not take, or a --paper that
    is neither size."""
    command = getattr(found, "command", None)
    render = command == "render"
    if command is not None and not render:
        return _not_taken([*_set_aside(argv, command), command], render=False)
    if argument == "--output":
        return UsageError(NEEDS_FOLDER, render=render)
    if argument == "--paper":
        return UsageError(PAPER_SIZES)
    # An option argparse names by all its spellings, as -h/--help, is named by its last.
    option = (argument or "").rpartition("/")[2]
    if option in _FLAGS:
        return UsageError(NO_ARGUMENT.format(option=option), render=render)
    return UsageError(UNREAD, render=render)


def _read_apart(word: str) -> bool:
    """Whether argparse reads the word in its own way on each Python: a word that starts
    with a dash and a digit (_DASH_DIGIT), or "--", which 3.11 takes for the command and
    3.12 and later drop."""
    return word == "--" or _DASH_DIGIT.match(word) is not None


def _command_word(argv: Sequence[str]) -> str | None:
    """The command word argparse finds in a command line that holds none of those words, as
    far as it reads before an error or --help."""
    found = argparse.Namespace()
    with contextlib.suppress(argparse.ArgumentError, UsageError, Help):
        _parser().parse_known_args(list(argv), found)
    return getattr(found, "command", None)


def parse(argv: Sequence[str]) -> argparse.Namespace:
    """Parse the command line. A usage error raises UsageError and --help raises Help, each
    printing nothing. A usage error names an argument only as the command line holds it,
    never in argparse's words (the GPT audit, pass 2, G2-01), and a command line has one
    outcome, in the same words, on every Python the tool supports: "--" and a word that
    starts with a dash and a digit are refused first, wherever they stand, each named,
    under render's usage when the rest of the command line is a render (the review of the
    audit fixes, round 3, m1). A name that starts with a dash is given after =, as
    --output=-1, or as ./-1.json."""
    apart = [each for each in argv if _read_apart(each)]
    if apart:
        rest = [each for each in argv if not _read_apart(each)]
        raise _not_taken(apart, render=_command_word(rest) == "render")
    parser = _parser()
    found = argparse.Namespace()  # what argparse read, before an error too
    try:
        args, left = parser.parse_known_args(list(argv), found)
    except argparse.ArgumentError as error:
        raise _refusal(argv, error.argument_name, found) from None
    render = args.command == "render"
    if left:
        raise _not_taken(left, render=render)
    if render:
        if not args.report:  # missing, or an empty argument, which names no file
            raise UsageError(NEEDS_REPORT, render=True)
        collect_only = (
            args.no_root,
            args.yes,
            args.collect_output is not None,
            args.json,
            args.collect_no_open,
            args.show_serial,
            args.paper is not None,
            args.debug,
        )
        if any(collect_only) and not (args.version or args.dry_run):
            raise UsageError(RENDER_ONLY, render=True)
        args.output, args.no_open = args.render_output, args.render_no_open
    else:
        args.output, args.no_open = args.collect_output, args.collect_no_open
    return args


def dry_run_text() -> str:
    """The frozen allow-list as ``--dry-run`` prints it, in list order."""
    lines = [
        f"voltry-mac {__version__} can run these commands and nothing else.",
        "--dry-run runs none of them.",
        "",
    ]
    for header, command_ids in _DRY_RUN_GROUPS:
        lines.append(header)
        for command_id in command_ids:
            template = allowlist.BY_ID[command_id].template
            lines.append(f"  {command_id:<4} {allowlist.display(template)}")
        lines.append("")
    lines.append(_PAYLOAD_NOTE)
    lines.append("Read inside voltry-mac, with no command:")
    lines.extend(
        textwrap.fill(
            read.description,
            _WIDTH,
            initial_indent=f"  {read.id:<4} ",
            subsequent_indent=" " * 7,
            break_long_words=False,
            break_on_hyphens=False,
        )
        for read in allowlist.IN_PROCESS_READS
    )
    return "\n".join(lines) + "\n"


def _emit(text: str) -> int:
    """An answer on stdout."""
    console.write(sys.stdout, text)
    return EXIT_OK


def _refuse(text: str, code: int) -> int:
    """A refusal on stderr, never on stdout, even with stderr closed."""
    console.write(sys.stderr, text + "\n")
    return code


def _answered(code: int, cancelled: Callable[[], bool]) -> int:
    """The last read of the flag for an answer, --help's, --version's or --dry-run's: a
    signal as it answered stops it once the answer is out, with the stop line and 130, as
    130 comes before 0 (spec, Failure modes, the exit codes)."""
    if code == EXIT_OK and cancelled():
        return _refuse(run.STOPPED, EXIT_INTERRUPTED)
    return code


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command line and return the exit code. From here to the exit, SIGINT,
    SIGTERM and SIGHUP only set the cancellation flag, and once the command has read it for
    the last time they are ignored, so none prints a traceback or ends the process by the
    signal (signals.cancellation; the audit fixes' review, round 3, m2, and the pre-audit
    of pass 3, 05)."""
    with signals.cancellation() as cancelled:
        return _command(sys.argv[1:] if argv is None else argv, cancelled)


def _command(argv: Sequence[str], cancelled: Callable[[], bool]) -> int:
    """The command line, under the flag main holds; returns the exit code."""
    try:
        parsed: argparse.Namespace | UsageError | Help = parse(argv)
    except (UsageError, Help) as held:  # each waits for the preflight
        parsed = held
    answers = isinstance(parsed, argparse.Namespace) and (parsed.version or parsed.dry_run)
    found: preflight.Platform | None = None
    if not answers:
        # The preflight, before any read, before an argument error and before --help: when
        # more than one applies, the exit code is the first of 5, 3 and 2 (spec, Failure
        # modes). Only --version and --dry-run skip it (Decision 7; change record 2: "only
        # `--version` and `--dry-run` skip the preflight"), so --help, render and a command
        # line that does not parse all take it. A signal here only sets the flag (main),
        # which is read below.
        found = None if preflight.is_root() else preflight.read()
        if found is None:  # started as root, so nothing was read
            return _refuse(preflight.ROOT, preflight.EXIT_ROOT)
        reason = preflight.refusal(found)
        if reason is not None:
            return _refuse(f"{HEADER}\n\n{reason}", preflight.EXIT_UNSUPPORTED)
    if isinstance(parsed, UsageError):
        return parsed.report()
    # The contradiction is an argument error, so --version and --dry-run, which skip only
    # the preflight, do not skip it (the MAC 3.1 review).
    if isinstance(parsed, argparse.Namespace) and parsed.yes and parsed.no_root:
        return _refuse(YES_WITH_NO_ROOT, EXIT_USAGE)
    # A signal since the command started, as the preflight ran say, stops it here, with no
    # traceback and before anything starts, --help's text included; a refusal above keeps
    # its code, as 5, 3 and 2 come before 130 (the run's review, round 2, n17).
    if cancelled():
        return _refuse(run.STOPPED, EXIT_INTERRUPTED)
    if isinstance(parsed, Help):
        return _answered(_emit(parsed.text), cancelled)
    if parsed.version:
        found = preflight.read(release=False)  # R4's two flags; nothing is refused
        code = _emit(
            f"voltry-mac {__version__}\nPython {python_version()}\n"
            f"Architecture {preflight.architecture(found)}\nRosetta {preflight.rosetta(found)}\n"
        )
        return _answered(code, cancelled)
    if parsed.dry_run:
        return _answered(_emit(dry_run_text()), cancelled)
    if parsed.command == "render":
        return run.rebuild(parsed)
    assert found is not None  # noqa: S101 - every run but --version and --dry-run read it
    return run.collect(parsed, found)
