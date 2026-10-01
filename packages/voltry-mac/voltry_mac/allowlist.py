"""Every command voltry-mac can run, and the five reads it makes in-process.

The spec of record is the "Command allow-list" section of docs/VOLTRY_MAC_SPEC.md: 38
fixed argv templates plus five in-process reads. Two arguments are dynamic and checked
as data: the SMART child's interpreter must be ``sys.executable``, and ``open`` takes only
the file this run just published. Everything else is a literal.

Two independent checks live here. ``match`` is the allow-list itself: an argv runs only
if it equals a template exactly. ``forbidden_shape`` is a second, shape-based scan for
the writers and escalations the spec names; a test runs it over the frozen set, so a
later edit cannot add a writer that happens to match exactly. The scan keeps its own copy
of every string it checks, so an edit to the list is caught unless it is made to the scan
too.
"""

from __future__ import annotations

import posixpath
import re
import shlex
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Literal

PROFILE: Final = "(version 1) (allow default) (deny file-write*) (deny network*)"
PROMPT: Final = "Your Mac password, for the two steps above: "
SERVICE_ACCOUNT: Final = "_mmaintenanced"
LEDGER_URI: Final = "file:/private/var/db/mmaintenanced/memory_errors.db?readonly_shm=1"
LEDGER_QUERY: Final = (
    "PRAGMA query_only=ON; PRAGMA temp_store=MEMORY; WITH classes(correctable,label) AS "
    "(VALUES(1,'correctable'),(0,'uncorrectable')) SELECT c.label AS class, COUNT(e.ID) AS "
    "event_rows, COALESCE(SUM(e.count),0) AS reported_count FROM classes c LEFT JOIN "
    "ecc_errors_v2 e ON e.correctable=c.correctable GROUP BY c.correctable,c.label ORDER BY "
    "c.correctable DESC;"
)
SAMPLERS: Final = "cpu_power,gpu_power,thermal"
SMART_MODULE: Final = "voltry_mac.smart_iokit"

# The two dynamic arguments. A placeholder is never a usable value: both real values
# must be absolute paths, and a placeholder starts with "<".
INTERPRETER: Final = "<the running interpreter>"
PUBLISHED_PATH: Final = "<the exact path just published>"
PLACEHOLDERS: Final = (INTERPRETER, PUBLISHED_PATH)

RunsAs = Literal["user", "service", "root"]


@dataclass(frozen=True)
class Command:
    """One allow-listed argv template.

    ``runs_as`` is the identity the program itself runs as: ``service`` is Apple's
    ``_mmaintenanced`` account (S3), ``root`` is S4, and everything else, sudo's own
    control steps included, is the user. ``timeout_s`` is the spec's timeout: a deadline
    for user commands, per listing for P1, the answer window for S2, and the payload's
    runtime from its identification for S3 and S4.
    """

    id: str
    template: tuple[str, ...]
    runs_as: RunsAs
    timeout_s: int


@dataclass(frozen=True)
class InProcessRead:
    """One read the tool makes inside its own process, with no command."""

    id: str
    description: str


_SANDBOX: Final = ("/usr/bin/sandbox-exec", "-p", PROFILE)
_SQLITE: Final = (
    "/usr/bin/sqlite3",
    "-init",
    "/dev/null",
    "-safe",
    "-nofollow",
    "-readonly",
    "-json",
    "-bail",
    LEDGER_URI,
    LEDGER_QUERY,
)
_POWERMETRICS: Final = (
    "/usr/bin/powermetrics",
    "-n",
    "5",
    "-i",
    "1000",
    "--samplers",
    SAMPLERS,
    "--format",
    "plist",
)
_SYSCTL_OIDS: Final = (
    "hw.model",
    "hw.target",
    "hw.memsize",
    "hw.ncpu",
    "machdep.cpu.brand_string",
    "hw.optional.arm64",
    "hw.nperflevels",
    "hw.perflevel0.name",
    "hw.perflevel0.physicalcpu",
    "hw.perflevel1.name",
    "hw.perflevel1.physicalcpu",
)
_SUDO: Final = "/usr/bin/sudo"


def _user(command_id: str, *argv: str, timeout_s: int = 10) -> Command:
    return Command(command_id, argv, "user", timeout_s)


COMMANDS: Final[tuple[Command, ...]] = (
    _user("C1", "/usr/bin/sw_vers"),
    _user("C2", "/usr/sbin/system_profiler", "-json", "SPHardwareDataType"),
    _user("C3", "/usr/sbin/system_profiler", "-json", "SPNVMeDataType"),
    _user("C4", "/usr/sbin/system_profiler", "-json", "SPDisplaysDataType"),
    _user("C5", "/usr/sbin/system_profiler", "-json", "SPMemoryDataType"),
    _user("C6", "/usr/sbin/system_profiler", "-json", "SPPowerDataType"),
    _user("C7", "/usr/sbin/ioreg", "-r", "-c", "AppleSmartBattery", "-a"),
    _user("C8", "/usr/bin/pmset", "-g", "therm"),
    _user("C9", "/usr/bin/memory_pressure", "-Q"),
    _user("C11", "/usr/sbin/diskutil", "info", "-plist", "/"),
    _user("C12", "/usr/bin/csrutil", "status"),
    _user("C13", "/usr/sbin/spctl", "--status"),
    _user("C14", "/usr/bin/fdesetup", "status"),
    *(
        _user(f"C{15 + index}", "/usr/sbin/sysctl", "-n", oid)
        for index, oid in enumerate(_SYSCTL_OIDS)
    ),
    _user("C26", "/usr/sbin/sysctl", "-n", "kern.hv_vmm_present"),
    _user("C27", "/usr/sbin/sysctl", "-n", "kern.boottime"),
    _user("C28", INTERPRETER, "-I", "-B", "-m", SMART_MODULE, timeout_s=15),
    _user("X1", *_SANDBOX, "/usr/bin/true"),
    _user("P1", "/bin/ps", "-axo", "pid,ppid,uid,lstart,comm", timeout_s=2),
    _user("O1", "/usr/bin/open", PUBLISHED_PATH),
    _user("S1", _SUDO, "-k"),
    _user("S2", _SUDO, "-v", "-p", PROMPT, timeout_s=180),
    Command(
        "S3",
        (_SUDO, "-u", SERVICE_ACCOUNT, "-H", "-p", PROMPT, "--", *_SANDBOX, *_SQLITE),
        "service",
        10,
    ),
    Command("S4", (_SUDO, "-H", "-p", PROMPT, "--", *_SANDBOX, *_POWERMETRICS), "root", 20),
    _user("S5", _SUDO, "-k"),
    _user("S2n", _SUDO, "-v", "-n", timeout_s=180),
    Command(
        "S3n",
        (_SUDO, "-u", SERVICE_ACCOUNT, "-H", "-n", "--", *_SANDBOX, *_SQLITE),
        "service",
        10,
    ),
    Command("S4n", (_SUDO, "-H", "-n", "--", *_SANDBOX, *_POWERMETRICS), "root", 20),
)

BY_ID: Final = MappingProxyType({command.id: command for command in COMMANDS})
USER_COMMAND_IDS: Final = tuple(command.id for command in COMMANDS if command.id[0] == "C")

IN_PROCESS_READS: Final[tuple[InProcessRead, ...]] = (
    InProcessRead("R1", "Counts the names ending in .panic in /Library/Logs/DiagnosticReports"),
    InProcessRead("R2", "Reads where /etc/localtime points, for the time zone name"),
    InProcessRead(
        "R3",
        "Reads AppleLocale from ~/Library/Preferences/.GlobalPreferences.plist, "
        "for the paper size",
    ),
    InProcessRead(
        "R4",
        "Reads sysctl.proc_translated, hw.optional.arm64 and kern.osrelease through "
        "sysctlbyname",
    ),
    InProcessRead(
        "R5",
        "Looks up the _mmaintenanced account in the account database, after you allow "
        "the two administrator reads",
    ),
)


def _usable(path: object) -> str | None:
    """A dynamic value is usable only as an absolute path; a placeholder never is."""
    return path if isinstance(path, str) and path.startswith("/") else None


def _executable() -> str | None:
    """The running interpreter, the only one C28 may use, read at the moment of use."""
    return _usable(sys.executable)


def resolve(command_id: str, *, published_path: str | None = None) -> tuple[str, ...]:
    """The exact argv for one allow-listed command, with its dynamic argument filled in.

    The interpreter is always ``sys.executable``; nothing can name another. Raises
    ``ValueError`` when the command needs a dynamic value that is missing or not an
    absolute path, and ``KeyError`` for an ID that is not on the list.
    """
    command = BY_ID[command_id]
    values = {INTERPRETER: _executable(), PUBLISHED_PATH: _usable(published_path)}
    argv: list[str] = []
    for part in command.template:
        if part in values:
            value = values[part]
            if value is None:
                raise ValueError(f"{command_id} needs {part}, as an absolute path")
            argv.append(value)
        else:
            argv.append(part)
    return tuple(argv)


def _as_argv(argv: object) -> tuple[str, ...] | None:
    """The argv as a tuple of text, or ``None`` for one string, bytes or non-text parts."""
    if isinstance(argv, str | bytes) or not isinstance(argv, Sequence):
        return None
    candidate = tuple(argv)
    return candidate if all(isinstance(part, str) for part in candidate) else None


def match(argv: Sequence[str], *, published_path: str | None = None) -> Command | None:
    """The command whose template ``argv`` equals exactly, or ``None``.

    The interpreter must be ``sys.executable`` and ``open`` matches only the path this run
    just published, passed as ``published_path``. When two templates are the same argv (S1
    and S5 both clear sudo's record), the first in list order is returned, so a caller that
    records runs keys them by the ID it asked for, not by this result.
    """
    candidate = _as_argv(argv)
    if candidate is None:
        return None
    values = {INTERPRETER: _executable(), PUBLISHED_PATH: _usable(published_path)}
    for command in COMMANDS:
        if len(command.template) != len(candidate):
            continue
        if all(
            (values[part] is not None and got == values[part]) if part in values else got == part
            for part, got in zip(command.template, candidate, strict=True)
        ):
            return command
    return None


_SHELL_SAFE: Final = re.compile(r"[\w@%+=:,./-]+", re.ASCII)
_DOUBLE_QUOTE_UNSAFE: Final = frozenset('"$`\\!')


def _quote(part: str) -> str:
    if part in PLACEHOLDERS or _SHELL_SAFE.fullmatch(part):
        return part
    if not set(part) & _DOUBLE_QUOTE_UNSAFE:
        return f'"{part}"'
    return shlex.quote(part)


def display(template: Sequence[str]) -> str:
    """A template as one line a shell would read back as the same argv.

    Placeholders stay as written, safe words stay bare, a literal with nothing a shell
    expands inside double quotes is double-quoted (as the spec's table writes them), and
    anything else is single-quoted.
    """
    return " ".join(_quote(part) for part in template)


# --- forbidden shapes ------------------------------------------------------------------------
#
# A closed scan. It names the spec's forbidden shapes where it recognizes them (shells,
# launchers, interpreters and the named tools by case-folded name, sudo's options in getopt
# bundles and prefixes), and then requires every program and its arguments to be one of
# the forms in its own tables below. The tables hold their own copy of every string they
# check, written out again on purpose: an edit to the list above changes the list and not
# the scan, so the scan catches it unless the same edit is made here too. Behind the copies,
# rules check properties the spec names, without reading the copies: the profile uses only
# the words version, 1, allow, deny, default, file-write* and network*, ends by denying file
# writes and the network, and allows neither; sqlite3 starts with its read-only flags, opens
# one read-only file under /private/var, never immutable, and runs a query that starts with
# PRAGMA query_only=ON; powermetrics takes no option but -n, -i, --samplers and --format,
# none twice, writes no file and names only its three samplers; and sysctl reads only plain
# dotted names, never the host name. The rules are a second line, not a complete one: the
# exact copies decide, and the prompt and the service account are held by them alone.

_SHELLS: Final = frozenset({"sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "fish"})
_LAUNCHERS: Final = frozenset(
    {"env", "xargs", "nohup", "nice", "time", "arch", "caffeinate", "script", "login", "su"}
    | {"xcrun", "open-with", "launchctl", "at", "batch", "crontab"}
)
_INTERPRETER_PREFIXES: Final = (
    "python",
    "pypy",
    "perl",
    "ruby",
    "tclsh",
    "wish",
    "php",
    "node",
    "lua",
    "awk",
    "expect",
    "osascript",
    "swift",
    "jsc",
)
_SUDO_PROGRAM: Final = "/usr/bin/sudo"
_SANDBOX_EXEC: Final = "/usr/bin/sandbox-exec"
_TRUE: Final = "/usr/bin/true"
_SQLITE3: Final = "/usr/bin/sqlite3"
_POWERMETRICS_PROGRAM: Final = "/usr/bin/powermetrics"

# The scan's own copies of the list's fixed strings.
_SCAN_PROFILE: Final = "(version 1) (allow default) (deny file-write*) (deny network*)"
_SCAN_PROMPT: Final = "Your Mac password, for the two steps above: "
_SCAN_ACCOUNT: Final = "_mmaintenanced"
_SCAN_SMART_MODULE: Final = "voltry_mac.smart_iokit"
_SCAN_SQLITE_TAIL: Final = (
    "-init",
    "/dev/null",
    "-safe",
    "-nofollow",
    "-readonly",
    "-json",
    "-bail",
    "file:/private/var/db/mmaintenanced/memory_errors.db?readonly_shm=1",
    "PRAGMA query_only=ON; PRAGMA temp_store=MEMORY; WITH classes(correctable,label) AS "
    "(VALUES(1,'correctable'),(0,'uncorrectable')) SELECT c.label AS class, COUNT(e.ID) AS "
    "event_rows, COALESCE(SUM(e.count),0) AS reported_count FROM classes c LEFT JOIN "
    "ecc_errors_v2 e ON e.correctable=c.correctable GROUP BY c.correctable,c.label ORDER BY "
    "c.correctable DESC;",
)
_SCAN_POWERMETRICS_TAIL: Final = (
    "-n",
    "5",
    "-i",
    "1000",
    "--samplers",
    "cpu_power,gpu_power,thermal",
    "--format",
    "plist",
)
_SYSCTL_NAMES: Final = frozenset(
    {
        "hw.model",
        "hw.target",
        "hw.memsize",
        "hw.ncpu",
        "machdep.cpu.brand_string",
        "hw.optional.arm64",
        "hw.nperflevels",
        "hw.perflevel0.name",
        "hw.perflevel0.physicalcpu",
        "hw.perflevel1.name",
        "hw.perflevel1.physicalcpu",
        "kern.hv_vmm_present",
        "kern.boottime",
    }
)

# The rules, which hold whatever the copies say.
_PROFILE_CHARACTERS: Final = re.compile(r"[()a-z0-9 *-]+", re.ASCII)
_PROFILE_WORDS: Final = frozenset(
    {"version", "1", "allow", "deny", "default", "file-write*", "network*"}
)
_PROFILE_ENDING: Final = " (deny file-write*) (deny network*)"
_PROFILE_NEVER: Final = ("(allow file-write", "(allow network")
_SQLITE_FIRST: Final = ("-init", "/dev/null", "-safe", "-nofollow", "-readonly")
_LEDGER_PLACE: Final = "file:/private/var/"
_READ_ONLY_SHM: Final = "readonly_shm=1"
_QUERY_START: Final = "PRAGMA query_only=ON;"
_SAMPLER_NAMES: Final = frozenset({"cpu_power", "gpu_power", "thermal"})
# Each option as its dashes and its name, so no copy of an option string stands here.
_POWERMETRICS_OPTIONS: Final = frozenset(
    {("-", "n"), ("-", "i"), ("--", "samplers"), ("--", "format")}
)
# Names that read the host name or the network setup, which the spec never reads, and the
# only form a name may take, since sysctl resolves kern.hostname. too.
_SYSCTL_NEVER: Final = frozenset({"kern.hostname", "kern.nisdomainname"})
_SYSCTL_FORM: Final = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+", re.ASCII)

_SUDO_CONTROL_FORMS: Final = frozenset({("-k",), ("-v", "-p", _SCAN_PROMPT), ("-v", "-n")})
# The option heads that may stand before "--", and the one payload each may run.
_SUDO_PAYLOAD_HEADS: Final = MappingProxyType(
    {
        ("-u", _SCAN_ACCOUNT, "-H", "-p", _SCAN_PROMPT): _SQLITE3,
        ("-u", _SCAN_ACCOUNT, "-H", "-n"): _SQLITE3,
        ("-H", "-p", _SCAN_PROMPT): _POWERMETRICS_PROGRAM,
        ("-H", "-n"): _POWERMETRICS_PROGRAM,
    }
)
_SYSTEM_PROFILER_TYPES: Final = (
    "SPHardwareDataType",
    "SPNVMeDataType",
    "SPDisplaysDataType",
    "SPMemoryDataType",
    "SPPowerDataType",
)
_USER_FORMS: Final = MappingProxyType(
    {
        "/usr/bin/sw_vers": frozenset({()}),
        "/usr/sbin/system_profiler": frozenset(("-json", kind) for kind in _SYSTEM_PROFILER_TYPES),
        "/usr/sbin/ioreg": frozenset({("-r", "-c", "AppleSmartBattery", "-a")}),
        "/usr/bin/pmset": frozenset({("-g", "therm")}),
        "/usr/bin/memory_pressure": frozenset({("-Q",)}),
        "/usr/sbin/diskutil": frozenset({("info", "-plist", "/")}),
        "/usr/bin/csrutil": frozenset({("status",)}),
        "/usr/sbin/spctl": frozenset({("--status",)}),
        "/usr/bin/fdesetup": frozenset({("status",)}),
        "/bin/ps": frozenset({("-axo", "pid,ppid,uid,lstart,comm")}),
    }
)
_SYSCTL: Final = "/usr/sbin/sysctl"
_OPEN: Final = "/usr/bin/open"
_STATUS_FORMS: Final = MappingProxyType(
    {"csrutil": ("status",), "spctl": ("--status",), "fdesetup": ("status",)}
)


def forbidden_shape(argv: Sequence[str], *, published_path: str | None = None) -> str | None:
    """Why ``argv`` has a shape the spec forbids, or ``None`` if it has none.

    The spec's list ("Forbidden shapes, asserted absent by test"): any pmset but ``-g
    therm``, nvram in any form, a sysctl write, powermetrics writing a file or using another
    sampler, memory_pressure changing pressure or waiting on it, diskutil or ps in any
    other form, the security tools in anything but their status forms, sudo opening a
    shell, editing, changing the timeout or switching to any account but
    ``_mmaintenanced`` in front of sqlite3, sandbox-exec with another profile or around any
    other program, a payload without the sandbox, a shell of any kind, open on any other
    file, another interpreter, and a program not given by its absolute path. The scan is
    closed: anything outside its own tables of programs and forms is forbidden too.
    """
    candidate = _as_argv(argv)
    if candidate is None:
        return "an argv that is not a sequence of text parts, such as one string"
    if not candidate:
        return "an empty argv"
    return _scan(candidate, published_path=_usable(published_path))


def _path_problem(program: str) -> str | None:
    if program == _executable():
        return None  # the running interpreter, however the platform spelled its path
    if not program.startswith("/"):
        return "a program given by a relative path"
    if program.startswith("//") or posixpath.normpath(program) != program:
        return "a program path that is not in normal form"
    return None


def _named_shape(name: str, program: str, args: tuple[str, ...]) -> str | None:
    """The spec's named shapes, by case-folded program name, whatever the path's spelling."""
    if name in _SHELLS:
        return f"a shell ({name})"
    if name in _LAUNCHERS:
        return f"a program that runs other programs ({name})"
    if name.startswith(_INTERPRETER_PREFIXES) and program != _executable():
        return "an interpreter other than sys.executable"
    if name == "nvram":
        return "nvram"
    if name == "pmset" and args != ("-g", "therm"):
        return "pmset other than -g therm"
    if name == "sysctl" and any(arg == "-w" or "=" in arg or arg.startswith("-f") for arg in args):
        return "a sysctl write"
    if name == "memory_pressure" and args != ("-Q",):
        return "memory_pressure other than -Q"
    if name == "diskutil" and args != ("info", "-plist", "/"):
        return "diskutil other than info -plist /"
    if name == "ps" and args != ("-axo", "pid,ppid,uid,lstart,comm"):
        return "ps with another option set"
    if name in _STATUS_FORMS and args != _STATUS_FORMS[name]:
        return f"{name} other than its status form"
    return None


def _scan(argv: tuple[str, ...], *, published_path: str | None) -> str | None:
    program, args = argv[0], argv[1:]
    problem = _path_problem(program)
    if problem is not None:
        return problem
    name = program.rsplit("/", 1)[-1].casefold()
    problem = _named_shape(name, program, args)
    if problem is not None:
        return problem
    if name in ("sqlite3", "powermetrics"):
        return f"{name} without sandbox-exec in front of it"
    if program == _SUDO_PROGRAM:
        return _scan_sudo(args, published_path=published_path)
    if program == _SANDBOX_EXEC:
        return _scan_sandbox(args, payload_for_sudo=None)
    if program == _executable():
        if args != ("-I", "-B", "-m", _SCAN_SMART_MODULE):
            return "the interpreter running anything but the SMART child, isolated, with -B"
        return None
    if program == _SYSCTL:
        if len(args) == 2 and args[0] == "-n" and args[1] in _SYSCTL_NAMES:
            if not _SYSCTL_FORM.fullmatch(args[1]):
                return "a sysctl name outside the plain dotted form"
            if args[1] in _SYSCTL_NEVER:
                return "a sysctl name on the never-read list"
            return None
        return "sysctl other than -n and one of its thirteen names"
    if program == _OPEN:
        if published_path is None or args != (published_path,):
            return "open on anything but the file just published"
        return None
    forms = _USER_FORMS.get(program)
    if forms is None:
        return "a program that is not on the fixed list"
    if args not in forms:
        return f"{name} in a form that is not on the fixed list"
    return None


def _named_sudo_problem(head: tuple[str, ...]) -> str | None:
    """A readable reason for the sudo misuses the spec names, where one applies."""
    index = 0
    while index < len(head):
        arg = head[index]
        if arg.startswith("--"):
            return f"sudo with {arg}"
        if arg.startswith("-") and len(arg) > 1:
            for position, letter in enumerate(arg[1:], start=1):
                if letter in "sieT":
                    return f"sudo with -{letter}"
                if letter in "pugChrtUDR":
                    value = arg[position + 1 :]
                    if not value:
                        index += 1
                        value = head[index] if index < len(head) else ""
                    if letter == "u" and value != _SCAN_ACCOUNT:
                        return "sudo -u with an account other than _mmaintenanced"
                    break
        index += 1
    return None


def _scan_sudo(args: tuple[str, ...], *, published_path: str | None) -> str | None:
    if args in _SUDO_CONTROL_FORMS:
        return None
    if "--" not in args:
        return _named_sudo_problem(args) or "sudo in a form that is not on the fixed list"
    split = args.index("--")
    head, inner = args[:split], args[split + 1 :]
    payload = _SUDO_PAYLOAD_HEADS.get(head)
    if payload is None:
        return _named_sudo_problem(head) or "sudo with options other than the fixed ones"
    if not inner or inner[0] != _SANDBOX_EXEC:
        if inner and _path_problem(inner[0]) is None:
            named = _named_shape(inner[0].rsplit("/", 1)[-1].casefold(), inner[0], inner[1:])
            if named is not None:
                return named
        return "sudo in front of anything but a sandboxed payload"
    return _scan_sandbox(inner[1:], payload_for_sudo=payload)


def _profile_problem(profile: str) -> str | None:
    # A character a profile reader treats as a comment, a quote or a string ends the check.
    if not _PROFILE_CHARACTERS.fullmatch(profile):
        return "a sandbox profile with a character outside a-z, 0-9, space, (, ), * and -"
    if not set(re.split(r"[ ()]+", profile)) - {""} <= _PROFILE_WORDS:
        return (
            "a sandbox profile with a word other than version, 1, allow, deny, default,"
            " file-write* and network*"
        )
    if not profile.endswith(_PROFILE_ENDING):
        return "a sandbox profile that does not end by denying file writes and network access"
    if any(clause in profile for clause in _PROFILE_NEVER):
        return "a sandbox profile that allows file writes or network access"
    if profile != _SCAN_PROFILE:
        return "sandbox-exec with a profile other than the fixed one"
    return None


def _sqlite_problem(rest: tuple[str, ...]) -> str | None:
    if any("immutable" in arg for arg in rest):
        return "sqlite3 with immutable"
    if rest[: len(_SQLITE_FIRST)] != _SQLITE_FIRST:
        return "sqlite3 without -init /dev/null -safe -nofollow -readonly first"
    places = [arg for arg in rest if arg.startswith("file:")]
    if len(places) != 1 or not (
        places[0].startswith(_LEDGER_PLACE) and _READ_ONLY_SHM in places[0]
    ):
        return "sqlite3 on a database other than a read-only one under /private/var"
    if not rest[-1].startswith(_QUERY_START):
        return "a ledger query that does not start with PRAGMA query_only=ON"
    if rest != _SCAN_SQLITE_TAIL:
        return "sqlite3 with arguments other than its fixed ones"
    return None


def _option(arg: str) -> tuple[str, str]:
    dashes = "--" if arg.startswith("--") else "-"
    return dashes, arg[len(dashes) :]


def _powermetrics_problem(rest: tuple[str, ...]) -> str | None:
    if any(arg.startswith(("-o", "--o")) for arg in rest):
        return "powermetrics writing to a file"
    if any(arg.startswith("-") and _option(arg) not in _POWERMETRICS_OPTIONS for arg in rest):
        return "powermetrics with an option other than -n, -i, --samplers and --format"
    options = [_option(arg) for arg in rest if arg.startswith("-")]
    if len(options) != len(set(options)):
        return "powermetrics with an option given more than once"
    samplers = rest[rest.index("--samplers") + 1] if "--samplers" in rest[:-1] else ""
    if not samplers or not set(samplers.split(",")) <= _SAMPLER_NAMES:
        return "powermetrics with a sampler other than cpu_power, gpu_power and thermal"
    if rest != _SCAN_POWERMETRICS_TAIL:
        return "powermetrics with arguments other than its fixed ones"
    return None


_PAYLOAD_RULES: Final = MappingProxyType(
    {_SQLITE3: _sqlite_problem, _POWERMETRICS_PROGRAM: _powermetrics_problem}
)


def _scan_sandbox(args: tuple[str, ...], *, payload_for_sudo: str | None) -> str | None:
    if len(args) < 3 or args[0] != "-p":
        return "sandbox-exec with a profile other than the fixed one"
    problem = _profile_problem(args[1])
    if problem is not None:
        return problem
    program, rest = args[2], args[3:]
    problem = _path_problem(program)
    if problem is not None:
        return problem
    if payload_for_sudo is None and program == _TRUE:
        return None if not rest else "sandbox-exec around true with arguments"
    if program not in _PAYLOAD_RULES:
        return "sandbox-exec in front of a program other than the two payloads and X1's true"
    if payload_for_sudo is not None and program != payload_for_sudo:
        if program == _SQLITE3:
            return "sqlite3 under sudo as any account but _mmaintenanced"
        return "powermetrics under sudo -u"
    problem = _PAYLOAD_RULES[program](rest)
    if problem is not None:
        return problem
    if payload_for_sudo is None:
        return "a payload outside sudo"
    return None
