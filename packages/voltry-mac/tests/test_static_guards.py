"""Static guards over the package source (docs/VOLTRY_MAC_SPEC.md, Test strategy part 2).

- One spawner (item 3): only the spawn chokepoint may reference a way to start a
  process, including the stdlib helpers that start one on their own
  (``platform.architecture`` runs ``file``, ``uuid.getnode`` can run ``ifconfig``).
- No network: an import scan forbids the network modules (part 3, "No network").
- Zero runtime dependencies: every import is the standard library or the package itself.
- One writer: only the output writer may create, change or remove a file (the
  Architecture's "one output writer is the only component that creates application output
  files"). os.open and open are allowed elsewhere only when called directly with flags or
  a mode the scan can read and that only read, and os.open(os.devnull, os.O_WRONLY), which
  creates nothing, is how the CLI stands in for a stdout that went away. pathlib and the
  modules that write files of their own are refused where they are imported or reached,
  since a method call cannot be told from a read, and so are shutil's and tempfile's
  private helpers and the writer's own private seams. tests/write_spy.py backs this scan
  at run time over the whole test run.
- Never read: the host name is never read (spec, "Never read"), so nothing may call
  uname, whose result carries it. Two functions may name os.uname without calling it:
  the swaps in the SMART child and the preflight (change record 2) that keep ctypes' own
  __init__ from calling it, and runtime spies in test_smart_child.py and test_preflight.py
  check that nothing calls it.
- Nothing hidden: no source file holds a bidirectional control, a line or paragraph
  separator, or a control other than tab and newline, which can make code read
  differently from how it runs.
- No compiled file: a child with nothing compiled shows that once the package is
  imported, no import writes a compiled file (change record 8).
- One character table: no module reads the running Python's Unicode database
  (unicodedata), whose version differs between the Pythons the package supports. The
  renderers take what a character is from characters.py, the static table
  tests/character_table.py writes (Decision 4: another Python reproduces the same content;
  the first audit's G1-08). No module is exempt: canonical.py refuses characters by a fixed
  pattern of code points, and the parsers do not import it. Nor may a module the terminal
  summary or the PDF is drawn from read the database another way (the review of #326,
  round 1, M1): a str predicate or case map (isdigit, lower and their kin), a regular
  expression whose classes (\\d, \\w, \\s, [[:...:]]) or IGNORECASE follow the database
  because the pattern is not re.ASCII, re.Scanner unless it is re.ASCII, textwrap, or
  string.capwords. A call that sees ASCII only is exempt by its module and its exact
  source, with why. What this scan cannot see (round 2, n1): a str method reached by name
  (getattr, operator.methodcaller) or taken off a string without a call there
  (``m = text.casefold``); int, float and Decimal of text, which take the database's
  digits, where the validator admits only ASCII digits in every number a report holds;
  repr, !r and %r, which escape by the database, where the renderers use them only in an
  error's text, and the run names an error by a fixed line, never by its text; and split,
  strip, rstrip, lstrip and splitlines with no argument, whose characters
  tests/test_characters.py pins on every Python instead. stringprep.unicodedata passes too,
  but it is Unicode 3.2.0 on every Python. The parsers, which read what a command printed
  into the report's values, are held to the same scan (the pass-3 pre-audit, P3-output-04).

The scans read the source with ``ast`` and resolve what each name is bound to, so an
alias (``import os as o``, ``from os import system as s``), a ``from`` import or a relative
one, an attribute chain (``o.posix_spawn``) or a private twin (``_socket``,
``_posixsubprocess``) is caught, not only a literal spelling. A chain from an imported
module is followed through what the modules hold, so os, builtins and the writing modules
reached through another module's names (``posixpath.os``, ``threading._os``,
``tokenize._builtin_open``, ``tempfile._shutil``) are named as themselves, and an attribute
that merely shares a module's name (``facts.os``) is not taken for it. So is a module or
function bound again by plain assignment (``x = os``) or a walrus used inline. A name bound
more than once in any way is unknown: a flags name so bound is not known to read, and a
name bound to a module and again is reported by the write and process scans where it is
first bound, unless its other bindings are a class's own attributes and methods. A
parameter is bound only to a module default, never to a default's value; a star import is
refused outright, because it hides what a name is bound to. What a static scan cannot see:
``getattr(module, name)``, a module's ``__dict__`` or ``vars(module)``, ``sys.modules``,
``globals()``, and ``eval`` or ``exec`` of a string (ruff's S102 and S307); a module held
in a container, a class or an instance attribute, passed as an argument, returned by a
function, a lambda or a decorator, chosen by a conditional or boolean expression, bound by
a with statement, captured by a match or bound by a loop; a module's alias bound again
only as a class's own attribute or method; and a foreign function called through ctypes
in the two modules the ctypes rule exempts. tests/write_spy.py catches such a write at run
time when a test runs it from the package's code, within the limits its own docstring
names. Each rule is also shown to fire on a planted module, so a scan that
silently matches nothing cannot pass.
"""

from __future__ import annotations

import ast
import builtins
import functools
import importlib
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
import types
from pathlib import Path

import pytest

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
SOURCE = PACKAGE_ROOT / "voltry_mac"

# Paths inside voltry_mac/ exempt from a rule. The spawn chokepoint (board item MAC 3.2)
# is the only module allowed a process API.
SPAWN_MODULES = {"spawn.py"}
# ctypes can reach libc's system() or posix_spawn(), so it is confined too: the SMART child
# (C28, IOKit) and the preflight's sysctlbyname reads (R4).
CTYPES_MODULES = {"smart_iokit.py", "preflight.py"}

PROCESS_MODULES = {
    "subprocess",
    "pty",
    "multiprocessing",
    "posixsubprocess",
    "concurrent.futures.process",
}
PROCESS_NAMES = {
    "concurrent.futures.ProcessPoolExecutor",
    "platform.architecture",
    "uuid.getnode",
    "uuid.uuid1",
}
PROCESS_FUNCTION_MODULES = {"os", "posix"}
PROCESS_PREFIXES = ("system", "popen", "exec", "spawn", "posix_spawn", "fork", "forkpty")
NETWORK_MODULES = {
    "socket",
    "ssl",
    "http",
    "urllib",
    "ftplib",
    "smtplib",
    "imaplib",
    "poplib",
    "nntplib",
    "telnetlib",
    "xmlrpc",
    "socketserver",
    "asyncio",
    "wsgiref",
    "webbrowser",
    "pydoc",
    "logging.handlers",
}
DYNAMIC_IMPORT_MODULES = {"importlib", "pkgutil", "runpy"}
# The output writer (MAC 3.10) is the only module that may create, change or remove a file.
WRITE_MODULES = {"writer.py"}
WRITE_NAMES = {
    *(
        f"os.{name}"
        for name in (
            "link",
            "symlink",
            "rename",
            "renames",
            "replace",
            "unlink",
            "remove",
            "rmdir",
            "removedirs",
            "mkdir",
            "makedirs",
            "mkfifo",
            "mknod",
            "truncate",
            "ftruncate",
            "chmod",
            "fchmod",
            "lchmod",
            "chown",
            "fchown",
            "lchown",
            "utime",
            "chflags",
            "lchflags",
            "fdopen",
            "setxattr",
            "removexattr",
            "copy_file_range",
            "posix_fallocate",
            "write",
            "pwrite",
            "writev",
            "sendfile",
            "pwritev",
        )
    ),
    *(
        f"shutil.{name}"
        for name in (
            "copy",
            "copy2",
            "copyfile",
            "copymode",
            "copystat",
            "copytree",
            "move",
            "rmtree",
            "make_archive",
            "unpack_archive",
            "chown",
        )
    ),
    *(
        f"tempfile.{name}"
        for name in (
            "mkstemp",
            "mkdtemp",
            "mktemp",
            "NamedTemporaryFile",
            "TemporaryFile",
            "SpooledTemporaryFile",
            "TemporaryDirectory",
        )
    ),
    "io.open",
    "io.FileIO",
    "codecs.open",
    "readline.write_history_file",
    "readline.append_history_file",
}
WRITE_WHOLE_MODULES = {
    "pathlib",
    "sqlite3",
    "zipfile",
    "tarfile",
    "gzip",
    "bz2",
    "lzma",
    "shelve",
    "dbm",
    "logging",
    "fileinput",
    "mmap",
    # Modules that write files of their own (the #354 review, rounds 2 and 3). _pyio is
    # named without its underscore, as every private twin is.
    "pyio",
    "wave",
    "pstats",
    "trace",
    "xml.etree",
    "py_compile",
    "compileall",
    "zipapp",
    "venv",
    "mailbox",
    "cProfile",
    "profile",
    "tracemalloc",
}
# The os.open flags that only read.
READ_FLAGS = {
    "os.O_RDONLY",
    "os.O_NOFOLLOW",
    "os.O_CLOEXEC",
    "os.O_DIRECTORY",
    "os.O_NONBLOCK",
    "os.O_NOCTTY",
    "os.O_SYMLINK",
    "os.O_EVTONLY",
}
DYNAMIC_IMPORT_NAMES = {"builtins.__import__"}
# os.uname() returns the host name, and so do the platform and sysconfig helpers built on
# it.
UNAME_NAMES = {
    "os.uname",
    "posix.uname",
    "platform.uname",
    "platform.node",
    "platform.machine",
    "platform.system",
    "platform.platform",
    "platform.release",
    "platform.version",
    "platform.processor",
    "sysconfig.get_platform",
    "sysconfig.get_host_platform",
}


# Standard-library modules the resolver never imports, since importing them acts:
# antigravity opens a web page, this prints a poem, and the rest print or start a GUI.
NEVER_IMPORTED = frozenset(
    {"antigravity", "this", "__hello__", "__phello__", "idlelib", "tkinter", "turtle", "turtledemo"}
)


def _modules() -> list[Path]:
    return sorted(SOURCE.rglob("*.py"))


def _exempt(path: Path, allowed: set[str]) -> bool:
    """Exemption by the path inside voltry_mac/, never by a file name found anywhere."""
    return path.relative_to(SOURCE).as_posix() in allowed


def _canonical(name: str) -> str:
    """A dotted name with a private twin's leading underscores dropped (_socket: socket)."""
    top, _, rest = name.partition(".")
    top = top.lstrip("_") or top
    return f"{top}.{rest}" if rest else top


@functools.cache
def _write_functions() -> dict[int, str]:
    """The functions that write, by identity, so a private alias of one is named as what it
    is (tokenize._builtin_open is builtins.open)."""
    found = {id(builtins.open): "builtins.open"}
    for name in sorted(WRITE_NAMES):
        module, _, attribute = name.rpartition(".")
        try:
            found.setdefault(id(getattr(importlib.import_module(module), attribute)), name)
        except (ImportError, AttributeError):
            continue
    return found


@functools.cache
def _resolve(chain: str) -> str | None:
    """What an attribute chain from an imported module names, by what the modules hold, not
    by its text: each part is followed while it is a module, and the chain is named from the
    last module reached, or as the write function it reaches. So os through another
    module's name (posixpath.os, threading._os, os.path.os), builtins (enum.bltns,
    inspect.builtins) and the writing modules (tempfile._shutil,
    concurrent.futures._base.logging) are named as themselves, and an attribute that merely
    shares a module's name is not taken for it (the #354 review, round 3). Only the standard
    library and the package are imported, never a module that acts when imported, and never
    a dunder name. None when the chain's base is not such a module."""
    parts = chain.split(".")
    if parts[0] in NEVER_IMPORTED or not (
        parts[0] in sys.stdlib_module_names or parts[0] == "voltry_mac"
    ):
        return None
    try:
        current = importlib.import_module(parts[0])
    except ImportError:
        return None
    index = 1
    while index < len(parts):
        part = parts[index]
        if part.startswith("__"):
            break
        found = getattr(current, part, None)
        if found is None:
            try:
                found = importlib.import_module(f"{current.__name__}.{part}")
            except ImportError:
                break
        if isinstance(found, types.ModuleType):
            current = found
            index += 1
            continue
        known = _write_functions().get(id(found))
        if known is not None:
            return ".".join([known, *parts[index + 1 :]])
        break
    return ".".join([current.__name__, *parts[index:]])


def _named(chain: str) -> str:
    """A chain from a bound name, resolved when the resolver can, as its canonical name."""
    return _canonical(_resolve(chain) or chain)


def _base(node: ast.expr) -> ast.expr:
    """An attribute chain's base, through a walrus used inline: ``(o := os).unlink``."""
    return node.value if isinstance(node, ast.NamedExpr) else node


def _dotted(node: ast.expr, bound: dict[str, str]) -> str | None:
    """What a name or attribute chain is bound to, when its base is a bound name."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = _base(node.value)
    node = _base(node)
    if isinstance(node, ast.Name) and node.id in bound:
        return ".".join([bound[node.id], *reversed(parts)])
    return None


Binding = tuple[str, ast.expr | None, int]  # a name, the value it is bound to, the line


def _bindings(tree: ast.AST) -> tuple[list[Binding], list[Binding], set[str], set[str]]:
    """Every name a statement binds, with the value it is bound to when the scan can read
    one, and its line: an assignment's targets, however many (``a = b = os``), a tuple
    unpacked from a tuple, and an annotated or walrus assignment; and each parameter with
    its default, apart. Also the names bound more than once, in any of those ways or as a
    loop, augmented, import, match, except, function or class target, which the scan cannot
    follow (the #354 review, rounds 2 and 3); and of those, the ones bound more than once
    besides a class's own attributes and methods, which are bound in the class (round 4). A
    name every binding of which imports one and the same module is bound once, however many
    times it is imported: it means that module wherever it is used."""
    pairs: list[Binding] = []
    parameters: list[Binding] = []
    imported_as: dict[str, set[str]] = {}
    imports: dict[str, int] = {}
    members = {
        id(statement)
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef)
        for statement in node.body
    }
    in_class: list[str] = []

    def bind(target: ast.expr, value: ast.expr | None) -> None:
        if isinstance(target, ast.Name):
            pairs.append((target.id, value, target.lineno))
        elif isinstance(target, ast.Tuple | ast.List):
            values = value.elts if isinstance(value, ast.Tuple | ast.List) else None
            if values is not None and len(values) != len(target.elts):
                values = None
            for index, element in enumerate(target.elts):
                bind(element, None if values is None else values[index])

    for node in ast.walk(tree):
        start = len(pairs)
        if isinstance(node, ast.Assign):
            for target in node.targets:
                bind(target, node.value)
        elif isinstance(node, ast.AnnAssign | ast.NamedExpr):
            bind(node.target, node.value)
        elif isinstance(node, ast.AugAssign | ast.For | ast.AsyncFor | ast.comprehension):
            bind(node.target, None)
        elif isinstance(node, ast.withitem) and node.optional_vars is not None:
            bind(node.optional_vars, None)
        elif isinstance(node, ast.arguments):
            positional = [*node.posonlyargs, *node.args]
            defaults = [None] * (len(positional) - len(node.defaults)) + list(node.defaults)
            for argument, default in [
                *zip(positional, defaults, strict=True),
                *zip(node.kwonlyargs, node.kw_defaults, strict=True),
            ]:
                parameters.append((argument.arg, default, argument.lineno))
            for extra in (node.vararg, node.kwarg):
                if extra is not None:
                    parameters.append((extra.arg, None, extra.lineno))
        elif isinstance(node, ast.Import | ast.ImportFrom):
            for alias in node.names:
                name = alias.asname or alias.name.split(".")[0]
                pairs.append((name, None, node.lineno))
                imported_as.setdefault(name, set()).add(_imported(node, alias))
                imports[name] = imports.get(name, 0) + 1
        elif isinstance(node, ast.MatchMapping) and node.rest is not None:
            pairs.append((node.rest, None, node.lineno))
        elif isinstance(
            node,
            ast.MatchAs
            | ast.MatchStar
            | ast.ExceptHandler
            | ast.FunctionDef
            | ast.AsyncFunctionDef
            | ast.ClassDef,
        ) and isinstance(node.name, str):
            pairs.append((node.name, None, node.lineno))
        if id(node) in members:
            in_class.extend(name for name, _, _ in pairs[start:])
    counts: dict[str, int] = {}
    for name, _, _ in [*pairs, *parameters]:
        counts[name] = counts.get(name, 0) + 1
    once = {
        name
        for name, modules in imported_as.items()
        if len(modules) == 1 and imports[name] == counts[name]
    }
    twice = {name for name, count in counts.items() if count > 1 and name not in once}
    return pairs, parameters, twice, {n for n in twice if counts[n] - in_class.count(n) > 1}


def _imported(node: ast.Import | ast.ImportFrom, alias: ast.alias) -> str:
    """What an import binds its name to: the module, or the name inside a module."""
    if isinstance(node, ast.Import):
        return alias.name if alias.asname else alias.name.split(".")[0]
    # A relative import is the package's own: voltry_mac has no subpackages.
    module = (
        node.module
        if not node.level
        else ".".join(part for part in ("voltry_mac", node.module) if part)
    )
    return f"{module}.{alias.name}"


def _follow_assignments(tree: ast.AST, bound: dict[str, str]) -> list[tuple[str, int, str]]:
    """Bind a name assigned from a bound one (``x = os``, ``x: T = o``, ``(x := os)``,
    ``a = b = os``, ``x, y = os, 1``, ``def f(o=os)``), and return each name bound more than
    once one of whose bindings is a module, as (name, line, module).

    A name bound more than once is bound to nothing, since the scan cannot tell which
    binding a use sees. So a flags name bound twice is not known to read, and its open is
    reported; and a name bound to a module and again is returned, for the write and process
    scans to report where it is first bound (the #354 review, round 4), unless its other
    bindings are a class's own attributes and methods. The passes stop when nothing changes,
    so a chain (``y = x`` after ``x = os``) resolves in any order.
    """
    pairs, parameters, twice, rebound = _bindings(tree)
    imported = {name: bound.pop(name) for name in twice if name in bound}
    # A parameter holds whatever a call passes, so it is bound only when its default is a
    # module, never to a default's value: def f(flags=os.O_RDONLY) proves nothing about
    # flags (the #354 review, round 3).
    for name, default, _ in parameters:
        resolved = None if default is None else _dotted(default, bound)
        if (
            resolved is not None
            and name not in twice
            and name not in bound
            and _is_module(resolved)
        ):
            bound[name] = resolved
    for _ in range(len(pairs)):
        changed = False
        for name, value, _ in pairs:
            if value is None or name in twice:
                continue
            resolved = _dotted(value, bound)
            if resolved is not None and name not in bound:
                bound[name] = resolved
                changed = True
        if not changed:
            break
    found = []
    for name in sorted(rebound):
        modules = {imported[name]} if name in imported and _is_module(imported[name]) else set()
        for other, value, _ in [*pairs, *parameters]:
            resolved = None if other != name or value is None else _dotted(value, bound)
            if resolved is not None and _is_module(resolved):
                modules.add(resolved)
        line = min(line for other, _, line in [*pairs, *parameters] if other == name)
        found.extend((name, line, module) for module in sorted(modules))
    return found


def _is_module(chain: str) -> bool:
    """Whether a whole chain names a module (os, os.path), not something inside one."""
    resolved = _resolve(chain)
    return resolved is not None and isinstance(sys.modules.get(resolved), types.ModuleType)


def _imports(tree: ast.AST) -> tuple[dict[str, str], list[tuple[str, int, str]]]:
    """What each name is bound to, and every import: (canonical name, line, "imports"). A
    name bound to a module and bound again comes too: ("<name> more than once, once to
    <module>", line, "binds")."""
    bound: dict[str, str] = {}
    found: list[tuple[str, int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.append((_canonical(alias.name), node.lineno, "imports"))
                local = alias.asname or alias.name.split(".")[0]
                bound[local] = alias.name if alias.asname else alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and (node.module or node.level):
            # A relative import is the package's own: voltry_mac has no subpackages.
            module = (
                node.module
                if not node.level
                else ".".join(part for part in ("voltry_mac", node.module) if part)
            )
            assert module is not None
            found.append((_canonical(module), node.lineno, "imports"))
            for alias in node.names:
                full = f"{module}.{alias.name}"
                found.append((_canonical(full), node.lineno, "imports"))
                bound[alias.asname or alias.name] = full
    for name, line, module in _follow_assignments(tree, bound):
        found.append((f"{name} more than once, once to {_canonical(module)}", line, "binds"))
    return bound, found


def _references(path: Path) -> list[tuple[str, int, str]]:
    """Every module or name the source imports or uses: (canonical name, line, how).

    Aliases are resolved: after ``import os as o``, ``o.system`` is reported as
    ``os.system``; after ``from os import system as s``, a use of ``s`` is ``os.system``.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    bound, found = _imports(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            parts: list[str] = [node.attr]
            value = _base(node.value)
            while isinstance(value, ast.Attribute):
                parts.append(value.attr)
                value = _base(value.value)
            if isinstance(value, ast.Name):
                if value.id in bound:
                    # From an imported module: named by what the modules hold.
                    chain = ".".join([bound[value.id], *reversed(parts)])
                    found.append((_named(chain), node.lineno, "reaches"))
                else:
                    chain = ".".join([value.id, *reversed(parts)])
                    found.append((_canonical(chain), node.lineno, "uses"))
        elif isinstance(node, ast.Name):
            if node.id == "__import__":
                found.append(("builtins.__import__", node.lineno, "uses"))
            elif node.id in bound:
                found.append((_canonical(bound[node.id]), node.lineno, "uses"))
    return found


def _within(name: str, modules: set[str]) -> bool:
    return any(name == module or name.startswith(module + ".") for module in modules)


def _report(path: Path, hits: list[tuple[str, int, str]]) -> list[str]:
    return sorted({f"{path.name}:{line}: {how} {name}" for name, line, how in hits})


def process_violations(path: Path) -> list[str]:
    hits = []
    for name, line, how in _references(path):
        module, _, function = name.rpartition(".")
        if (
            _within(name, PROCESS_MODULES)
            or name in PROCESS_NAMES
            or (module in PROCESS_FUNCTION_MODULES and function.startswith(PROCESS_PREFIXES))
            or how == "binds"  # a module name the scan cannot follow
        ):
            hits.append((name, line, how))
    return _report(path, hits)


def unicodedata_violations(path: Path) -> list[str]:
    return _report(path, [ref for ref in _references(path) if _within(ref[0], {"unicodedata"})])


# The str methods whose answer is the running Python's Unicode database: the predicates and
# the case maps.
STR_PREDICATES = {"isdigit", "isdecimal", "isnumeric", "isalpha", "isalnum", "isspace"}
STR_PREDICATES |= {"isprintable", "isupper", "islower", "istitle", "isidentifier"}
CASE_MAPS = {"lower", "upper", "casefold", "title", "capitalize", "swapcase"}
# The regex functions that take a pattern first, with where each takes its flags; and
# re.Scanner, whose first argument is a list of patterns the scan does not read, so only
# re.ASCII lets it through.
PATTERN_FLAGS = {
    "re.compile": 1,
    "re.search": 2,
    "re.match": 2,
    "re.fullmatch": 2,
    "re.findall": 2,
    "re.finditer": 2,
    "re.split": 3,
    "re.sub": 4,
    "re.subn": 4,
    "re.Scanner": 1,
}
# Standard library code that reads the database for itself: textwrap's word breaks (\w and
# \d in its patterns) and string.capwords (split and capitalize).
TEXT_MODULES = {"textwrap"}
TEXT_FUNCTIONS = {"string.capwords"}
# Calls the Unicode scan would refuse that see ASCII only, each by its module and its exact
# source: a new call, or a change to one of these, is refused until someone reads it.
ASCII_ONLY = {
    ("terminal.py", "wording.TITLE.upper()"): "the report's fixed title",
    ("terminal.py", "section.title.upper()"): "a detail section's fixed title (details.py)",
    ("report_pdf.py", "phrases.NOT_REPORTED[0].upper()"): "a fixed phrase",
    ("phrases.py", "self.phrase[:1].upper()"): "a gap's words, all fixed copy",
    ("sections.py", "state.capitalize()"): "the thermal states' fixed names (phrases.STATES)",
    ("pdf.py", "text.isprintable()"): "after text.isascii() in the same test",
    ("pdf.py", "identifier.hex().upper()"): "hexadecimal digits",
    ("registry.py", "state.lower()"): "the thermal states' fixed names (THERMAL_STATES)",
}


def _renderer_modules() -> list[Path]:
    """terminal.py and report_pdf.py, which draw the terminal summary and the PDF, and every
    package module they import, directly or through another."""
    return _imported_from("terminal", "report_pdf")


def _parser_modules() -> list[Path]:
    """The parsers, which read what a command printed into the report's values: parsers.py
    for the user reads, payloads.py for the two payloads and smart.py for the SMART child
    (the Architecture's parsers row), and every package module they import but the
    chokepoint, whose result smart.py reads and which parses nothing into a value."""
    return _imported_from("parsers", "payloads", "smart", but={"spawn"})


def _imported_from(*roots: str, but: set[str] | None = None) -> list[Path]:
    """The modules named and every package module they import, directly or through another,
    leaving out those in ``but`` and what only they import."""
    names, todo = set(but or ()), list(roots)
    while todo:
        name = todo.pop()
        if name in names:
            continue
        names.add(name)
        tree = ast.parse((SOURCE / f"{name}.py").read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                dotted = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level:
                # A relative import is the package's own: voltry_mac has no subpackages.
                dotted = [f"voltry_mac.{node.module or alias.name}" for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module == "voltry_mac":
                dotted = [f"voltry_mac.{alias.name}" for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                dotted = [node.module]
            else:
                continue
            for each in dotted:
                package, _, rest = each.partition(".")
                if package == "voltry_mac" and (SOURCE / f"{rest.split('.')[0]}.py").is_file():
                    todo.append(rest.split(".")[0])
    return sorted(SOURCE / f"{name}.py" for name in names - set(but or ()))


def _flags_say(node: ast.expr | None, bound: dict[str, str], names: set[str]) -> bool:
    """Whether a flags argument holds one of these re flags, alone or or-ed with others."""
    if node is None:
        return False
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _flags_say(node.left, bound, names) or _flags_say(node.right, bound, names)
    name = _dotted(node, bound)
    return name is not None and _named(name) in names


# A pattern's own flags: ASCII for the whole pattern, set at its start, and IGNORECASE,
# there or for a group.
_INLINE_ASCII = re.compile(r"\(\?[aiLmsux]*a[aiLmsux]*\)")
_INLINE_IGNORECASE = re.compile(r"\(\?[aiLmsux]*i[aiLmsux]*(?:-[imsx]*)?[:)]")


def _unicode_classes(pattern: str) -> list[str]:
    """The pattern's classes that follow the Unicode database unless it is re.ASCII: the
    escapes \\d, \\w, \\s and \\b and their capitals, and a POSIX class ([[:...:]])."""
    found, index = [], 0
    while index < len(pattern):
        if pattern[index] == "\\":
            if pattern[index + 1 : index + 2] in tuple("dDwWsSbB"):
                found.append(pattern[index : index + 2])
            index += 2
            continue
        if pattern.startswith("[[:", index):
            found.append("[[:")
        index += 1
    return found


def unicode_violations(path: Path) -> list[str]:
    """What reads the running Python's Unicode database without naming unicodedata: a str
    predicate or case map, called or named on str; a regular expression whose classes or
    IGNORECASE follow the database because it is not re.ASCII, or whose pattern the scan
    cannot read; and textwrap or string.capwords, reached any way. A call in ASCII_ONLY is
    exempt. The module's docstring names what the scan cannot see."""
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    bound, _ = _imports(tree)
    module = path.relative_to(SOURCE).as_posix() if path.is_relative_to(SOURCE) else None
    hits = [
        (name, line, how)
        for name, line, how in _references(path)
        if _within(name, TEXT_MODULES) or name in TEXT_FUNCTIONS
    ]
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in STR_PREDICATES | CASE_MAPS
        ):
            segment = ast.get_source_segment(source, node) or node.func.attr
            if (module, segment) not in ASCII_ONLY:
                hits.append((segment, node.lineno, "calls"))
        if (
            isinstance(node, ast.Attribute)
            and node.attr in STR_PREDICATES | CASE_MAPS
            and isinstance(node.value, ast.Name)
            and node.value.id == "str"
        ):
            hits.append((f"str.{node.attr}", node.lineno, "names"))
        if not isinstance(node, ast.Call):
            continue
        name = _dotted(node.func, bound)
        function = _named(name) if name is not None else None
        if function not in PATTERN_FLAGS:
            continue
        position = PATTERN_FLAGS[function]
        flags = next((k.value for k in node.keywords if k.arg == "flags"), None)
        if flags is None and len(node.args) > position:
            flags = node.args[position]
        pattern = next((k.value for k in node.keywords if k.arg == "pattern"), None)
        if pattern is None and node.args:
            pattern = node.args[0]
        if _flags_say(flags, bound, {"re.ASCII", "re.A"}):
            continue
        if not (isinstance(pattern, ast.Constant) and isinstance(pattern.value, str | bytes)):
            hits.append(("a pattern the scan cannot read", node.lineno, function))
            continue
        if isinstance(pattern.value, bytes) or _INLINE_ASCII.match(pattern.value):
            continue  # a bytes pattern, or one that sets ASCII for itself: (?a)
        classes = _unicode_classes(pattern.value)
        ignoring = _flags_say(flags, bound, {"re.IGNORECASE", "re.I"}) or bool(
            _INLINE_IGNORECASE.search(pattern.value)
        )
        if classes or ignoring:
            said = ", ".join(classes) + (" IGNORECASE" if ignoring else "")
            hits.append(
                (f"a pattern with {said.strip(', ')} and no re.ASCII", node.lineno, function)
            )
    return _report(path, hits)


def ctypes_violations(path: Path) -> list[str]:
    return _report(path, [ref for ref in _references(path) if _within(ref[0], {"ctypes"})])


def network_violations(path: Path) -> list[str]:
    return _report(path, [ref for ref in _references(path) if _within(ref[0], NETWORK_MODULES)])


def dynamic_import_violations(path: Path) -> list[str]:
    hits = [
        ref
        for ref in _references(path)
        if _within(ref[0], DYNAMIC_IMPORT_MODULES) or ref[0] in DYNAMIC_IMPORT_NAMES
    ]
    return _report(path, hits)


def _as_os(name: str) -> str:
    """posix's functions are os's."""
    return "os." + name[len("posix.") :] if name.startswith("posix.") else name


def _opener(node: ast.expr, bound: dict[str, str]) -> str | None:
    """ "os.open" or "open" when the node names one of the two, builtins.open included,
    else None."""
    if isinstance(node, ast.Name) and node.id == "open" and "open" not in bound:
        return "open"
    name = _dotted(node, bound)
    if name is None:
        return None
    name = _as_os(_named(name))
    return {"os.open": "os.open", "builtins.open": "open", "io.open": "open"}.get(name)


def _read_flags(node: ast.expr, bound: dict[str, str]) -> bool:
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _read_flags(node.left, bound) and _read_flags(node.right, bound)
    name = _dotted(node, bound)
    return name is not None and _as_os(_named(name)) in READ_FLAGS


def _only_reads(opener: str, call: ast.Call, bound: dict[str, str]) -> bool:
    """Whether a direct call of os.open or open can be read, and only reads. Arguments
    unpacked with * or ** cannot be read."""
    if any(isinstance(arg, ast.Starred) for arg in call.args) or any(
        keyword.arg is None for keyword in call.keywords
    ):
        return False
    if opener == "os.open":
        target = call.args[0] if call.args else None
        flags = call.args[1] if len(call.args) > 1 else None
        flags = next((k.value for k in call.keywords if k.arg == "flags"), flags)
        if flags is None:
            return False
        devnull = target is not None and _dotted(target, bound) in ("os.devnull", "posix.devnull")
        if devnull and _dotted(flags, bound) in ("os.O_WRONLY", "posix.O_WRONLY"):
            return True  # /dev/null: nothing is created
        return _read_flags(flags, bound)
    modes = list(call.args[1:2]) + [k.value for k in call.keywords if k.arg == "mode"]
    return all(
        isinstance(mode, ast.Constant)
        and isinstance(mode.value, str)
        and not set(mode.value) & set("wax+")
        for mode in modes
    )


def write_violations(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    bound, _ = _imports(tree)
    # A whole module is matched where it is imported, which every use needs (and a dynamic
    # import is its own rule's), so a local name such as profile is not taken for it.
    hits = [
        (name, line, how)
        for name, line, how in _references(path)
        if _as_os(name) in WRITE_NAMES
        or (how in ("imports", "reaches") and _within(name, WRITE_WHOLE_MODULES))
        # shutil's and tempfile's private helpers write, and so do the writer's own seams.
        or name.startswith(("shutil._", "tempfile._", "voltry_mac.writer._"))
        or how == "binds"  # a module name the scan cannot follow
    ]
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    for node in ast.walk(tree):
        # Rebinding an attribute of os (os.devnull, say) changes what every later use means.
        if isinstance(node, ast.Assign | ast.AugAssign | ast.AnnAssign):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                name = _dotted(target, bound) if isinstance(target, ast.Attribute) else None
                if name is not None and _as_os(_named(name)).startswith("os."):
                    hits.append((f"rebinding {name}", node.lineno, "uses"))
        # setattr on os rebinds one of its attributes as surely as an assignment.
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "setattr"
            and "setattr" not in bound
            and node.args
        ):
            name = _dotted(node.args[0], bound)
            if name is not None and _as_os(_named(name)) in ("os", "posix"):
                attribute = node.args[1] if len(node.args) > 1 else None
                what = attribute.value if isinstance(attribute, ast.Constant) else None
                # What a write depends on, or a name the scan cannot read. The SMART child's
                # swap of os.uname, a read, is the uname rule's.
                if (
                    not isinstance(what, str)
                    or what in ("devnull", "open", "fdopen")
                    or (what.startswith("O_") or f"os.{what}" in WRITE_NAMES)
                ):
                    hits.append(("setattr on os", node.lineno, "uses"))
        if not isinstance(node, ast.Attribute | ast.Name):
            continue
        opener = _opener(node, bound)
        if opener is None:
            continue
        call = parents.get(node)
        if not (
            isinstance(call, ast.Call) and call.func is node and _only_reads(opener, call, bound)
        ):
            hits.append((f"{opener} for writing", node.lineno, "uses"))
    return _report(path, hits)


# The two exemptions, by path and function: each swap names os.uname, and nothing else that
# carries the host name, to set it aside while ctypes is imported and to put it back; the
# only call inside it is setattr.
UNAME_SWAPS = {
    "preflight.py": "_uname_swapped_out",
    "smart_iokit.py": "_uname_swapped_out",
}


def _function(path: Path, function: str) -> ast.FunctionDef | None:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return next(
        (n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == function),
        None,
    )


def _function_lines(path: Path, function: str) -> range:
    found = _function(path, function)
    return range(0) if found is None else range(found.lineno, (found.end_lineno or 0) + 1)


def _swap_of(path: Path) -> str | None:
    if not path.is_relative_to(SOURCE):
        return None
    return UNAME_SWAPS.get(path.relative_to(SOURCE).as_posix())


def uname_violations(path: Path) -> list[str]:
    function = _swap_of(path)
    allowed = _function_lines(path, function) if function else range(0)
    hits = [
        ref
        for ref in _references(path)
        if ref[0] in UNAME_NAMES and not (ref[0] == "os.uname" and ref[1] in allowed)
    ]
    return _report(path, hits)


def swap_calls(path: Path) -> list[str]:
    """Inside the exempt swap, any call but setattr."""
    function = _swap_of(path)
    found = _function(path, function) if function else None
    if found is None:
        return []
    return [
        f"{path.name}:{node.lineno}: a call inside the swap"
        for node in ast.walk(found)
        if isinstance(node, ast.Call)
        and not (isinstance(node.func, ast.Name) and node.func.id == "setattr")
    ]


def uname_calls(path: Path) -> list[str]:
    """A call of anything named uname, whatever it is bound to: the swap never calls it."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return [
        f"{path.name}:{node.lineno}: calls uname"
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and (
            (isinstance(node.func, ast.Attribute) and node.func.attr == "uname")
            or (isinstance(node.func, ast.Name) and node.func.id == "uname")
        )
    ]


def star_imports(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return [
        f"{path.name}:{node.lineno}: imports * from {node.module or '.'}"
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and any(alias.name == "*" for alias in node.names)
    ]


def non_stdlib_imports(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    allowed = set(sys.stdlib_module_names) | {"voltry_mac", "__future__"}
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.extend(
                f"{path.name}:{node.lineno}: imports {a.name}"
                for a in node.names
                if a.name.split(".")[0] not in allowed
            )
        elif (
            isinstance(node, ast.ImportFrom)
            and node.level == 0
            and node.module
            and node.module.split(".")[0] not in allowed
        ):
            found.append(f"{path.name}:{node.lineno}: imports {node.module}")
    return found


# --- the standing gates over the real package -------------------------------------------


def test_the_scans_read_the_real_package():
    names = {p.name for p in _modules()}
    assert {"__init__.py", "__main__.py", "cli.py", "allowlist.py"} <= names


def test_only_the_chokepoint_may_start_a_process():
    found = [v for p in _modules() if not _exempt(p, SPAWN_MODULES) for v in process_violations(p)]
    assert not found, "\n".join(found)


def test_ctypes_is_confined_to_the_smart_child_and_the_preflight():
    found = [v for p in _modules() if not _exempt(p, CTYPES_MODULES) for v in ctypes_violations(p)]
    assert not found, "\n".join(found)


def test_the_package_has_no_network_code():
    found = [v for p in _modules() for v in network_violations(p)]
    assert not found, "\n".join(found)


def test_only_the_writer_creates_changes_or_removes_a_file():
    found = [v for p in _modules() if not _exempt(p, WRITE_MODULES) for v in write_violations(p)]
    assert not found, "\n".join(found)


def test_the_write_scan_sees_the_writers_own_writes():
    assert write_violations(SOURCE / "writer.py")


def test_the_package_never_imports_dynamically():
    found = [v for p in _modules() for v in dynamic_import_violations(p)]
    assert not found, "\n".join(found)


def test_no_module_reads_the_running_pythons_unicode_database():
    found = [v for p in _modules() for v in unicodedata_violations(p)]
    assert not found, "\n".join(found)


def test_no_renderer_reads_the_unicode_database_another_way():
    found = [v for p in _renderer_modules() for v in unicode_violations(p)]
    assert not found, "\n".join(found)


def test_the_renderer_modules_are_what_the_summary_and_the_pdf_import():
    assert {path.name for path in _renderer_modules()} == {
        "appendices.py",
        "characters.py",
        "details.py",
        "layout.py",
        "metrics.py",
        "pdf.py",
        "phrases.py",
        "registry.py",
        "report_pdf.py",
        "sections.py",
        "terminal.py",
        "versions.py",
        "wording.py",
    }


def test_no_parser_reads_the_unicode_database_another_way():
    # A sysctl line took str.isprintable()'s word, which is the running Python's: "Apple M5"
    # and U+0CF3, a mark Unicode 15.0.0 added, was unread on 3.11 and read on 3.14 (the
    # pass-3 pre-audit, P3-output-04).
    found = [v for p in _parser_modules() for v in unicode_violations(p)]
    assert not found, "\n".join(found)


def test_the_parser_modules_are_the_parsers_and_what_they_import():
    # characters.py among them: the parsers take what a character is from the table too.
    assert {path.name for path in _parser_modules()} == {
        "canonical.py",
        "characters.py",
        "numbers.py",
        "parsers.py",
        "payloads.py",
        "registry.py",
        "smart.py",
    }


def test_each_ascii_only_call_is_still_in_its_module():
    # An exemption left behind would pass a new call written the same way.
    for module, segment in ASCII_ONLY:
        source = (SOURCE / module).read_text(encoding="utf-8")
        tree = ast.parse(source)
        segments = {ast.get_source_segment(source, node) for node in ast.walk(tree)}
        assert segment in segments, (module, segment)


def test_the_package_never_star_imports():
    found = [v for p in _modules() for v in star_imports(p)]
    assert not found, "\n".join(found)


def test_the_package_never_calls_uname():
    found = [v for p in _modules() for v in uname_violations(p)]
    found += [v for p in _modules() for v in uname_calls(p)]
    found += [v for p in _modules() for v in swap_calls(p)]
    assert not found, "\n".join(found)


def test_the_swaps_are_the_only_exemptions_and_exist():
    assert UNAME_SWAPS == {
        "preflight.py": "_uname_swapped_out",
        "smart_iokit.py": "_uname_swapped_out",
    }
    for module, function in UNAME_SWAPS.items():
        lines = _function_lines(SOURCE / module, function)
        assert len(lines) > 0, f"the exempt function in {module} is gone: drop the exemption"


SWAP_SHAPE = '    real = os.uname\n    setattr(os, "uname", _no_host_name)'


@pytest.mark.parametrize(
    ("imports", "inside"),
    [
        ("", "    real()\n"),
        ("import posix\n", "    peek = posix.uname\n    peek()\n"),
        ("import platform\n", "    platform.node()\n"),
        ("import sysconfig\n", "    sysconfig.get_platform()\n"),
        ("", "    os.uname.__call__()\n"),
    ],
    ids=["the saved uname called", "a posix alias", "platform.node", "sysconfig", "__call__"],
)
@pytest.mark.parametrize("module", sorted(UNAME_SWAPS))
def test_nothing_but_the_swap_passes_inside_it(tmp_path, monkeypatch, module, imports, inside):
    shipped = (SOURCE / module).read_text(encoding="utf-8")
    assert shipped.count(SWAP_SHAPE) == 1
    planted = tmp_path / module
    changed = shipped.replace("import os\n", "import os\n" + imports, 1).replace(
        SWAP_SHAPE, "    real = os.uname\n" + inside + '    setattr(os, "uname", _no_host_name)'
    )
    planted.write_text(changed, encoding="utf-8")
    monkeypatch.setattr(sys.modules[__name__], "SOURCE", tmp_path)
    assert uname_violations(planted) + uname_calls(planted) + swap_calls(planted)


@pytest.mark.parametrize("module", sorted(UNAME_SWAPS))
def test_the_shipped_swap_passes_in_place(tmp_path, monkeypatch, module):
    shipped = (SOURCE / module).read_text(encoding="utf-8")
    (tmp_path / module).write_text(shipped, encoding="utf-8")
    monkeypatch.setattr(sys.modules[__name__], "SOURCE", tmp_path)
    planted = tmp_path / module
    assert not (uname_violations(planted) + uname_calls(planted) + swap_calls(planted))
    outside = shipped + "\n\nPEEK = os.uname\n"
    planted.write_text(outside, encoding="utf-8")
    assert uname_violations(planted), "os.uname outside the swap is refused"


@pytest.mark.parametrize("module", sorted(UNAME_SWAPS))
def test_the_exemption_is_by_path(tmp_path, module):
    planted = tmp_path / module
    planted.write_text(
        "import os\n\ndef _uname_swapped_out():\n    real = os.uname\n", encoding="utf-8"
    )
    assert uname_violations(planted), "a file outside the package is never exempt"


def test_every_import_is_the_standard_library_or_the_package():
    found = [v for p in _modules() for v in non_stdlib_imports(p)]
    assert not found, "\n".join(found)


# Characters that can make source read differently from how it runs (the Trojan Source
# attacks, CVE-2021-42574): the bidirectional controls and marks, the line and paragraph
# separators, the invisible joiners, spaces and hyphens, the byte-order mark, and C0 and
# C1 controls other than tab and newline. Where a test needs one, an escape spells it.
_HIDDEN = re.compile(
    "[\x00-\x08\x0b-\x1f\x7f-\x9f\u00ad\u061c\u180e"
    "\u200b-\u200f\u2028-\u202e\u2060-\u2064\u2066-\u2069\ufeff]"
)


def test_the_hidden_characters_are_the_ones_named():
    for code in (
        0x00,
        0x08,
        0x0B,
        0x1F,
        0x7F,
        0x85,
        0x9F,
        0xAD,
        0x061C,
        0x180E,
        0x200B,
        0x200E,
        0x200F,
        0x2028,
        0x2029,
        0x202A,
        0x202E,
        0x2060,
        0x2064,
        0x2066,
        0x2069,
        0xFEFF,
    ):
        assert _HIDDEN.search(chr(code)), hex(code)
    for text in ("\t", "a", "\u00b0", "\u00e9", "\ufffd"):
        assert not _HIDDEN.search(text), text


def test_no_source_file_holds_a_hidden_character():
    files = sorted([*SOURCE.rglob("*.py"), *(PACKAGE_ROOT / "tests").rglob("*.py")])
    assert len(files) > 10
    found = [
        f"{path.relative_to(PACKAGE_ROOT)}:{number}"
        for path in files
        for number, line in enumerate(path.read_text(encoding="utf-8").split("\n"), 1)
        if _HIDDEN.search(line)
    ]
    assert not found, "\n".join(found)


def test_the_distribution_declares_no_runtime_dependency():
    project = tomllib.loads((PACKAGE_ROOT / "pyproject.toml").read_text())["project"]
    assert project.get("dependencies", []) == []
    assert "optional-dependencies" not in project
    assert project["requires-python"] == ">=3.11"


# --- each rule fires on a planted module ---------------------------------------------------

PLANTED = {
    "process": (
        process_violations,
        [
            "import subprocess",
            "import subprocess as sp",
            "from subprocess import run",
            "import pty",
            "import multiprocessing",
            "from concurrent.futures.process import ProcessPoolExecutor",
            "import os\nos.system('x')",
            # The #354 review, round 2: os through a module that re-exports it.
            "import posixpath\nposixpath.os.system('x')",
            "import shutil\nshutil.os.fork()",
            "import os\nos.popen('x')",
            "import os\nos.execv('/bin/x', ['x'])",
            "import os\nos.spawnv(0, '/bin/x', ['x'])",
            "import os\nos.posix_spawn('/bin/x', ['x'], {})",
            "import os\nos.fork()",
            "from os import posix_spawnp",
            "from os import system",
            # From the #336 review: aliases, the posix module and hidden spawners.
            "import os as o\no.system('x')",
            "import os as _os\n_os.posix_spawn('/bin/x', ['x'], {})",
            "import posix\nposix.system('x')",
            "from posix import fork",
            "import _posixsubprocess",
            "from concurrent.futures import ProcessPoolExecutor",
            "import platform\nplatform.architecture()",
            "import uuid\nuuid.getnode()",
            "from uuid import uuid1",
            # From the round-2 review: a module or function bound again by assignment.
            "import os\nx = os\nx.posix_spawn('/bin/x', ['x'], {})",
            "import os as o\nx = o\ny = x\ny.fork()",
            "import os\nx: object = os\nx.system('x')",
            "import os\nif (x := os):\n    x.execv('/bin/x', ['x'])",
            "import posix\ndef f():\n    x = posix\n    return x.system('x')",
            "import subprocess\nrun = subprocess.run\nrun(['x'])",
            # From the #354 review, round 4: a name bound to a module and bound again.
            "import os\nfor o in ():\n    pass\no = os\no.system('x')",
        ],
    ),
    "ctypes": (
        ctypes_violations,
        ["import ctypes", "from ctypes import CDLL", "import ctypes.util", "import _ctypes"],
    ),
    "network": (
        network_violations,
        [
            "import socket",
            "from socket import create_connection",
            "import ssl",
            "import http.client",
            "from urllib import request",
            "import urllib.request",
            "import asyncio",
            "import xmlrpc.client",
            "import webbrowser",
            "from _socket import socket",
            "import _ssl",
            "from logging.handlers import SocketHandler",
            "import pydoc",
        ],
    ),
    "dynamic import": (
        dynamic_import_violations,
        [
            "import importlib",
            "from importlib import import_module",
            "__import__('subprocess')",
            "import builtins\nbuiltins.__import__('os')",
            "import pkgutil",
            "import runpy",
        ],
    ),
    "uname": (
        uname_violations,
        [
            "import os\nos.uname()",
            "import platform\nplatform.uname()",
            "import platform\nplatform.node()",
            "import platform\nplatform.machine()",
            "import platform\nplatform.system()",
            "from platform import node",
            "import sysconfig\nsysconfig.get_platform()",
            "import platform as p\np.node()",
            "import os as o\no.uname()",
            "import os\ndef _uname_swapped_out():\n    os.uname()",
        ],
    ),
    "uname call": (
        uname_calls,
        ["import os\nos.uname()", "from os import uname\nuname()", "x.uname()"],
    ),
    "non-stdlib": (non_stdlib_imports, ["import requests", "from pydantic import BaseModel"]),
    # The review of #326, round 1, M1: every way a renderer can read the database but
    # unicodedata. Each method is written out, not drawn from the lists the scan reads, so a
    # name dropped from a list fails here (round 2, n1).
    "unicode": (
        unicode_violations,
        [
            "text.isdigit()",
            "text.isdecimal()",
            "text.isnumeric()",
            "text.isalpha()",
            "text.isalnum()",
            "text.isspace()",
            "text.isprintable()",
            "text.isupper()",
            "text.islower()",
            "text.istitle()",
            "text.isidentifier()",
            "text.lower()",
            "text.upper()",
            "text.casefold()",
            "text.title()",
            "text.capitalize()",
            "text.swapcase()",
            "last[-1:].isdigit()",
            "found = map(str.isdigit, units)",
            "found = map(str.casefold, units)",
            "import re\nre.compile(r'\\d+')",
            "import re\nre.compile(r'[^\\W_]')",
            "import re\nre.match(r'\\w+', text)",
            "import re\nre.fullmatch(r'\\S+', text)",
            "import re\nre.search(r'\\bGB', text)",
            "import re\nre.findall(r'\\D', text)",
            "import re\nre.finditer(r'\\B', text)",
            "import re\nre.split(r'\\s+', text)",
            "import re\nre.sub(r'\\s+', ' ', text)",
            "import re\nre.subn(r'\\s+', ' ', text)",
            "import re\nre.compile('[[:digit:]]')",
            "import re\nre.compile('gb', re.IGNORECASE)",
            "import re\nre.compile('gb', flags=re.I | re.M)",
            "import re\nre.compile('(?i)gb')",
            "import re\nre.compile('(?i:gb)')",
            "import re\nre.compile(r'\\d', re.MULTILINE)",
            "import re\nre.compile(pattern, 0)",
            "import re as r\nr.compile(r'\\d')",
            "from re import compile as c\nc(r'\\w')",
            "import re\nre.compile(pattern=r'\\d')",
            # re.UNICODE is the default for a str pattern, never ASCII (round 2, n1).
            "import re\nre.compile(r'\\d', re.U)",
            "import re\nre.search(r'\\w', text, flags=re.UNICODE)",
            "import re\nre.Scanner([(r'\\w+', None)])",
            "import textwrap\ntextwrap.fill(text, 20)",
            "from textwrap import fill\nfill(text, 20)",
            "import string\nstring.capwords(text)",
            "from string import capwords\ncapwords(text)",
        ],
    ),
    "unicodedata": (
        unicodedata_violations,
        [
            "import unicodedata",
            "import unicodedata as u\nu.category('x')",
            "from unicodedata import east_asian_width",
            "from unicodedata import normalize as n\nn('NFC', 'x')",
            "import unicodedata\nclassify = unicodedata.category\nclassify('x')",
            "import unicodedata\nunicodedata.ucd_3_2_0.normalize('NFC', 'x')",
        ],
    ),
    # From the #354 review: every write shape the first guard missed.
    "write": (
        write_violations,
        [
            "import os\nos.unlink('x')",
            "import os\nos.open('x', os.O_WRONLY | os.O_CREAT)",
            "import os\nos.open('x', os.O_RDWR)",
            "import os\nflags = os.O_WRONLY | os.O_CREAT | os.O_EXCL\nos.open('x', flags, 0o600)",
            "import os\nos.open('x', 0x601)",
            "import os\nos.open('x', flags=os.O_WRONLY)",
            "from os import unlink\nunlink('x')",
            "import os as o\no.rename('x', 'y')",
            "import os\nrm = os.remove\nrm('x')",
            "from os import open as o_open, O_WRONLY, O_CREAT\no_open('x', O_WRONLY | O_CREAT)",
            "import os\nopener = os.open\nopener('x', os.O_RDONLY)",
            "import posix\nposix.unlink('x')",
            "import os\nos.write(3, b'x')",
            "import os\nos.fdopen(3, 'w')",
            "import os\nos.chflags('x', 2)",
            "import os\nclass C:\n    devnull = 'report.pdf'\nos.open(C.devnull, os.O_WRONLY)",
            "open('x', 'w')",
            "open('x', mode='a')",
            "open('x', 'r+')",
            "open('x', 'xb')",
            "mode = 'rb'\nopen('x', mode)",
            "o = open\no('x', 'w')",
            "from pathlib import Path\nPath('x').open('w')",
            "from pathlib import Path\nPath('x').rename('y')",
            "import pathlib\npathlib.Path('x').write_bytes(b'')",
            "import io\nio.open('x', 'w')",
            "import codecs\ncodecs.open('x', 'w')",
            "from shutil import rmtree\nrmtree('d')",
            "import shutil as sh\nsh.copyfile('a', 'b')",
            "from tempfile import mkstemp\nmkstemp()",
            "import tempfile\ntempfile.NamedTemporaryFile()",
            "import sqlite3\nsqlite3.connect('x.db')",
            "import zipfile\nzipfile.ZipFile('x.zip', 'w')",
            "import gzip\ngzip.open('x.gz', 'wb')",
            "import logging\nlogging.FileHandler('x.log')",
            # From the #354 review, round 2: os through a module that re-exports it, other
            # spellings of open, a flags name bound twice, bindings the scan did not follow,
            # and more calls and modules that write.
            "import posixpath\nposixpath.os.unlink('x')",
            "import os\nos.path.os.remove('x')",
            "import shutil\nshutil.os.rename('x', 'y')",
            "import builtins\nbuiltins.open('x', 'w')",
            "from builtins import open as o\no('x', 'w')",
            "kw = {'mode': 'w'}\nopen('x', **kw)",
            "args = ('x', 'w')\nopen(*args)",
            "import os\nf = os.O_RDONLY\nf = os.O_WRONLY | os.O_CREAT\nos.open('x', f)",
            "import os\na = b = os\nb.unlink('x')",
            "import os\nx, y = os, 1\nx.unlink('x')",
            "import os\ndef f(o=os):\n    o.unlink('x')",
            "import os\nos.devnull = 'report.pdf'\nos.open(os.devnull, os.O_WRONLY)",
            "import os\nos.pwritev(3, [b'x'], 0)",
            "import readline\nreadline.write_history_file('x')",
            "import py_compile",
            "import compileall",
            "import zipapp",
            "import venv",
            "import mailbox",
            "import cProfile",
            "import profile",
            "import tracemalloc",
            # From the #354 review, round 3. A parameter is never taken for its default's
            # value, and a name bound by an import and again otherwise is unknown.
            "import os\ndef opener(path, flags=os.O_RDONLY):\n    return os.open(path, flags)",
            "import os\ndef quiet(path=os.devnull):\n    return os.open(path, os.O_WRONLY)",
            "import os\nfrom os import O_RDONLY as f\n"
            "f = os.O_WRONLY | os.O_CREAT\nos.open('y', f)",
            # os, builtins and the modules that write, reached through another module's
            # private names: resolved by what the imported module holds, not by the text.
            "import threading\nthreading._os.unlink('x')",
            "import tempfile\ntempfile._os.remove('x')",
            "import random\nrandom._os.unlink('x')",
            "import argparse\nargparse._os.unlink('x')",
            "import enum\nenum.bltns.open('y', 'w')",
            "import codecs\ncodecs.builtins.open('y', 'w')",
            "import inspect\ninspect.builtins.open('y', 'w')",
            "import tokenize\ntokenize._builtin_open('y', 'w')",
            "import tempfile\ntempfile._shutil.rmtree('d')",
            "import tempfile\ntempfile._io.open('y', 'w')",
            "import concurrent.futures\nconcurrent.futures._base.logging.FileHandler('x.log')",
            "import _pyio\n_pyio.open('y', 'w')",
            "import shutil\nshutil._rmtree_unsafe('d', None)",
            "import tempfile\ntempfile._mkstemp_inner('.', 'p', '.s', 0, str)",
            "import wave\nwave.open('y.wav', 'wb')",
            "import pstats\npstats.Stats('prof').dump_stats('y')",
            "import xml.etree.ElementTree as ET\nET.ElementTree(ET.Element('a')).write('y.xml')",
            "import trace",
            "import os\n(o := os).unlink('x')",
            "import os\nsetattr(os, 'devnull', 'report.pdf')",
            # A relative import is the package's own, and the writer's private seams are
            # the writer's alone.
            "from .writer import os as o\no.unlink('x')",
            "from voltry_mac.writer import _unlink",
            "from .writer import _publish",
            # From the #354 review, round 4: a name bound to a module and bound again is
            # reported, not dropped with its uses unreported.
            "import os\ntry:\n    raise ValueError\nexcept ValueError as o:\n    pass\n"
            "o = os\no.unlink('x')",
            "import os as o\no = 1\no.unlink('x')",
            # One name imported as two modules is still two bindings.
            "import os\ndef f():\n    import shutil as os\n    os.rmtree('d')",
        ],
    ),
    "star import": (star_imports, ["from os import *", "from pathlib import *"]),
}


@pytest.mark.parametrize(
    ("rule", "source"),
    [(rule, source) for rule, (_, sources) in PLANTED.items() for source in sources],
)
def test_each_rule_fires_on_a_planted_module(tmp_path, rule, source):
    scan = PLANTED[rule][0]
    planted = tmp_path / "planted.py"
    planted.write_text(source + "\n", encoding="utf-8")
    assert scan(planted), f"{rule} scan missed: {source!r}"


def test_the_rules_leave_ordinary_code_alone(tmp_path):
    planted = tmp_path / "planted.py"
    planted.write_text(
        "import os\nimport sys\nimport threading\n"
        "os.getuid()\nos.environ.get('X')\nsys.executable\n",
        encoding="utf-8",
    )
    for scan, _ in PLANTED.values():
        assert scan(planted) == [], scan.__name__


@pytest.mark.parametrize(
    "source",
    [
        "import os\nos.open(os.devnull, os.O_WRONLY)",
        "import os\nos.open('x', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)",
        "import os\nos.open('x', os.O_RDONLY | os.O_DIRECTORY, dir_fd=3)",
        "open('x')",
        "open('x', 'rb')",
        "open('x', encoding='utf-8')",
        "import shutil\nshutil.which('ls')",
        "import shutil\nshutil.get_terminal_size()",
        "import shutil\nshutil.disk_usage('/')",
        "import tempfile\ntempfile.gettempdir()",
        "import os\nos.read(3, 10)\nos.stat('x')\nos.listdir('.')",
        "import os\nos.open('x', os.O_RDONLY | os.O_SYMLINK)",
        "import os\nos.open('x', os.O_EVTONLY)",
        # From the #354 review, round 3: an attribute named os is not the module.
        "def f(facts):\n    return facts.os.write(1, b'x')",
        "class C:\n    def __init__(self):\n        self.os = []\n    def f(self):\n"
        "        self.os.remove('x')",
        "from voltry_mac.writer import save, NotSaved",
        # From the #354 review, round 4: a class's own method or field that shares a
        # module's name binds it in the class, not where the module is used.
        "import signal\nclass C:\n    def signal(self):\n        return 1\nsignal.getsignal(2)",
        "from voltry_mac import listing\nclass R:\n    listing: str = 'x'\nlisting.Unreadable",
        # One module imported in more than one place, or twice, is one binding: the name
        # means that module wherever it is used (the preflight imports ctypes in three
        # functions).
        "def f():\n    import os\n    return os.getuid()\n"
        "def g():\n    import os\n    return os.getpid()",
        "import os\nimport os\nos.getuid()",
    ],
)
def test_the_write_scan_leaves_reads_alone(tmp_path, source):
    planted = tmp_path / "planted.py"
    planted.write_text(source + "\n", encoding="utf-8")
    assert write_violations(planted) == []


@pytest.mark.parametrize(
    "source",
    [
        "text.isascii()",
        "section.title",
        "'0' <= last[-1:] <= '9'",
        "import re\nre.compile(r'\\d+', re.ASCII)",
        "import re\nre.compile(r'\\d+', flags=re.A | re.M)",
        "import re\nre.compile(r'[0-9]+')",
        "import re\nre.compile(r'(?a)\\w')",
        "import re\nre.compile(rb'\\d')",
        "import re\nre.compile(r'\\\\d')",
        "import re\nre.compile(r'gb', re.ASCII | re.IGNORECASE)",
        "import re\nPATTERN = re.compile(r'[A-Za-z]+')\nPATTERN.fullmatch(text)",
        "import re\nre.Scanner([(r'\\w+', None)], re.ASCII)",
        "import string\nstring.ascii_letters",
    ],
    ids=[
        "isascii",
        "an attribute named title",
        "an ASCII digit test",
        "re.ASCII",
        "re.A with another flag",
        "an explicit class",
        "an inline ASCII flag",
        "a bytes pattern",
        "an escaped backslash before a d",
        "IGNORECASE with re.ASCII",
        "a compiled pattern's own method",
        "a scanner with re.ASCII",
        "string's ASCII letters",
    ],
)
def test_the_unicode_scan_leaves_ascii_alone(tmp_path, source):
    planted = tmp_path / "planted.py"
    planted.write_text(source + "\n", encoding="utf-8")
    assert unicode_violations(planted) == []


def test_an_ascii_only_exemption_is_by_module_and_source(tmp_path):
    # The same call in another module, or another call in an exempt module, is refused.
    planted = tmp_path / "terminal.py"
    planted.write_text("wording.TITLE.upper()\n", encoding="utf-8")
    assert unicode_violations(planted)
    assert ("terminal.py", "wording.TITLE.lower()") not in ASCII_ONLY


def test_exemptions_are_by_path_inside_the_package_not_by_file_name():
    assert _exempt(SOURCE / "writer.py", WRITE_MODULES)
    assert not _exempt(SOURCE / "sub" / "writer.py", WRITE_MODULES)
    assert _exempt(SOURCE / "spawn.py", SPAWN_MODULES)
    assert not _exempt(SOURCE / "vendor" / "spawn.py", SPAWN_MODULES)
    assert _exempt(SOURCE / "smart_iokit.py", CTYPES_MODULES)
    assert not _exempt(SOURCE / "extra" / "smart_iokit.py", CTYPES_MODULES)


def test_the_process_scan_takes_no_attribute_named_os_for_the_module(tmp_path):
    # The #354 review, round 3: a field read such as mac.os.system_version is not os.system.
    planted = tmp_path / "planted.py"
    planted.write_text("def f(mac):\n    return mac.os.system_version\n", encoding="utf-8")
    assert process_violations(planted) == []


def test_the_resolver_never_imports_a_module_that_acts_when_imported(tmp_path, monkeypatch):
    # antigravity opens a web page and this prints a poem when imported: the scan reads
    # their names and never imports them.
    imported: list[str] = []
    real = importlib.import_module
    monkeypatch.setattr(
        importlib, "import_module", lambda name, *rest: imported.append(name) or real(name, *rest)
    )
    planted = tmp_path / "planted.py"
    planted.write_text("import antigravity\nimport this\nantigravity.x.y\nthis.s.t\n")
    write_violations(planted)
    assert not {"antigravity", "this"} & set(imported)


# --- the runtime spy (tests/write_spy.py), the other half of the write scan ------------------

SPY = sys.modules["voltry_mac_test_write_spy"]


def test_the_runtime_spy_sees_a_write_from_the_packages_code(tmp_path):
    target = tmp_path / "x"
    planted = compile("open(target, 'w').close()", SPY.PACKAGE[0] + "planted.py", "exec")
    exec(planted, {"target": str(target)})  # noqa: S102 - the package's frame, planted
    found = list(SPY.WRITES)
    SPY.WRITES.clear()
    assert len(found) == 1 and "planted.py" in found[0]


def test_the_runtime_spy_leaves_the_writer_and_the_tests_alone(tmp_path):
    # Package code that saves through the writer's save writes nothing of its own, and a
    # test's own file is the test's.
    planted = compile(
        "from voltry_mac import writer\n"
        "writer.save(b'%PDF', b'{}', local='2026-09-23T14:05:31-07:00', folder=folder,\n"
        "            cancelled=lambda: False)\n",
        SPY.PACKAGE[0] + "planted.py",
        "exec",
    )
    exec(planted, {"folder": str(tmp_path)})  # noqa: S102 - the package's frame, planted
    (tmp_path / "t").write_text("the test's own file")
    assert SPY.WRITES == []
    assert sorted(path.suffix for path in tmp_path.iterdir()) == ["", ".json", ".pdf"]


def test_the_runtime_spy_knows_a_real_modules_frames(tmp_path):
    # The check that the spy's prefix matches the frames of a module the package really
    # loaded: the writer opens a folder, a read the spy sees as the package's.
    from voltry_mac import writer

    seen = SPY.watching(lambda: os.close(writer._open_folder(str(tmp_path))))
    assert any(name.endswith("writer.py") for name in seen)


def test_the_runtime_spy_sees_the_writers_private_functions_used_elsewhere(tmp_path):
    # Only save, home and base_name are the writer's to be entered by: its private seams,
    # reached from other package code (by getattr, say), are that code's writes (the #354
    # review, round 4).
    (tmp_path / "theirs").write_text("theirs")
    planted = compile(
        "from voltry_mac import writer\n"
        "folder_fd = writer._open_folder(folder)\n"
        "try:\n"
        "    getattr(writer, '_un' + 'link')(folder_fd, 'theirs')\n"
        "finally:\n"
        "    writer._close_folder(folder_fd)\n",
        SPY.PACKAGE[0] + "planted.py",
        "exec",
    )
    exec(planted, {"folder": str(tmp_path)})  # noqa: S102 - the package's frame, planted
    found = list(SPY.WRITES)
    SPY.WRITES.clear()
    assert not (tmp_path / "theirs").exists()
    assert len(found) == 1 and found[0].startswith("os.remove") and "planted.py" in found[0]


def test_the_runtime_spy_leaves_pythons_bytecode_cache_alone(tmp_path, monkeypatch):
    # An import from the package's code writes the imported module's bytecode, which is
    # Python's doing: on a checkout with no bytecode yet it was a false alarm (the #354
    # review, round 4).
    monkeypatch.setattr(sys, "dont_write_bytecode", False)
    (tmp_path / "fresh_module.py").write_text("VALUE = 1\n")
    planted = compile(
        "import importlib.util\n"
        "spec = importlib.util.spec_from_file_location('fresh_module', source)\n"
        "spec.loader.exec_module(importlib.util.module_from_spec(spec))\n",
        SPY.PACKAGE[0] + "planted.py",
        "exec",
    )
    exec(planted, {"source": str(tmp_path / "fresh_module.py")})  # noqa: S102
    found = list(SPY.WRITES)
    SPY.WRITES.clear()
    assert list((tmp_path / "__pycache__").iterdir()), "the import wrote its bytecode"
    assert found == []


def test_the_runtime_spy_sees_a_socket_file_and_a_database_file(tmp_path, monkeypatch):
    # A socket bound to a path and a database sqlite3 connects to are files (the #354
    # review, round 4); an address and a database in memory are not.
    monkeypatch.chdir(tmp_path)  # a short relative path: macOS takes 104 bytes at most
    planted = compile(
        "import socket, sqlite3\n"
        "unix = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"
        "try:\n"
        "    unix.bind('f.sock')\n"
        "finally:\n"
        "    unix.close()\n"
        "sqlite3.connect('e.db').close()\n",
        SPY.PACKAGE[0] + "planted.py",
        "exec",
    )
    exec(planted, {})  # noqa: S102 - the package's frame, planted
    found = list(SPY.WRITES)
    SPY.WRITES.clear()
    assert (tmp_path / "f.sock").exists() and (tmp_path / "e.db").exists()
    assert [entry.split()[0] for entry in found] == ["socket.bind", "sqlite3.connect"]
    assert not SPY._writes("socket.bind", (None, ("127.0.0.1", 0)))
    assert not SPY._writes("sqlite3.connect", (":memory:",))


_AT_EXIT = """
import atexit, importlib.util, os, sys
spec = importlib.util.spec_from_file_location("voltry_mac_test_write_spy", sys.argv[1])
spy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(spy)
spy.install()
atexit.register(os.remove, sys.argv[2])
"""


def test_the_runtime_spy_lets_a_call_at_exit_run(tmp_path):
    # An atexit callback runs with no frame of Python's under the hook: the hook must not
    # fail it, as a shallow stack once did (the #354 review, round 4).
    target = tmp_path / "x"
    target.write_text("x")
    ran = subprocess.run(
        [sys.executable, "-c", _AT_EXIT, SPY.__file__, str(target)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert ran.returncode == 0 and "Traceback" not in ran.stderr, ran.stderr
    assert not target.exists()


def test_the_runtime_spy_fails_a_check_after_a_write_and_starts_the_next_clean():
    # conftest.py checks before each test, after it, and after the last one (the #354
    # review, round 4).
    SPY.WRITES.append("os.remove 'x' from planted.py")
    with pytest.raises(AssertionError, match="before this test began"):
        SPY.check("before this test began")
    assert SPY.WRITES == []
    SPY.check("with nothing since")


# --- compiled files (change record 8) ------------------------------------------------------------
#
# The audit fixes' review, round 3, M1: uv installs its Pythons with no compiled standard
# library, and --compile-bytecode compiles only the tool's own code, so a first run wrote
# about 40 compiled files of the standard library into uv's Python folder, outside the
# tool's install folder. A child with an empty pycache prefix stands for a Python with nothing
# compiled: the package's own first module is compiled as it is imported, before any line of
# it runs, which the install already did; after that, no import writes a compiled file.
_COMPILED = (
    "import os, sys\n"
    "prefix = sys.argv[1]\n"
    "def written():\n"
    "    return {os.path.relpath(os.path.join(folder, name), prefix)\n"
    "            for folder, _, names in os.walk(prefix) for name in names}\n"
    "started = written()\n"
    "import voltry_mac\n"
    "package = written() - started\n"
    "from voltry_mac import cli\n"
    "cli.parse(['--no-root'])\n"
    "cli.dry_run_text()\n"
    "print('off', sys.dont_write_bytecode)\n"
    "for path in sorted(package):\n"
    "    print('package', path)\n"
    "for path in sorted(written() - started - package):\n"
    "    print('after', path)\n"
    "import importlib.util\n"
    "own = importlib.util.cache_from_source(voltry_mac.__file__)\n"
    "print('own', os.path.relpath(own, prefix))\n"
)


def test_the_installed_tool_writes_only_pythons_own_library_caches(tmp_path):
    """Change record 25 (the GPT audit, pass 3, G3-01), from process start: a run of the
    installed tool writes no compiled file of its own code, and with that code compiled as
    `uv tool install --compile-bytecode` compiles it, every compiled file a run writes is a
    copy of Python's own standard library, which Python caches as it starts any program.
    The tool is installed as an installer lays it out: a virtual environment holding the
    package alone and a console script that calls cli.main, run with an empty cache
    prefix and none of Python's environment settings."""
    venv = tmp_path / "venv"
    subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(venv)], check=True)
    python = venv / "bin" / "python"
    query = "import json, sysconfig; p = sysconfig.get_paths(); print(json.dumps(p))"
    paths = json.loads(
        subprocess.run(
            [str(python), "-c", query], capture_output=True, text=True, check=True
        ).stdout
    )
    purelib = Path(paths["purelib"])
    shutil.copytree(
        PACKAGE_ROOT / "voltry_mac",
        purelib / "voltry_mac",
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    script = venv / "bin" / "voltry-mac"
    script.write_text(
        f"#!{python}\nimport sys\nfrom voltry_mac.cli import main\n"
        "if __name__ == '__main__':\n    sys.exit(main())\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    prefix = tmp_path / "pycache"
    env = {name: value for name, value in os.environ.items() if not name.startswith("PYTHON")}
    env.update(PYTHONPYCACHEPREFIX=str(prefix), HOME=str(tmp_path), TMPDIR=str(tmp_path))
    compiled = [str(python), "-m", "compileall", "-q", str(purelib / "voltry_mac")]
    subprocess.run(compiled, env=env, check=True)
    # Keep only the package's own compiled copies: compileall cached the standard-library
    # modules it imported itself, which would hide the ones the run's startup writes.
    package = (purelib / "voltry_mac").resolve()
    for cache in list(prefix.rglob("*.pyc")):
        source = (Path("/") / cache.parent.relative_to(prefix)).resolve()
        if source != package and package not in source.parents:
            cache.unlink()
    before = set(prefix.rglob("*.pyc"))
    assert before, "compileall should have compiled the package into the prefix"
    subprocess.run(
        [str(script), "--dry-run"],
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
    )
    written = set(prefix.rglob("*.pyc")) - before
    assert written, "an empty prefix should have taken Python's own startup caches"
    library = [Path(paths[name]).resolve() for name in ("stdlib", "platstdlib")]
    outside = []
    for cache in sorted(written):
        source = (Path("/") / cache.parent.relative_to(prefix)).resolve()
        if not any(source == root or root in source.parents for root in library):
            outside.append(str(cache.relative_to(prefix)))
    assert outside == [], "compiled files outside Python's own standard library"
    assert not any("voltry_mac" in str(cache) for cache in written)


def test_a_run_writes_no_compiled_file(tmp_path):
    prefix = tmp_path / "pycache"
    prefix.mkdir()
    env = {k: v for k, v in os.environ.items() if k != "PYTHONDONTWRITEBYTECODE"}
    env["PYTHONPYCACHEPREFIX"] = str(prefix)
    ran = subprocess.run(  # noqa: S603 - a test-owned child that imports the package
        [sys.executable, "-c", _COMPILED, str(prefix)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        env=env,
    )
    assert ran.returncode == 0, ran.stderr
    *lines, own = ran.stdout.splitlines()
    assert lines == ["off True", f"package {own.removeprefix('own ')}"]
