"""The frozen allow-list (docs/VOLTRY_MAC_SPEC.md, "Command allow-list").

Test strategy part 2: item 1 (the pin), item 4 (near misses) and item 5 (forbidden
shapes). The expected argvs below are transcribed from the spec independently of
``voltry_mac.allowlist``, so a change to the list needs a change here too, on purpose.
"""

from __future__ import annotations

import ast
import dataclasses
import inspect
import sys
import types

import pytest

from voltry_mac import allowlist

PROFILE = "(version 1) (allow default) (deny file-write*) (deny network*)"
PROMPT = "Your Mac password, for the two steps above: "
LEDGER_URI = "file:/private/var/db/mmaintenanced/memory_errors.db?readonly_shm=1"
QUERY = (
    "PRAGMA query_only=ON; PRAGMA temp_store=MEMORY; WITH classes(correctable,label) AS "
    "(VALUES(1,'correctable'),(0,'uncorrectable')) SELECT c.label AS class, COUNT(e.ID) AS "
    "event_rows, COALESCE(SUM(e.count),0) AS reported_count FROM classes c LEFT JOIN "
    "ecc_errors_v2 e ON e.correctable=c.correctable GROUP BY c.correctable,c.label ORDER BY "
    "c.correctable DESC;"
)
SQLITE = (
    "/usr/bin/sqlite3",
    "-init",
    "/dev/null",
    "-safe",
    "-nofollow",
    "-readonly",
    "-json",
    "-bail",
    LEDGER_URI,
    QUERY,
)
POWERMETRICS = (
    "/usr/bin/powermetrics",
    "-n",
    "5",
    "-i",
    "1000",
    "--samplers",
    "cpu_power,gpu_power,thermal",
    "--format",
    "plist",
)
SANDBOX = ("/usr/bin/sandbox-exec", "-p", PROFILE)
PUBLISHED = "/Users/owner/Desktop/Voltry Mac Report 2026-09-23 14.05.pdf"
SYSCTL_OIDS = (
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

EXPECTED: dict[str, tuple[str, ...]] = {
    "C1": ("/usr/bin/sw_vers",),
    "C2": ("/usr/sbin/system_profiler", "-json", "SPHardwareDataType"),
    "C3": ("/usr/sbin/system_profiler", "-json", "SPNVMeDataType"),
    "C4": ("/usr/sbin/system_profiler", "-json", "SPDisplaysDataType"),
    "C5": ("/usr/sbin/system_profiler", "-json", "SPMemoryDataType"),
    "C6": ("/usr/sbin/system_profiler", "-json", "SPPowerDataType"),
    "C7": ("/usr/sbin/ioreg", "-r", "-c", "AppleSmartBattery", "-a"),
    "C8": ("/usr/bin/pmset", "-g", "therm"),
    "C9": ("/usr/bin/memory_pressure", "-Q"),
    "C11": ("/usr/sbin/diskutil", "info", "-plist", "/"),
    "C12": ("/usr/bin/csrutil", "status"),
    "C13": ("/usr/sbin/spctl", "--status"),
    "C14": ("/usr/bin/fdesetup", "status"),
    **{f"C{15 + i}": ("/usr/sbin/sysctl", "-n", oid) for i, oid in enumerate(SYSCTL_OIDS)},
    "C26": ("/usr/sbin/sysctl", "-n", "kern.hv_vmm_present"),
    "C27": ("/usr/sbin/sysctl", "-n", "kern.boottime"),
    "C28": (sys.executable, "-I", "-B", "-m", "voltry_mac.smart_iokit"),
    "X1": (*SANDBOX, "/usr/bin/true"),
    "P1": ("/bin/ps", "-axo", "pid,ppid,uid,lstart,comm"),
    "O1": ("/usr/bin/open", PUBLISHED),
    "S1": ("/usr/bin/sudo", "-k"),
    "S2": ("/usr/bin/sudo", "-v", "-p", PROMPT),
    "S3": ("/usr/bin/sudo", "-u", "_mmaintenanced", "-H", "-p", PROMPT, "--", *SANDBOX, *SQLITE),
    "S4": ("/usr/bin/sudo", "-H", "-p", PROMPT, "--", *SANDBOX, *POWERMETRICS),
    "S5": ("/usr/bin/sudo", "-k"),
    "S2n": ("/usr/bin/sudo", "-v", "-n"),
    "S3n": ("/usr/bin/sudo", "-u", "_mmaintenanced", "-H", "-n", "--", *SANDBOX, *SQLITE),
    "S4n": ("/usr/bin/sudo", "-H", "-n", "--", *SANDBOX, *POWERMETRICS),
}

USER_IDS = [f"C{n}" for n in range(1, 10)] + [f"C{n}" for n in range(11, 29)]
SPEC_ORDER = [*USER_IDS, "X1", "P1", "O1", "S1", "S2", "S3", "S4", "S5", "S2n", "S3n", "S4n"]


def _resolve(command_id: str) -> tuple[str, ...]:
    return allowlist.resolve(command_id, published_path=PUBLISHED)


# --- 1. the pin -------------------------------------------------------------------------


def test_the_list_holds_exactly_38_templates_in_the_spec_order():
    assert [c.id for c in allowlist.COMMANDS] == SPEC_ORDER
    assert len(allowlist.COMMANDS) == 38


def test_every_template_resolves_to_the_spec_argv():
    for command_id, argv in EXPECTED.items():
        assert _resolve(command_id) == argv, command_id


def test_the_user_commands_are_the_27_the_report_records():
    assert list(allowlist.USER_COMMAND_IDS) == USER_IDS
    assert len(allowlist.USER_COMMAND_IDS) == 27


def test_the_fixed_strings_are_the_spec_strings():
    assert allowlist.PROFILE == PROFILE
    assert allowlist.PROMPT == PROMPT
    assert allowlist.LEDGER_URI == LEDGER_URI
    assert allowlist.LEDGER_QUERY == QUERY


def test_who_each_command_runs_as():
    runs_as = {c.id: c.runs_as for c in allowlist.COMMANDS}
    assert runs_as.pop("S3") == "service"
    assert runs_as.pop("S3n") == "service"
    assert runs_as.pop("S4") == "root"
    assert runs_as.pop("S4n") == "root"
    assert set(runs_as.values()) == {"user"}, "only S3 and S4 (and their -n forms) run elevated"


def test_timeouts_are_the_spec_timeouts():
    timeouts = {c.id: c.timeout_s for c in allowlist.COMMANDS}
    for command_id in [*USER_IDS[:-1], "X1", "O1", "S1", "S5"]:
        assert timeouts[command_id] == 10, command_id
    assert timeouts["C28"] == 15
    assert timeouts["P1"] == 2
    assert timeouts["S2"] == timeouts["S2n"] == 180
    assert timeouts["S3"] == timeouts["S3n"] == 10
    assert timeouts["S4"] == timeouts["S4n"] == 20


def test_the_in_process_reads_are_r1_to_r5():
    assert [r.id for r in allowlist.IN_PROCESS_READS] == ["R1", "R2", "R3", "R4", "R5"]
    text = {r.id: r.description for r in allowlist.IN_PROCESS_READS}
    assert "/Library/Logs/DiagnosticReports" in text["R1"] and ".panic" in text["R1"]
    assert "/etc/localtime" in text["R2"]
    assert "AppleLocale" in text["R3"]
    assert "sysctl.proc_translated" in text["R4"] and "hw.optional.arm64" in text["R4"]
    assert "kern.osrelease" in text["R4"], "change record 2"
    assert "kern.osproductversion" not in text["R4"], "it answers 10.16 in compatibility mode"
    assert "_mmaintenanced" in text["R5"]


def test_the_list_cannot_be_changed_at_run_time():
    command = allowlist.COMMANDS[0]
    assert isinstance(allowlist.COMMANDS, tuple)
    assert isinstance(command.template, tuple)
    with pytest.raises(dataclasses.FrozenInstanceError):
        command.template = ("/bin/sh",)  # type: ignore[misc]
    with pytest.raises(TypeError):
        allowlist.BY_ID["C1"] = command  # type: ignore[index]


# --- matching: every template, exactly, and nothing else ---------------------------------


def test_every_template_matches_itself():
    for command_id in EXPECTED:
        matched = allowlist.match(_resolve(command_id), published_path=PUBLISHED)
        assert matched is not None and matched.id in (command_id, _twin(command_id))


def _twin(command_id: str) -> str:
    # S1 and S5 are the same argv; the list keeps both IDs because the report records both.
    return {"S1": "S5", "S5": "S1"}.get(command_id, command_id)


def test_the_two_dynamic_arguments_must_equal_their_known_values(monkeypatch):
    c28 = EXPECTED["C28"]
    assert allowlist.match(c28) is not None
    assert allowlist.match(("/usr/bin/python3", *c28[1:])) is None
    monkeypatch.setattr(sys, "executable", "/opt/other/python3")
    assert allowlist.match(c28) is None, "C28 follows sys.executable, nothing else"
    monkeypatch.undo()
    o1 = EXPECTED["O1"]
    assert allowlist.match(o1, published_path=PUBLISHED) is not None
    assert allowlist.match(o1) is None, "O1 needs the path this run just published"
    assert allowlist.match(o1, published_path=PUBLISHED + ".x") is None


def test_a_placeholder_is_never_a_match_by_itself():
    dynamic = [c for c in allowlist.COMMANDS if set(c.template) & set(allowlist.PLACEHOLDERS)]
    assert sorted(c.id for c in dynamic) == ["C28", "O1"]
    for command in dynamic:
        assert allowlist.match(command.template, published_path=PUBLISHED) is None, command.id


def test_resolve_refuses_a_missing_or_relative_dynamic_value():
    with pytest.raises(ValueError):
        allowlist.resolve("O1")
    with pytest.raises(ValueError):
        allowlist.resolve("O1", published_path="Voltry Mac Report.pdf")
    with pytest.raises(KeyError):
        allowlist.resolve("C10")


@pytest.mark.parametrize("executable", ["", "python3", "<the running interpreter>"])
def test_an_unusable_sys_executable_closes_c28(monkeypatch, executable):
    monkeypatch.setattr(sys, "executable", executable)
    with pytest.raises(ValueError):
        allowlist.resolve("C28")
    assert allowlist.match((executable, "-I", "-B", "-m", "voltry_mac.smart_iokit")) is None


def test_nothing_can_rebind_the_interpreter():
    # The spec: C28's interpreter must equal sys.executable. No caller may name another.
    for function in (allowlist.resolve, allowlist.match, allowlist.forbidden_shape):
        assert "interpreter" not in inspect.signature(function).parameters, function.__name__


@pytest.mark.parametrize("argv", ["/usr/bin/sw_vers", b"/usr/bin/sw_vers", "/usr/bin/sudo -s"])
def test_an_argv_given_as_one_string_is_refused(argv):
    assert allowlist.match(argv) is None
    assert allowlist.forbidden_shape(argv) is not None


def test_display_quotes_literals_and_keeps_placeholders():
    assert allowlist.display(("/usr/bin/sw_vers",)) == "/usr/bin/sw_vers"
    assert allowlist.display(allowlist.BY_ID["X1"].template) == (
        f'/usr/bin/sandbox-exec -p "{PROFILE}" /usr/bin/true'
    )
    assert allowlist.display(allowlist.BY_ID["O1"].template) == (
        "/usr/bin/open <the exact path just published>"
    )
    # A literal holding single quotes and nothing a shell expands inside double quotes is
    # shown in double quotes, as the spec's table writes the aggregate query.
    assert allowlist.display(("/usr/bin/x", "a 'b' c")) == "/usr/bin/x \"a 'b' c\""
    assert allowlist.display(("/usr/bin/x", 'say "$HOME"')) == "/usr/bin/x 'say \"$HOME\"'"


def test_matching_takes_lists_and_tuples_alike():
    assert allowlist.match(list(EXPECTED["C1"])) is not None


# --- 4. near misses -----------------------------------------------------------------------

NEAR_MISSES = {
    "pmset -g therm -a": ("/usr/bin/pmset", "-g", "therm", "-a"),
    "nvram -p -c": ("/usr/sbin/nvram", "-p", "-c"),
    "sysctl assignment": ("/usr/sbin/sysctl", "-n", "hw.model=1"),
    "powermetrics -o": (*EXPECTED["S4"], "-o", "/Users/owner/x.plist"),
    "memory_pressure -Q -S": ("/usr/bin/memory_pressure", "-Q", "-S"),
    "relative sw_vers": ("sw_vers",),
    "software profile": ("/usr/sbin/system_profiler", "-json", "SPSoftwareDataType"),
    "diskutil disk0": ("/usr/sbin/diskutil", "info", "-plist", "disk0"),
    "ps -ef": ("/bin/ps", "-ef"),
    "sudo -s": ("/usr/bin/sudo", "-s"),
    "sudo -T 5": ("/usr/bin/sudo", "-T", "5", "-v", "-p", PROMPT),
    "sudo -u root sqlite3": tuple("root" if p == "_mmaintenanced" else p for p in EXPECTED["S3"]),
    "sudo -u _mmaintenanced powermetrics": (
        "/usr/bin/sudo",
        "-u",
        "_mmaintenanced",
        *EXPECTED["S4"][1:],
    ),
    "payload without sandbox-exec": ("/usr/bin/sudo", "-H", "-p", PROMPT, "--", *POWERMETRICS),
    "profile off by one character": (
        "/usr/bin/sandbox-exec",
        "-p",
        PROFILE.replace("file-write*", "file-write"),
        "/usr/bin/true",
    ),
    "sandbox around false": (*SANDBOX, "/usr/bin/false"),
    "the /var database path": tuple(
        p.replace("file:/private/var/", "file:/var/") for p in EXPECTED["S3"]
    ),
    "open another path": ("/usr/bin/open", "/Users/owner/Desktop/other.pdf"),
    "another interpreter": ("/usr/bin/python3", "-I", "-B", "-m", "voltry_mac.smart_iokit"),
    # Change record 8: C28 runs with -B, so it writes no bytecode.
    "the SMART child writing bytecode": (sys.executable, "-I", "-m", "voltry_mac.smart_iokit"),
}


@pytest.mark.parametrize("argv", list(NEAR_MISSES.values()), ids=list(NEAR_MISSES))
def test_near_misses_are_refused(argv):
    assert allowlist.match(argv, published_path=PUBLISHED) is None


# --- 5. forbidden shapes --------------------------------------------------------------------


def test_no_template_in_the_frozen_set_has_a_forbidden_shape():
    for command_id in EXPECTED:
        argv = _resolve(command_id)
        assert allowlist.forbidden_shape(argv, published_path=PUBLISHED) is None, command_id


S3N_HEAD = ("/usr/bin/sudo", "-u", "_mmaintenanced", "-H", "-n", "--", *SANDBOX)
S4N_HEAD = ("/usr/bin/sudo", "-H", "-n", "--", *SANDBOX)

FORBIDDEN = {
    "pmset other than -g therm": ("/usr/bin/pmset", "-g", "batt"),
    "pmset setting": ("/usr/bin/pmset", "-a", "sleep", "0"),
    "nvram read": ("/usr/sbin/nvram", "-p"),
    "nvram under sudo": ("/usr/bin/sudo", "-H", "-n", "--", "/usr/sbin/nvram", "boot-args"),
    "sysctl -w": ("/usr/sbin/sysctl", "-w", "kern.x=1"),
    "sysctl assignment": ("/usr/sbin/sysctl", "kern.x=1"),
    "powermetrics -o": (*SANDBOX, *POWERMETRICS, "-o", "/Users/owner/x.plist"),
    "powermetrics --output-file": (
        *SANDBOX,
        *POWERMETRICS,
        "--output-file",
        "/Users/owner/x.plist",
    ),
    "powermetrics another sampler": tuple(
        "cpu_power,gpu_power,thermal,network" if p == "cpu_power,gpu_power,thermal" else p
        for p in (*SANDBOX, *POWERMETRICS)
    ),
    "memory_pressure -S": ("/usr/bin/memory_pressure", "-S"),
    "memory_pressure -l": ("/usr/bin/memory_pressure", "-l", "warn"),
    "diskutil list": ("/usr/sbin/diskutil", "list"),
    "diskutil erase": ("/usr/sbin/diskutil", "eraseDisk", "APFS", "x", "disk4"),
    "ps other options": ("/bin/ps", "-axo", "pid,command"),
    "csrutil disable": ("/usr/bin/csrutil", "disable"),
    "spctl master-disable": ("/usr/sbin/spctl", "--master-disable"),
    "fdesetup enable": ("/usr/bin/fdesetup", "enable"),
    "sudo -s": ("/usr/bin/sudo", "-s"),
    "sudo -i": ("/usr/bin/sudo", "-i"),
    "sudo -e": ("/usr/bin/sudo", "-e", "/etc/hosts"),
    "sudo -T": ("/usr/bin/sudo", "-T", "5", "-k"),
    "sudo a shell": ("/usr/bin/sudo", "-H", "-n", "--", "/bin/sh", "-c", "true"),
    "sudo -u root before sqlite3": (
        "/usr/bin/sudo",
        "-u",
        "root",
        "-H",
        "-n",
        "--",
        *SANDBOX,
        *SQLITE,
    ),
    "sudo -u before powermetrics": (
        "/usr/bin/sudo",
        "-u",
        "_mmaintenanced",
        "-H",
        "-n",
        "--",
        *SANDBOX,
        *POWERMETRICS,
    ),
    "another sandbox profile": ("/usr/bin/sandbox-exec", "-p", "(version 1)", "/usr/bin/true"),
    "sandbox around another program": (*SANDBOX, "/usr/bin/false"),
    "true under sudo": ("/usr/bin/sudo", "-H", "-n", "--", *SANDBOX, "/usr/bin/true"),
    "payload without sandbox": ("/usr/bin/sudo", "-H", "-n", "--", *POWERMETRICS),
    "sqlite3 bare": SQLITE,
    "a shell": ("/bin/zsh", "-c", "true"),
    "env": ("/usr/bin/env", "sw_vers"),
    "perl": ("/usr/bin/perl", "-e", "1"),
    "osascript": ("/usr/bin/osascript", "-e", "1"),
    "arch": ("/usr/bin/arch", "-arm64", "/usr/bin/sw_vers"),
    "xargs": ("/usr/bin/xargs", "/usr/bin/sw_vers"),
    "the interpreter running code": (sys.executable, "-c", "print(1)"),
    "the SMART child outside isolated mode": (sys.executable, "-B", "-m", "voltry_mac.smart_iokit"),
    "the SMART child writing bytecode": (sys.executable, "-I", "-m", "voltry_mac.smart_iokit"),
    "open another path": ("/usr/bin/open", "/Users/owner/other.pdf"),
    "another interpreter": ("/usr/bin/python3", "-I", "-B", "-m", "voltry_mac.smart_iokit"),
    "relative argv": ("sw_vers",),
    "empty argv": (),
    "sudo --shell": ("/usr/bin/sudo", "--shell"),
    "sudo with an attached -u": ("/usr/bin/sudo", "-uroot", "-H", "-n", "--", *SANDBOX, *SQLITE),
    "sudo -u with no value": ("/usr/bin/sudo", "-u"),
    "sudo -u with no payload": ("/usr/bin/sudo", "-u", "_mmaintenanced", "-v", "-n"),
    "sudo running a program without --": ("/usr/bin/sudo", "/usr/bin/true"),
    "sqlite3 immutable": tuple(p.replace("readonly_shm=1", "immutable=1") for p in EXPECTED["S3"]),
    "powermetrics -s": (*SANDBOX, "/usr/bin/powermetrics", "-s", "cpu_power,gpu_power,thermal"),
    "powermetrics --samplers= another set": (
        *SANDBOX,
        "/usr/bin/powermetrics",
        "--samplers=cpu_power,gpu_power,thermal,network",
    ),
    "powermetrics default samplers": (*SANDBOX, "/usr/bin/powermetrics", "-n", "5"),
    "sandbox around true with arguments": (*SANDBOX, "/usr/bin/true", "x"),
    # From the #336 review: ordinary getopt spellings of the same shapes.
    "powermetrics -xo bundle": (*S4N_HEAD, *POWERMETRICS, "-xo", "/Users/owner/x"),
    "powermetrics -Wo attached": (*S4N_HEAD, *POWERMETRICS, "-Wo/Users/owner/x"),
    "powermetrics --out prefix": (*S4N_HEAD, *POWERMETRICS, "--out", "/Users/owner/x"),
    "powermetrics --sampler= prefix": (*S4N_HEAD, *POWERMETRICS, "--sampler=tasks"),
    "powermetrics -xs bundle": (*S4N_HEAD, *POWERMETRICS, "-xs", "tasks"),
    "powermetrics --show-all": (*S4N_HEAD, *POWERMETRICS, "--show-all"),
    "memory_pressure -QS": ("/usr/bin/memory_pressure", "-QS"),
    "memory_pressure -lwarn": ("/usr/bin/memory_pressure", "-lwarn"),
    "memory_pressure -Sl warn": ("/usr/bin/memory_pressure", "-Sl", "warn"),
    "memory_pressure -p": ("/usr/bin/memory_pressure", "-p", "10"),
    "sysctl -f": ("/usr/sbin/sysctl", "-f", "/Users/owner/writes.conf"),
    "sysctl another option": ("/usr/sbin/sysctl", "-a"),
    # Program paths in other spellings of the same file (APFS is case-insensitive).
    "SUDO -s": ("/usr/bin/SUDO", "-s"),
    "Sudo -u root shell": ("/usr/bin/Sudo", "-u", "root", "--", "/bin/sh"),
    "ZSH": ("/bin/ZSH", "-c", "true"),
    "NVRAM": ("/usr/sbin/NVRAM", "-c"),
    "PMSET": ("/usr/bin/PMSET", "-a", "sleep", "0"),
    "SQLITE3 bare": ("/usr/bin/SQLITE3", "x.db", "DROP TABLE t"),
    "Python3": ("/usr/bin/Python3", "-c", "1"),
    "double slash payload": ("/usr/bin//sqlite3", "x.db", "DROP TABLE t"),
    "dot-dot payload": ("/usr/bin/../bin/powermetrics", "-o", "/Users/owner/x"),
    "leading double slash": ("//usr/bin/sw_vers",),
    # Interpreters under other names, and a program off the fixed list.
    "perl5.34": ("/usr/bin/perl5.34", "-e", "1"),
    "tclsh8.5": ("/usr/bin/tclsh8.5",),
    "swift": ("/usr/bin/swift", "-e", "1"),
    "xcrun": ("/usr/bin/xcrun", "python3", "-c", "1"),
    "a program off the fixed list": ("/usr/sbin/networksetup", "-listallnetworkservices"),
    # The payloads' fixed tails.
    "sqlite3 without -readonly": (
        *S3N_HEAD,
        *(part for part in SQLITE if part != "-readonly"),
    ),
    "sqlite3 without -safe": (*S3N_HEAD, *(part for part in SQLITE if part != "-safe")),
    "sqlite3 another query": (*S3N_HEAD, *SQLITE[:-1], "DELETE FROM ecc_errors_v2;"),
    "sudo -E": ("/usr/bin/sudo", "-E", "-H", "-n", "--", *SANDBOX, *POWERMETRICS),
    "sudo -h swallows -s": ("/usr/bin/sudo", "-h", "-s"),
    "sudo -S": ("/usr/bin/sudo", "-S", "-v"),
    "sudo another prompt": ("/usr/bin/sudo", "-v", "-p", "Password: "),
    # The count as root, which the spec rejects; and the scan's other closing branches.
    "sqlite3 as root": ("/usr/bin/sudo", "-H", "-n", "--", *SANDBOX, *SQLITE),
    "software profile": ("/usr/sbin/system_profiler", "-json", "SPSoftwareDataType"),
    "ioreg everything": ("/usr/sbin/ioreg", "-l"),
    "sw_vers another form": ("/usr/bin/sw_vers", "-productVersion"),
    "sudo with nothing after --": ("/usr/bin/sudo", "-H", "-n", "--"),
    "sudo before a relative payload": ("/usr/bin/sudo", "-H", "-n", "--", "powermetrics"),
    "sandbox around a doubled path": (*SANDBOX, "/usr/bin//true"),
}


@pytest.mark.parametrize("argv", list(FORBIDDEN.values()), ids=list(FORBIDDEN))
def test_each_forbidden_shape_is_caught(argv):
    assert allowlist.forbidden_shape(argv, published_path=PUBLISHED) is not None


def test_a_forbidden_shape_is_never_a_match():
    for argv in FORBIDDEN.values():
        assert allowlist.match(argv, published_path=PUBLISHED) is None


def test_the_scan_does_not_trust_the_templates(monkeypatch):
    # A later edit that adds a writer to the list must still be caught by the scan, so the
    # scan's own table of programs and forms is independent of COMMANDS.
    writer = allowlist.Command("C29", ("/usr/sbin/nvram", "-p"), "user", 10)
    monkeypatch.setattr(allowlist, "COMMANDS", (*allowlist.COMMANDS, writer))
    assert allowlist.forbidden_shape(writer.template) is not None


# --- 5b. the scan keeps its own copies (the #336 round-2 review) ----------------------------
#
# Each case below edits the list in a copy of the module's source, as a later commit might,
# and scans every template of the edited copy with that copy's own scan. The scan must flag
# exactly the commands the edit changed: it holds its own copy of every string it checks,
# so an edit to one of the list's constants changes the list and not the scan.


class _SetTopLevel(ast.NodeTransformer):
    """Give one of the module's top-level constants a new value."""

    def __init__(self, name: str, value_source: str) -> None:
        self.name, self.value_source = name, value_source

    def visit_Module(self, node: ast.Module) -> ast.Module:
        hits = [
            statement
            for statement in node.body
            if isinstance(statement, ast.AnnAssign)
            and isinstance(statement.target, ast.Name)
            and statement.target.id == self.name
        ]
        assert len(hits) == 1, f"{self.name} is not assigned once at the top of allowlist.py"
        hits[0].value = ast.parse(self.value_source, mode="eval").body
        return node


class _ReplaceEverywhere(ast.NodeTransformer):
    """Change every copy of one string in the module, the list's and the scan's alike."""

    def __init__(self, old: str, new: str) -> None:
        self.old, self.new, self.count = old, new, 0

    def visit_Constant(self, node: ast.Constant) -> ast.Constant:
        if node.value == self.old:
            self.count += 1
            return ast.copy_location(ast.Constant(self.new), node)
        return node


def _edited(monkeypatch, transformer: ast.NodeTransformer) -> types.ModuleType:
    tree = transformer.visit(ast.parse(inspect.getsource(allowlist)))
    module = types.ModuleType("voltry_mac.edited_allowlist")
    monkeypatch.setitem(sys.modules, module.__name__, module)
    code = compile(ast.fix_missing_locations(tree), "<edited allowlist>", "exec")
    exec(code, module.__dict__)  # noqa: S102 - the module's own source, edited by the test
    return module


def _flagged(module: types.ModuleType) -> dict[str, str]:
    found = {}
    for command in module.COMMANDS:
        argv = module.resolve(command.id, published_path=PUBLISHED)
        reason = module.forbidden_shape(argv, published_path=PUBLISHED)
        if reason is not None:
            found[command.id] = reason
    return found


SANDBOXED = {"X1", "S3", "S4", "S3n", "S4n"}
LEDGER_READS = {"S3", "S3n"}
POWER_SAMPLES = {"S4", "S4n"}

ONE_CONSTANT_EDITED = {
    "the profile loses (deny file-write*)": (
        "PROFILE",
        repr("(version 1) (allow default) (deny network*)"),
        SANDBOXED,
    ),
    "the profile allows everything": ("PROFILE", repr("(version 1) (allow default)"), SANDBOXED),
    "another prompt": ("PROMPT", repr("Password: "), {"S2", "S3", "S4"}),
    "the count as root": ("SERVICE_ACCOUNT", repr("root"), LEDGER_READS),
    "an immutable ledger address": (
        "LEDGER_URI",
        repr("file:/private/var/db/mmaintenanced/memory_errors.db?immutable=1"),
        LEDGER_READS,
    ),
    "a query that deletes": ("LEDGER_QUERY", repr("DELETE FROM ecc_errors_v2;"), LEDGER_READS),
    "sqlite3 without -safe and -readonly": (
        "_SQLITE",
        repr(tuple(part for part in SQLITE if part not in ("-safe", "-readonly"))),
        LEDGER_READS,
    ),
    "another sampler": ("SAMPLERS", repr("cpu_power,gpu_power,thermal,tasks"), POWER_SAMPLES),
    "powermetrics writing a file": (
        "_POWERMETRICS",
        repr((*POWERMETRICS, "-o", "/tmp/x")),  # noqa: S108 - a path in an edit, never used
        POWER_SAMPLES,
    ),
    "another module in the SMART child": ("SMART_MODULE", repr("voltry_mac.other"), {"C28"}),
    "the host name among the sysctl names": (
        "_SYSCTL_OIDS",
        repr(tuple("kern.hostname" if oid == "hw.target" else oid for oid in SYSCTL_OIDS)),
        {"C16"},
    ),
}


def test_the_unedited_copy_flags_nothing(monkeypatch):
    # The harness itself: an untouched copy of the module scans clean.
    assert _flagged(_edited(monkeypatch, ast.NodeTransformer())) == {}


@pytest.mark.parametrize(
    ("name", "value_source", "expected"),
    list(ONE_CONSTANT_EDITED.values()),
    ids=list(ONE_CONSTANT_EDITED),
)
def test_an_edit_to_one_of_the_lists_constants_is_caught(monkeypatch, name, value_source, expected):
    module = _edited(monkeypatch, _SetTopLevel(name, value_source))
    assert set(_flagged(module)) == expected


PROFILE_CHARACTERS = "a sandbox profile with a character outside a-z, 0-9, space, (, ), * and -"
POWERMETRICS_OPTIONS = "powermetrics with an option other than -n, -i, --samplers and --format"
PROFILE_WORDS = (
    "a sandbox profile with a word other than version, 1, allow, deny, default, file-write*"
    " and network*"
)
POWERMETRICS_TWICE = "powermetrics with an option given more than once"
SYSCTL_FORM = "a sysctl name outside the plain dotted form"

# The rules hold whatever the fixed strings say: when an edit changes every copy of a string,
# the list's and the scan's together, a rule still catches what the spec names.
BOTH_COPIES_EDITED = {
    "the denies come before allow default": (
        PROFILE,
        "(version 1) (deny file-write*) (deny network*) (allow default)",
        SANDBOXED,
        "a sandbox profile that does not end by denying file writes and network access",
    ),
    "an immutable ledger address": (
        LEDGER_URI,
        "file:/private/var/db/mmaintenanced/memory_errors.db?immutable=1",
        LEDGER_READS,
        "sqlite3 with immutable",
    ),
    "a query that deletes": (
        QUERY,
        "DELETE FROM ecc_errors_v2;",
        LEDGER_READS,
        "a ledger query that does not start with PRAGMA query_only=ON",
    ),
    "another sampler": (
        "cpu_power,gpu_power,thermal",
        "cpu_power,gpu_power,thermal,tasks",
        POWER_SAMPLES,
        "powermetrics with a sampler other than cpu_power, gpu_power and thermal",
    ),
    # From the round-3 review: edits that kept the old rules' shape.
    "a profile with a comment": (
        PROFILE,
        "(version 1) (allow default) ; (deny file-write*) (deny network*)",
        SANDBOXED,
        PROFILE_CHARACTERS,
    ),
    "a profile with a quote": (
        PROFILE,
        "(version 1) (allow default) '(deny file-write*) (deny network*)",
        SANDBOXED,
        PROFILE_CHARACTERS,
    ),
    "a bundled -o": ("--format", "-xo", POWER_SAMPLES, POWERMETRICS_OPTIONS),
    "every sampler": ("--format", "--show-all", POWER_SAMPLES, POWERMETRICS_OPTIONS),
    "a sampler given with =": (
        "--samplers",
        "--samplers=tasks",
        POWER_SAMPLES,
        POWERMETRICS_OPTIONS,
    ),
    "the host name": (
        "hw.target",
        "kern.hostname",
        {"C16"},
        "a sysctl name on the never-read list",
    ),
    # From the round-4 review.
    "a redefined deny": (
        PROFILE,
        "(version 1) (allow default) (define deny allow) (deny file-write*) (deny network*)",
        SANDBOXED,
        PROFILE_WORDS,
    ),
    "a redefined deny function": (
        PROFILE,
        "(version 1) (allow default) (define (deny x) x) (deny file-write*) (deny network*)",
        SANDBOXED,
        PROFILE_WORDS,
    ),
    "the host name with a trailing dot": ("hw.target", "kern.hostname.", {"C16"}, SYSCTL_FORM),
}


@pytest.mark.parametrize(
    ("old", "new", "expected", "reason"),
    list(BOTH_COPIES_EDITED.values()),
    ids=list(BOTH_COPIES_EDITED),
)
def test_a_rule_catches_an_edit_made_to_every_copy(monkeypatch, old, new, expected, reason):
    transformer = _ReplaceEverywhere(old, new)
    module = _edited(monkeypatch, transformer)
    assert transformer.count >= 1, "the edit changed nothing"
    assert _flagged(module) == dict.fromkeys(expected, reason)


def test_a_rule_catches_edits_made_to_every_copy_together(monkeypatch):
    # A second --samplers in place of --format, with a sampler in place of plist.
    transformers = [
        _ReplaceEverywhere("--format", "--samplers"),
        _ReplaceEverywhere("plist", "tasks"),
    ]

    class _Both(ast.NodeTransformer):
        def visit(self, node: ast.AST) -> ast.AST:
            for transformer in transformers:
                node = transformer.visit(node)
            return node

    module = _edited(monkeypatch, _Both())
    assert all(transformer.count >= 1 for transformer in transformers)
    assert _flagged(module) == dict.fromkeys(POWER_SAMPLES, POWERMETRICS_TWICE)


S3N = ("/usr/bin/sudo", "-u", "_mmaintenanced", "-H", "-n", "--", *SANDBOX)
S4N = ("/usr/bin/sudo", "-H", "-n", "--", *SANDBOX)
LEDGER_HEAD = SQLITE[:-2]

RULE_REASONS = {
    "denies before allow default": (
        (
            "/usr/bin/sandbox-exec",
            "-p",
            "(version 1) (deny file-write*) (deny network*) (allow default)",
            "/usr/bin/true",
        ),
        "a sandbox profile that does not end by denying file writes and network access",
    ),
    "a profile that allows the network": (
        (
            "/usr/bin/sandbox-exec",
            "-p",
            "(version 1) (allow default) (allow network*) (deny file-write*) (deny network*)",
            "/usr/bin/true",
        ),
        "a sandbox profile that allows file writes or network access",
    ),
    "a profile with another wording": (
        (
            "/usr/bin/sandbox-exec",
            "-p",
            "(version 1)  (allow default) (deny file-write*) (deny network*)",
            "/usr/bin/true",
        ),
        "sandbox-exec with a profile other than the fixed one",
    ),
    "sandbox-exec with no profile": (
        ("/usr/bin/sandbox-exec", "/usr/bin/true"),
        "sandbox-exec with a profile other than the fixed one",
    ),
    "immutable": (
        (*S3N, *LEDGER_HEAD, LEDGER_URI.replace("readonly_shm", "immutable"), QUERY),
        "sqlite3 with immutable",
    ),
    "sqlite3 without -readonly": (
        (*S3N, *(part for part in SQLITE if part != "-readonly")),
        "sqlite3 without -init /dev/null -safe -nofollow -readonly first",
    ),
    "another database": (
        (*S3N, *LEDGER_HEAD, "file:/Users/owner/x.db?readonly_shm=1", QUERY),
        "sqlite3 on a database other than a read-only one under /private/var",
    ),
    "a ledger address without readonly_shm": (
        (*S3N, *LEDGER_HEAD, LEDGER_URI.partition("?")[0], QUERY),
        "sqlite3 on a database other than a read-only one under /private/var",
    ),
    "a query that deletes": (
        (*S3N, *SQLITE[:-1], "DELETE FROM ecc_errors_v2;"),
        "a ledger query that does not start with PRAGMA query_only=ON",
    ),
    "sqlite3 without -json": (
        (*S3N, *(part for part in SQLITE if part != "-json")),
        "sqlite3 with arguments other than its fixed ones",
    ),
    "powermetrics -o": (
        (*S4N, *POWERMETRICS, "-o", "/Users/owner/x.plist"),
        "powermetrics writing to a file",
    ),
    "a fourth sampler": (
        (*S4N, *POWERMETRICS[:6], "cpu_power,gpu_power,thermal,tasks", *POWERMETRICS[7:]),
        "powermetrics with a sampler other than cpu_power, gpu_power and thermal",
    ),
    "no sampler named": (
        (*S4N, *POWERMETRICS[:5], *POWERMETRICS[7:]),
        "powermetrics with a sampler other than cpu_power, gpu_power and thermal",
    ),
    "powermetrics without --format plist": (
        (*S4N, *POWERMETRICS[:-2]),
        "powermetrics with arguments other than its fixed ones",
    ),
    "the count as root": (
        ("/usr/bin/sudo", "-u", "root", "-H", "-n", "--", *SANDBOX, *SQLITE),
        "sudo -u with an account other than _mmaintenanced",
    ),
    "a sandboxed payload outside sudo": ((*SANDBOX, *POWERMETRICS), "a payload outside sudo"),
    "a profile with a comment": (
        (
            "/usr/bin/sandbox-exec",
            "-p",
            "(version 1) (allow default) ; (deny file-write*) (deny network*)",
            "/usr/bin/true",
        ),
        PROFILE_CHARACTERS,
    ),
    "a bundled -o": (
        (*S4N, *POWERMETRICS[:-2], "-xo", "plist"),
        POWERMETRICS_OPTIONS,
    ),
    "--show-all": ((*S4N, *POWERMETRICS, "--show-all"), POWERMETRICS_OPTIONS),
    "a sampler given with =": (
        (*S4N, *POWERMETRICS[:5], "--samplers=cpu_power,gpu_power,thermal", *POWERMETRICS[7:]),
        POWERMETRICS_OPTIONS,
    ),
    "a redefined deny": (
        (
            "/usr/bin/sandbox-exec",
            "-p",
            "(version 1) (allow default) (define deny allow) (deny file-write*) (deny network*)",
            "/usr/bin/true",
        ),
        PROFILE_WORDS,
    ),
    "a second --samplers": (
        (*S4N, *POWERMETRICS[:-2], "--samplers", "tasks"),
        POWERMETRICS_TWICE,
    ),
}


@pytest.mark.parametrize(("argv", "reason"), list(RULE_REASONS.values()), ids=list(RULE_REASONS))
def test_each_rule_names_what_it_caught(argv, reason):
    assert allowlist.forbidden_shape(argv, published_path=PUBLISHED) == reason


SYSCTL_NAMES = (*SYSCTL_OIDS, "kern.hv_vmm_present", "kern.boottime")


@pytest.mark.parametrize("name", SYSCTL_NAMES)
def test_sysctl_reads_its_thirteen_names(name):
    assert allowlist.forbidden_shape(("/usr/sbin/sysctl", "-n", name)) is None


@pytest.mark.parametrize(
    "name",
    ["kern.hostname", "kern.uuid", "kern.bootsessionuuid", "kern.osproductversion", "hw.model2"],
)
def test_sysctl_reads_no_other_name(name):
    # The host name is on the spec's never-read list; the rest are simply not on the list.
    reason = allowlist.forbidden_shape(("/usr/sbin/sysctl", "-n", name))
    assert reason == "sysctl other than -n and one of its thirteen names"


def test_the_running_interpreter_passes_the_scan_however_it_is_spelled(monkeypatch):
    # uv can launch Python by a path that starts with //; C28 must still scan clean, and
    # the same spelling of any other interpreter is still refused.
    monkeypatch.setattr(sys, "executable", "//opt/python/bin/python3.11")
    assert allowlist.forbidden_shape(allowlist.resolve("C28")) is None
    other = ("//usr/bin/python3", "-I", "-B", "-m", "voltry_mac.smart_iokit")
    assert allowlist.forbidden_shape(other) is not None


def test_the_host_name_stays_unread_even_if_the_scans_name_set_lists_it(monkeypatch):
    monkeypatch.setattr(allowlist, "_SYSCTL_NAMES", allowlist._SYSCTL_NAMES | {"kern.hostname"})
    reason = allowlist.forbidden_shape(("/usr/sbin/sysctl", "-n", "kern.hostname"))
    assert reason == "a sysctl name on the never-read list"


@pytest.mark.parametrize("name", ["kern.hostname.", ".kern.hostname", "kern..hostname", "1.10"])
def test_a_sysctl_name_must_be_plain_even_if_the_scans_name_set_lists_it(monkeypatch, name):
    monkeypatch.setattr(allowlist, "_SYSCTL_NAMES", allowlist._SYSCTL_NAMES | {name})
    assert allowlist.forbidden_shape(("/usr/sbin/sysctl", "-n", name)) == SYSCTL_FORM
