"""The live tests' gate (docs/VOLTRY_MAC_SPEC.md, Test strategy part 5, "Live macOS CI";
board items MAC 4.1 and 4.2, issues #323 and #324).

tests_live/ runs the real voltry-mac through sudo, so it may run only in a GitHub Actions
job on a GitHub-hosted runner that asked for it. Its gate is imported here, on every
platform, and shown to refuse this environment, which never sets VOLTRY_MAC_LIVE (only the
steps of .github/workflows/voltry-mac.yml that run gated code do), to refuse every
environment short of all three conditions and every value near the right one, and to
pass only with all three. The live conftest is run here too, in this process, against
every such environment as a mapping, the fixture job's own among them: it must hand the
gate the environment exactly as it finds it, and refuse before it loads anything else.
No process is ever given those variables. Collecting the live folder here stops at its
conftest with the gate's message, and each live test module needs what only the
conftest registers, past the gate. The capture changes the machine it runs on, so its
gate adds root, through sudo from GitHub's runner account, and a virtual machine, and asks
whether this is one only once everything else holds: a refused run reads nothing.
"""

from __future__ import annotations

import ast
import importlib.util
import itertools
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType

import pytest

LIVE = Path(__file__).resolve().parents[1] / "tests_live"
ALL = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "VOLTRY_MAC_LIVE": "1"}
REFUSED = "The voltry-mac live tests run the real command through sudo"
# Every environment short of all three, as the names it sets: none of them, as on a
# developer's Mac; GITHUB_ACTIONS and RUNNER_ENVIRONMENT, as in every job on a
# GitHub-hosted runner that did not ask for the live tests, the fixture job and ci.yml's
# among them; and each of the rest.
SHORT = [names for count in range(len(ALL)) for names in itertools.combinations(sorted(ALL), count)]
FIXTURE_JOB = ("GITHUB_ACTIONS", "RUNNER_ENVIRONMENT")


def _near(value: str) -> list[str]:
    """Values a loose comparison would let through for ``value``: spacing and a line break,
    case, a character more or less at either end, and other ways to write the number one."""
    forms = {
        f" {value}",
        f"{value} ",
        f"\t{value}",
        f"{value}\n",
        f"{value}\r",
        value.upper(),
        value.title(),
        value[1:],
        value[:-1],
        f"{value}{value[-1]}",
        f"{value[0]}{value}",
        f"0{value}",
        f"{value}0",
        f"{value}x",
    }
    if value == "1":
        forms |= {"+1", "1.0", "\uff11", "on", "y"}
    return sorted(forms - {value})


def _gate() -> ModuleType:
    """tests_live/gate.py, loaded by its path: the live folder is not on the import path."""
    name = "voltry_mac_live_gate"
    if name not in sys.modules:
        path = LIVE / "gate.py"
        assert path.is_file(), "tests_live/gate.py, the live tests' gate, does not exist"
        spec = importlib.util.spec_from_file_location(name, path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        sys.modules[name] = module
    return sys.modules[name]


def test_the_gate_refuses_this_environment():
    # Nothing that runs the package's own tests sets VOLTRY_MAC_LIVE: not a Mac, not the
    # fixture job, not ci.yml.
    refused = _gate().refusal(os.environ)
    assert refused is not None and refused.startswith(REFUSED)


def test_the_gate_passes_with_all_three_set():
    gate = _gate()
    assert gate.refusal(ALL) is None
    assert gate.refusal({**os.environ, **ALL}) is None


@pytest.mark.parametrize("left_out", sorted(ALL))
def test_two_of_the_three_are_refused(left_out):
    refused = _gate().refusal({name: value for name, value in ALL.items() if name != left_out})
    assert refused is not None and refused.endswith(
        f"Not set that way here: {left_out}. Nothing was run. The package's own tests are in "
        "agents/voltry-mac/tests."
    )


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("GITHUB_ACTIONS", "false"),
        ("GITHUB_ACTIONS", "True"),
        ("GITHUB_ACTIONS", "1"),
        ("RUNNER_ENVIRONMENT", "self-hosted"),
        ("RUNNER_ENVIRONMENT", "github-hosted "),
        ("VOLTRY_MAC_LIVE", "0"),
        ("VOLTRY_MAC_LIVE", "true"),
        ("VOLTRY_MAC_LIVE", "yes"),
        ("VOLTRY_MAC_LIVE", " 1"),
        ("VOLTRY_MAC_LIVE", "1 "),
        ("VOLTRY_MAC_LIVE", "10"),
        ("VOLTRY_MAC_LIVE", ""),
    ],
)
def test_only_the_exact_value_counts(name, value):
    refused = _gate().refusal({**ALL, name: value})
    assert refused is not None and f"Not set that way here: {name}." in refused


@pytest.mark.parametrize(
    ("name", "value"),
    [(name, near) for name, value in ALL.items() for near in _near(value)],
    ids=repr,
)
def test_a_value_near_the_right_one_is_refused(name, value):
    refused = _gate().refusal({**ALL, name: value})
    assert refused is not None and f"Not set that way here: {name}." in refused


def test_the_refusal_names_all_three_conditions_and_every_one_missing():
    refused = _gate().refusal({})
    assert refused is not None
    assert all(f"{name}={value}" in refused for name, value in ALL.items())
    assert f"Not set that way here: {', '.join(ALL)}." in refused


@pytest.mark.parametrize(
    "present",
    SHORT,
    ids=lambda names: "the fixture job's" if names == FIXTURE_JOB else "+".join(names) or "none",
)
def test_the_conftest_refuses_as_the_gate_does_before_it_loads_anything(present, monkeypatch):
    """The conftest runs here, in this process, with os.environ swapped for a mapping that
    sets ``present`` as the live job would and drops the rest: no process is given them.
    It must raise the gate's refusal for exactly that environment, so it hands the gate
    what it finds and adds nothing, and raise it before it loads live.py or defines the
    shared run. live.py never runs here: a stand-in holds its module name, so a conftest
    that went past the gate would take the stand-in, and show it."""
    gate = _gate()
    environ = {name: value for name, value in os.environ.items() if name not in ALL}
    environ.update((name, ALL[name]) for name in present)
    expected = gate.refusal(environ)
    assert expected is not None
    spec = importlib.util.spec_from_file_location("voltry_mac_live_conftest", LIVE / "conftest.py")
    assert spec is not None and spec.loader is not None
    conftest = importlib.util.module_from_spec(spec)
    raised: BaseException | None = None
    with monkeypatch.context() as patch:
        patch.setattr(os, "environ", environ)
        patch.setitem(sys.modules, "voltry_mac_live", ModuleType("voltry_mac_live"))
        try:
            spec.loader.exec_module(conftest)
        except BaseException as found:  # a skip or an exit would pass for this test's own
            raised = found
    assert isinstance(raised, gate.Refused), f"expected the gate's refusal, not {raised!r}"
    assert str(raised) == expected
    assert "live" not in vars(conftest), "expected the refusal before live.py is loaded"
    assert "main_run" not in vars(conftest), "expected the refusal before the shared run"


def test_every_live_module_needs_what_only_the_gate_registers():
    """A run that skips the conftest (--noconftest, a --confcutdir below the live folder, or
    unittest's discovery) still stops before any test: every live test module imports
    voltry_mac_live, a name only the conftest registers, and only past the gate, and runs
    nothing but imports before it."""
    modules = sorted(LIVE.glob("test*.py"))
    assert len(modules) >= 2, "expected the live checks and the ledger fixtures"
    for path in modules:
        body = ast.parse(path.read_text(encoding="utf-8")).body
        first = next(
            (
                index
                for index, node in enumerate(body)
                if isinstance(node, ast.Import)
                and "voltry_mac_live" in (alias.name for alias in node.names)
            ),
            None,
        )
        assert first is not None, f"{path.name} does not import voltry_mac_live"
        before = body[:first]
        if before and isinstance(before[0], ast.Expr):  # the docstring
            before = before[1:]
        assert all(
            isinstance(node, ast.Import | ast.ImportFrom) for node in before
        ), f"{path.name} runs something before it imports voltry_mac_live"


def test_collecting_the_live_folder_here_stops_at_the_gate(tmp_path):
    """The live conftest raises the refusal before it defines anything, so pytest ends with
    an error that carries the gate's message, and runs and skips nothing. This child only
    collects, and imports nothing of the package: even a broken gate could reach no sudo
    from here."""
    environ = {name: value for name, value in os.environ.items() if name not in ALL}
    environ.pop("PYTEST_ADDOPTS", None)
    environ["PYTHONDONTWRITEBYTECODE"] = "1"
    found = subprocess.run(
        [sys.executable, "-m", "pytest", str(LIVE), "--collect-only", "-p", "no:cacheprovider"],
        cwd=tmp_path,
        env=environ,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=120,
    )
    printed = found.stdout + found.stderr
    # pytest's usage error: a conftest named on the command line failed to load.
    assert found.returncode == 4, printed
    assert REFUSED in printed
    assert "passed" not in printed and "skipped" not in printed
    # No live test module was even collected.
    assert "test_live" not in printed and "test_ledger" not in printed


# --- the capture's gate (MAC 4.2) ----------------------------------------------------------

CHANGE_REFUSED = "The voltry-mac capture changes the machine it runs on"
# What the capture's step gives it on GitHub's macOS images: the gate's three variables,
# and sudo's SUDO_USER, the account GitHub runs every job as.
AS_RUNNER = {**ALL, "SUDO_USER": "runner"}


def _virtual(asked: list[str], answer: object = True) -> Callable[[], object]:
    """A virtual machine check that notes each time it is asked."""

    def virtual() -> object:
        asked.append("asked")
        return answer

    return virtual


def test_the_capture_is_refused_here_and_reads_nothing():
    asked: list[str] = []
    refused = _gate().refusal_to_change(os.environ, euid=os.geteuid(), virtual=_virtual(asked))
    assert refused is not None and refused.startswith(CHANGE_REFUSED)
    assert refused.endswith("Nothing was changed.")
    assert asked == [], "the virtual machine check ran before the other conditions held"


@pytest.mark.parametrize("left_out", sorted(ALL))
def test_the_capture_needs_all_three_variables_even_as_root(left_out):
    asked: list[str] = []
    environ = {name: value for name, value in AS_RUNNER.items() if name != left_out}
    refused = _gate().refusal_to_change(environ, euid=0, virtual=_virtual(asked))
    assert refused is not None and f"Not so here: {left_out}. Nothing was changed." in refused
    assert asked == []


def test_the_capture_needs_root():
    asked: list[str] = []
    refused = _gate().refusal_to_change(AS_RUNNER, euid=501, virtual=_virtual(asked))
    assert refused is not None and "Not so here: root. Nothing was changed." in refused
    assert asked == []


@pytest.mark.parametrize(
    "account", [None, "", "root", "admin", "runner ", "Runner", "runner2"], ids=repr
)
def test_the_capture_needs_sudo_from_the_runner_account(account):
    # A developer's own macOS virtual machine can have the three variables exported and
    # sudo -E, but not by accident the runner account GitHub's images run jobs as.
    asked: list[str] = []
    environ = dict(ALL) if account is None else {**ALL, "SUDO_USER": account}
    refused = _gate().refusal_to_change(environ, euid=0, virtual=_virtual(asked))
    assert refused is not None
    assert "Not so here: sudo from the runner account. Nothing was changed." in refused
    assert asked == []


@pytest.mark.parametrize("answer", [False, None, 1, "1"], ids=["false", "none", "one", "text"])
def test_the_capture_needs_a_virtual_machine(answer):
    asked: list[str] = []
    refused = _gate().refusal_to_change(AS_RUNNER, euid=0, virtual=_virtual(asked, answer))
    assert refused is not None and "Not so here: a virtual machine." in refused
    assert asked == ["asked"]


def test_a_virtual_machine_check_that_fails_is_a_refusal():
    def broken() -> bool:
        raise OSError("sysctl could not run")

    refused = _gate().refusal_to_change(AS_RUNNER, euid=0, virtual=broken)
    assert refused is not None and "Not so here: a virtual machine." in refused


def test_the_capture_passes_as_root_from_the_runner_on_a_virtual_machine_with_all_three_set():
    asked: list[str] = []
    assert _gate().refusal_to_change(AS_RUNNER, euid=0, virtual=_virtual(asked)) is None
    assert asked == ["asked"]


def test_the_refusals_name_every_condition():
    gate = _gate()
    refused = gate.refusal_to_change({}, euid=501, virtual=_virtual([]))
    assert refused is not None
    assert all(f"{name}={value}" in refused for name, value in ALL.items())
    assert "root through sudo from the runner account, and a virtual machine" in refused
    assert f"Not so here: {', '.join(ALL)}, root, sudo from the runner account." in refused
    sandbox = gate.refusal({}, gate.SANDBOX_REFUSAL)
    assert sandbox is not None and sandbox.startswith("The voltry-mac sandbox run")
    assert f"Not set that way here: {', '.join(ALL)}. Nothing was run." in sandbox
    assert gate.refusal(ALL, gate.SANDBOX_REFUSAL) is None
