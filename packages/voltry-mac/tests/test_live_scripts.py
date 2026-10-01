"""The capture's and the sandbox job's scripts, checked here on every platform
(docs/VOLTRY_MAC_SPEC.md, Test strategy part 5, "Live macOS CI", its second and third
bullets; Decision 2's pinned templates and "Stopping a payload"; change records 12 to 14;
board item MAC 4.2, issue #324).

Nothing in tests_live/ may run here: capture.py changes the throwaway virtual machine it
runs on, and sandbox.py runs the CLI under sandbox-exec, and both refuse anywhere else. What
can be checked here is checked here, as data. The capture's template assertions accept each
pinned template's line as that template and no other and refuse a near miss; a template no
case reproduced is held to its sudo source by the package's own test, never to a line of
the capture's making, and never beside its own failing case. What depends on sudo's version
follows the version sudo -V prints. Its judgment of a case's stderr holds each line to the
case, the lecture and the lines sudo prints unchanged. Its safety code runs here against a
folder of its own with every macOS tool faked, and no test can start a real one: installing
a drop-in, removing one or an account only when it is the capture's, the cleanup going on
past an error, the base policy checked first, passwords given to dscl on standard input and
never in an argv or a failure's text, the virtual machine and the invoking account. Each
runtime check of the capture and of the sandbox job is a function of what a probe or a run
sent back, checked here on made-up results, and a failure prints what was seen; and each step
that runs them is run here too, with sudo and the probes faked, so a bad result from any of
them reaches the verdict and a good run fails nothing. The drop-ins
grant nothing without a password and turn off exactly what makes sudo execute directly; the
sandbox profile, parsed as text and never applied, denies the network and every file write
outside its folder, and runs only the user commands' programs and the interpreter; and both
scripts refuse to run on this machine before they read or change anything.
"""

from __future__ import annotations

import ast
import dataclasses
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest
import voltry_mac_test_reports as reports

from voltry_mac import allowlist, sudo_messages, tracking
from voltry_mac.sudo_messages import Class

LIVE = Path(__file__).resolve().parents[1] / "tests_live"
GATE_VARIABLES = ("GITHUB_ACTIONS", "RUNNER_ENVIRONMENT", "VOLTRY_MAC_LIVE")
NEWEST = (1, 9, 17, 2)  # macOS 26.1 and later
OLDEST = (1, 9, 13, 2)  # macOS 15.0 to 15.6 and 26.0 (change record 12)
STOCK = ("pam_permit.so",)


def _load(name: str, file: str) -> ModuleType:
    """A tests_live module, loaded by its path: the live folder is not on the import path."""
    if name not in sys.modules:
        path = LIVE / file
        assert path.is_file(), f"tests_live/{file} does not exist"
        spec = importlib.util.spec_from_file_location(name, path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


def _messages() -> ModuleType:
    return _load("voltry_mac_live_messages", "messages.py")


def _sandbox() -> ModuleType:
    return _load("voltry_mac_live_sandbox", "sandbox.py")


def _capture() -> ModuleType:
    return _load("voltry_mac_live_capture", "capture.py")


def _topology() -> ModuleType:
    return _load("voltry_mac_live_topology", "topology.py")


class _NoTools:
    """What the capture finds in place of subprocess in every test here: a real macOS tool
    started from a test fails it, so no test can reach sudo, visudo, dscl or pwpolicy."""

    TimeoutExpired = subprocess.TimeoutExpired
    DEVNULL = subprocess.DEVNULL
    CompletedProcess = subprocess.CompletedProcess

    @staticmethod
    def run(*args: object, **kwargs: object) -> None:
        raise AssertionError("a test reached a real command")


def _no_fork(*args: object, **kwargs: object) -> None:
    raise AssertionError("a test reached a real fork")


@pytest.fixture(autouse=True)
def _no_tools(monkeypatch, tmp_path):
    """The capture's tools and its one fork faked, the sandbox job's commands too, and the
    capture's sudoers, drop-in folder and PAM file in a folder of the test's own, for every
    test here: no test can start sudo, a macOS tool, sandbox-exec or the CLI."""
    capture = _capture()
    monkeypatch.setattr(capture, "subprocess", _NoTools)
    monkeypatch.setattr(capture, "_fork", _no_fork)
    monkeypatch.setattr(_sandbox(), "subprocess", _NoTools)
    monkeypatch.setattr(capture, "SUDOERS", tmp_path / "sudoers")
    monkeypatch.setattr(capture, "SUDOERS_D", tmp_path / "sudoers.d")
    monkeypatch.setattr(capture, "PAM_SUDO", tmp_path / "pam.d-sudo", raising=False)
    (tmp_path / "sudoers.d").mkdir()


class _Tools:
    """A stand-in for the capture's _run: it notes each argv and what was given on standard
    input, and answers from ``answer`` (exit 0 and nothing printed unless it says)."""

    def __init__(self, answer: Callable[[list[str]], tuple[int, str]] | None = None) -> None:
        self.calls: list[tuple[list[str], str | None]] = []
        self.answer = answer or (lambda argv: (0, ""))

    def __call__(
        self, argv: list[str], *, timeout: float = 60.0, given: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        self.calls.append((list(argv), given))
        code, stdout = self.answer(list(argv))
        return subprocess.CompletedProcess(list(argv), code, stdout, "")


# --- the capture's template assertions ----------------------------------------------------

PINNED = [text for _, text in sudo_messages.TEMPLATES]
# One line each template can stand for, with made-up names: test data for the matching
# alone. The capture holds no template to a line of its own making (below).
SAMPLES = {
    "sudo: account validation failure, is your account locked?": (
        "sudo: account validation failure, is your account locked?"
    ),
    "sudo: Account or password is expired, reset your password and try again": (
        "sudo: Account or password is expired, reset your password and try again"
    ),
    "sudo: unable to change expired password: %s": (
        "sudo: unable to change expired password: Authentication token manipulation error"
    ),
    "sudo: Password expired, contact your system administrator": (
        "sudo: Password expired, contact your system administrator"
    ),
    'sudo: Account expired or PAM config lacks an "account" section for sudo, contact your '
    "system administrator": (
        'sudo: Account expired or PAM config lacks an "account" section for sudo, contact your '
        "system administrator"
    ),
    "Sorry, user %s is not allowed to execute '...' as %s on %s.": (
        "Sorry, user vmcap_plain is not allowed to execute '/usr/bin/id' as root on capture-host."
    ),
    "Sorry, user %s may not run sudo on %s.": (
        "Sorry, user vmcap_unlisted may not run sudo on capture-host."
    ),
    "%s is not allowed to run sudo on %s.": (
        "vmcap_elsewhere is not allowed to run sudo on capture-host."
    ),
    "%s is not in the sudoers file.": "vmcap_unlisted is not in the sudoers file.",
    "sudo: %u incorrect password attempt": "sudo: 1 incorrect password attempt",
    "sudo: a password is required": "sudo: a password is required",
    "sudo: a terminal is required to read the password; either use the -S option to read "
    "from standard input or configure an askpass helper": (
        "sudo: a terminal is required to read the password; either use the -S option to read "
        "from standard input or configure an askpass helper"
    ),
    "sudo: a terminal is required to read the password; either use ssh's -t option or "
    "configure an askpass helper": (
        "sudo: a terminal is required to read the password; either use ssh's -t option or "
        "configure an askpass helper"
    ),
    "sudo: timed out reading password": "sudo: timed out reading password",
    "sudo: no password was provided": "sudo: no password was provided",
}
# For each pinned template, a line one word or one mark away from it, which must match no
# template at all.
NEAR_MISSES = {
    "sudo: account validation failure, is your account locked?": (
        "sudo: account validation failed, is your account locked?"
    ),
    "sudo: Account or password is expired, reset your password and try again": (
        "sudo: Account or password has expired, reset your password and try again"
    ),
    "sudo: unable to change expired password: %s": (
        "sudo: unable to change the expired password: Authentication token manipulation error"
    ),
    "sudo: Password expired, contact your system administrator": (
        "sudo: Password expired, contact the system administrator"
    ),
    'sudo: Account expired or PAM config lacks an "account" section for sudo, contact your '
    "system administrator": (
        'sudo: Account expired or PAM config lacks an "auth" section for sudo, contact your '
        "system administrator"
    ),
    "Sorry, user %s is not allowed to execute '...' as %s on %s.": (
        "Sorry, user vmcap_plain is not allowed to execute /usr/bin/id as root on capture-host."
    ),
    "Sorry, user %s may not run sudo on %s.": (
        "Sorry, user vmcap_unlisted may not use sudo on capture-host."
    ),
    "%s is not allowed to run sudo on %s.": (
        "vmcap_elsewhere is not allowed to use sudo on capture-host."
    ),
    "%s is not in the sudoers file.": "vmcap_unlisted is not in the sudoers file",
    "sudo: %u incorrect password attempt": "sudo: one incorrect password attempt",
    "sudo: a password is required": "sudo: a password was required",
    "sudo: a terminal is required to read the password; either use the -S option to read "
    "from standard input or configure an askpass helper": (
        "sudo: a terminal is required to read the password; either use the -S option to read "
        "from stdin or configure an askpass helper"
    ),
    "sudo: a terminal is required to read the password; either use ssh's -t option or "
    "configure an askpass helper": (
        "sudo: a terminal is required to read the password; either use ssh's -T option or "
        "configure an askpass helper"
    ),
    "sudo: timed out reading password": "sudo: timed out while reading password",
    "sudo: no password was provided": "sudo: no password was given",
}


def test_every_pinned_template_has_a_sample_and_a_near_miss():
    assert list(SAMPLES) == PINNED
    assert list(NEAR_MISSES) == PINNED


@pytest.mark.parametrize("template", PINNED, ids=[text[:40] for text in PINNED])
def test_the_capture_accepts_a_templates_line_as_that_template_and_no_other(template):
    messages = _messages()
    sample = SAMPLES[template]
    assert messages.matching(sample) == (template,)
    assert messages.problem(sample, template) is None
    assert messages.problem(sample + "  \t", template) is None, "trailing whitespace dropped"
    # And refuses it as any other template.
    assert all(messages.problem(sample, other) is not None for other in PINNED if other != template)


@pytest.mark.parametrize("template", PINNED, ids=[text[:40] for text in PINNED])
def test_the_capture_refuses_a_near_miss(template):
    messages = _messages()
    near = NEAR_MISSES[template]
    assert messages.matching(near) == ()
    assert messages.problem(near, template) is not None
    # Text before or after a template is refused, unless a wildcard there takes it.
    sample = SAMPLES[template]
    assert (messages.problem("note: " + sample, template) is None) is template.startswith("%s")
    assert (messages.problem(sample + " (twice)", template) is None) is template.endswith("%s")


def test_the_attempts_template_takes_one_digit_or_several_singular_or_plural():
    messages = _messages()
    template = "sudo: %u incorrect password attempt"
    for line in ("sudo: 1 incorrect password attempt", "sudo: 3 incorrect password attempts"):
        assert messages.problem(line, template) is None, line
    for line in ("sudo: 3a incorrect password attempts", "sudo:  incorrect password attempt"):
        assert messages.problem(line, template) is not None, line


@pytest.mark.parametrize(
    ("line", "template"),
    [
        (
            "Sorry, user  may not run sudo on capture-host.",
            "Sorry, user %s may not run sudo on %s.",
        ),
        (" is not in the sudoers file.", "%s is not in the sudoers file."),
        ("vmcap_elsewhere is not allowed to run sudo on .", "%s is not allowed to run sudo on %s."),
        (
            "sudo: unable to change expired password: ",
            "sudo: unable to change expired password: %s",
        ),
    ],
    ids=["an empty account", "no account", "an empty host", "an empty reason"],
)
def test_each_wildcard_must_hold_something(line, template):
    assert _messages().problem(line, template) is not None


def test_a_quoted_command_may_be_empty():
    line = "Sorry, user vmcap_plain is not allowed to execute '' as root on capture-host."
    assert (
        _messages().problem(line, "Sorry, user %s is not allowed to execute '...' as %s on %s.")
        is None
    )


# A line that fits two templates at once, since each wildcard can take the other's text.
TWICE = [
    "Sorry, user x may not run sudo on y is not allowed to run sudo on z.",
    "Sorry, user x is not allowed to execute 'y' as z on h is not in the sudoers file.",
]


@pytest.mark.parametrize("line", TWICE, ids=["two host refusals", "a refusal and no listing"])
def test_a_line_that_matches_two_templates_is_refused_as_either(line):
    messages = _messages()
    found = messages.matching(line)
    assert len(found) == 2
    assert all(messages.problem(line, template) is not None for template in found)
    problems = messages.judge(_case("a command the drop-in denies"), line + "\n", ignorable=())
    assert any("matches more than one template" in problem for problem in problems)


def test_the_rewritten_authfail_line_matches_no_template_and_is_the_fourth_class():
    messages = _messages()
    assert messages.problem(messages.AUTHFAIL_LINE, None) is None
    assert messages.AUTHFAIL_LINE.startswith("sudo: ") and "%d" not in messages.AUTHFAIL_LINE
    assert sudo_messages.classify(messages.AUTHFAIL_LINE + "\n") is Class.OTHER_SUDO
    assert sudo_messages.classify(messages.CMDDENIAL + "\n") is Class.OTHER


def test_the_cases_ask_for_every_refusal_and_authentication_template():
    # The image must reproduce all ten, the ssh hint only on sudo 1.9.17 and later; the
    # account-state five only where it allows it, which stock macOS never does.
    messages = _messages()
    assert messages.PROMPT == allowlist.PROMPT, "sudo prompts as it does for the tool"
    asked = {text for case in messages.CASES for text in case.expects}
    assert asked == {text for kind, text in sudo_messages.TEMPLATES if kind > Class.ACCOUNT_STATE}
    assert {case.name: case.shows for case in messages.CASES if case.where_allowed} == {
        "a locked account, where the image allows it": "account_state",
        "an expired password, where the image allows it": "account_state",
        "the right password once a failed attempt locked the account, where the image allows it": (
            "refused"
        ),
    }


# --- a template no case reproduced (M3) -----------------------------------------------------


def test_the_capture_holds_no_template_to_a_line_of_its_own_making():
    # A line the capture wrote from a template can only match that template: holding one
    # to the other asserts nothing about sudo.
    messages = _messages()
    assert not hasattr(messages, "SAMPLES") and not hasattr(messages, "pinned_only")
    source = (LIVE / "messages.py").read_text(encoding="utf-8")
    source += (LIVE / "capture.py").read_text(encoding="utf-8")
    assert "pinned source only" not in source


def test_a_template_no_case_reproduced_is_held_to_its_sudo_source_by_the_packages_test():
    messages = _messages()
    said = messages.pinned_lines(set(), set(), version=NEWEST, account_modules=("pam_foo.so",))
    assert len(said) == len(PINNED)
    for template, line in zip(PINNED, said, strict=True):
        assert line == (
            f"not reproduced on this image: {template!r}, held to sudo 1.9.17p2's "
            f"{messages.SOURCES[template]} by {messages.HELD_BY}"
        )
    assert messages.HELD_BY.startswith("agents/voltry-mac/tests/test_sudo_sources.py::")


def test_the_capture_says_why_this_image_could_not_print_a_template():
    messages = _messages()
    said = dict(
        zip(
            PINNED,
            messages.pinned_lines(set(), set(), version=OLDEST, account_modules=STOCK),
            strict=True,
        )
    )
    assert said[messages.NO_TERMINAL_SSH].endswith(
        "; this image's sudo 1.9.13p2 has no ssh hint, which 1.9.17 added"
    )
    for template in PINNED:
        if messages.KIND[template] is Class.ACCOUNT_STATE:
            assert said[template].endswith(
                "; stock macOS's account check, pam_permit.so, never lets sudo print it "
                "(change record 13)"
            )
    newest = messages.pinned_lines(set(), set(), version=NEWEST, account_modules=STOCK)
    assert "ssh hint" not in newest[PINNED.index(messages.NO_TERMINAL_SSH)]


def test_a_template_whose_case_failed_is_never_said_to_be_held_elsewhere():
    messages = _messages()
    reproduced = {messages.REQUIRED}
    failed = {messages.NO_TERMINAL_SSH}
    said = messages.pinned_lines(reproduced, failed, version=NEWEST, account_modules=STOCK)
    assert (
        said[PINNED.index(messages.REQUIRED)] == f"reproduced on this image: {messages.REQUIRED!r}"
    )
    assert said[PINNED.index(messages.NO_TERMINAL_SSH)] == (
        f"not reproduced: {messages.NO_TERMINAL_SSH!r}; the case that asks for it failed above"
    )
    # A template both reproduced and asked for by a case that failed was reproduced.
    both = messages.pinned_lines(reproduced, reproduced, version=NEWEST, account_modules=STOCK)
    assert both[PINNED.index(messages.REQUIRED)].startswith("reproduced on this image")


# --- sudo's version (M1, change record 12) --------------------------------------------------


@pytest.mark.parametrize(
    ("line", "version"),
    [
        ("Sudo version 1.9.13p2", (1, 9, 13, 2)),
        ("Sudo version 1.9.17p2", (1, 9, 17, 2)),
        ("Sudo version 1.9.14", (1, 9, 14, 0)),
        ("Sudo version 1.10.0p12", (1, 10, 0, 12)),
    ],
)
def test_sudos_version_is_read_from_its_first_line(line, version):
    messages = _messages()
    assert messages.parse_version(line) == version
    assert messages.spelled(version) == line.removeprefix("Sudo version ")


@pytest.mark.parametrize(
    "line",
    [
        "",
        "Sudo version 1.9.13p2 ",
        "sudo version 1.9.13p2",
        "Sudo version 1.9",
        "Sudo version 1.9.13p",
        "Sudoers policy plugin version 1.9.13p2",
    ],
)
def test_a_first_line_in_any_other_shape_is_no_version(line):
    assert _messages().parse_version(line) is None


SUDO_V = """Sudo version 1.9.13p2
Sudoers policy plugin version 1.9.13p2
Sudoers file grammar version 50
Sudoers I/O plugin version 1.9.13p2
Sudoers audit plugin version 1.9.13p2

Sudoers path: /etc/sudoers
Authentication methods: 'pam'
Syslog facility if syslog is being used for logging: authpriv
Authentication timestamp timeout: 5.0 minutes
Password prompt timeout: 0.0 minutes
File containing the sudo lecture: /etc/sudo_lecture
Path to mail program: /usr/sbin/sendmail
"""


def test_the_capture_reads_the_version_and_the_lecture_file_from_sudo_v():
    capture = _capture()
    assert capture.read_sudo_v(SUDO_V, 0) == ((1, 9, 13, 2), "/etc/sudo_lecture")
    without = SUDO_V.replace("File containing the sudo lecture: /etc/sudo_lecture\n", "")
    assert capture.read_sudo_v(without, 0) == ((1, 9, 13, 2), None)


@pytest.mark.parametrize(
    ("shown", "said"),
    [
        (SUDO_V.replace("Sudo version 1.9.13p2", "Sudo version 1.9"), "is not sudo's version"),
        ("Sudoers policy plugin version 1.9.13p2\n" + SUDO_V, "is not sudo's version"),
        (SUDO_V + "Log the output of the command being run\n", "an I/O log configured"),
        (
            SUDO_V + "Time in seconds after which the command will be terminated: 60\n",
            "a command timeout configured",
        ),
        (
            SUDO_V.replace("Authentication timestamp timeout: 5.0 minutes\n", ""),
            "listed no sudoers defaults",
        ),
    ],
    ids=["no version", "another first line", "an I/O log", "a command timeout", "no defaults"],
)
def test_the_capture_stops_on_a_sudo_it_cannot_read_or_that_never_executes_directly(shown, said):
    capture = _capture()
    with pytest.raises(capture.Failed, match=re.escape(said)):
        capture.read_sudo_v(shown, 0)


IO_LOG = (
    "Log user's input for the command being run",
    "Log the command's standard input if not connected to a terminal",
    "Log the user's terminal input for the command being run",
    "Log the output of the command being run",
    "Log the command's standard output if not connected to a terminal",
    "Log the command's standard error if not connected to a terminal",
    "Log the terminal output of the command being run",
)


@pytest.mark.parametrize("flag", IO_LOG, ids=[flag[8:40] for flag in IO_LOG])
def test_each_of_the_seven_io_log_flags_stops_the_capture(flag):
    # sudo 1.9.17p2's plugins/sudoers/def_data.in, the same in 1.9.13p2: any I/O log makes
    # sudo run the command behind a monitor, never directly.
    capture = _capture()
    assert capture.IO_LOG == IO_LOG
    with pytest.raises(capture.Failed, match="an I/O log configured"):
        capture.read_sudo_v(SUDO_V + f"    {flag}\n", 0)


def test_a_log_server_or_a_failing_exit_stops_the_capture():
    capture = _capture()
    server = "Sudo log server(s) to connect to with optional port"
    with pytest.raises(capture.Failed, match="a log server configured"):
        capture.read_sudo_v(SUDO_V + f"  {server}\n    logs.example.invalid:30344\n", 0)
    with pytest.raises(capture.Failed, match="sudo -V exited 1"):
        capture.read_sudo_v(SUDO_V, 1)


@pytest.mark.parametrize(
    ("version", "ssh", "monitor", "denial"),
    [
        (OLDEST, False, False, False),
        ((1, 9, 14, 0), False, True, False),
        ((1, 9, 16, 0), False, True, True),
        ((1, 9, 17, 0), True, True, True),
        (NEWEST, True, True, True),
    ],
    ids=["1.9.13p2", "1.9.14", "1.9.16", "1.9.17", "1.9.17p2"],
)
def test_each_version_dependent_expectation_follows_the_version(version, ssh, monitor, denial):
    messages = _messages()
    over_ssh = _case("no terminal, without -S, over ssh without -t")
    planned, why = messages.plan(over_ssh, version)
    assert planned is not None
    if ssh:
        assert (planned, why) == (over_ssh, None)
    else:
        assert planned.expects == (messages.NO_TERMINAL,)
        assert dataclasses.replace(planned, expects=over_ssh.expects) == over_ssh
        assert why is not None and "1.9.17 added the ssh hint" in why
        assert messages.spelled(version) in why
    denied = _case("a command the drop-in denies, with a cmddenial_message")
    planned, why = messages.plan(denied, version)
    assert (planned is denied) is denial
    assert (why is None) is denial
    assert denial or "1.9.16 added cmddenial_message" in str(why)
    for case in messages.CASES:
        if case not in (over_ssh, denied):
            assert messages.plan(case, version) == (case, None), case.name
    said = messages.expectations(version)
    assert all(line.startswith(f"sudo {messages.spelled(version)}: ") for line in said)
    assert ("has no ssh hint" in said[0]) is not ssh
    assert ("runs no monitor" in said[1]) is not monitor
    assert ("has no cmddenial_message" in said[2]) is not denial


def test_the_thresholds_are_sudos_own():
    # sudo's NEWS: the ssh hint in 1.9.17, use_pty by default in 1.9.14, cmddenial_message
    # in 1.9.16. A version compares with its patch level last.
    messages = _messages()
    assert (messages.SSH_HINT_SINCE, messages.MONITOR_SINCE, messages.CMDDENIAL_SINCE) == (
        (1, 9, 17),
        (1, 9, 14),
        (1, 9, 16),
    )
    assert OLDEST < messages.MONITOR_SINCE <= (1, 9, 14, 0) < messages.CMDDENIAL_SINCE
    assert messages.SSH_HINT_SINCE <= NEWEST


# --- judging a case's stderr --------------------------------------------------------------


def _case(name: str) -> object:
    (found,) = [case for case in _messages().CASES if case.name == name]
    return found


# macOS's lecture file (Apple's sudo-113 and sudo-114.100.11, files/sudo_lecture).
APPLE_LECTURE = (
    "",
    "WARNING: Improper use of the sudo command could lead to data loss",
    "or the deletion of important system files. Please double-check your",
    'typing when using sudo. Type "man sudo" for more information.',
    "",
    "To proceed, enter your password, or type Ctrl-C to abort.",
    "",
)


def _ignorable() -> frozenset[str]:
    return _messages().ignorable(APPLE_LECTURE)


def test_a_case_with_its_lines_is_judged_clean():
    messages = _messages()
    denied = _case("a command the drop-in denies, with a cmddenial_message")
    stderr = "\n".join((*APPLE_LECTURE, SAMPLES[messages.REFUSED_COMMAND], messages.CMDDENIAL, ""))
    assert messages.judge(denied, stderr, ignorable=_ignorable()) == []
    timed_out = _case("a password read that times out")
    stderr = "sudo: timed out reading password\nsudo: a password is required\n"
    assert messages.judge(timed_out, stderr, ignorable=_ignorable()) == []
    authfail = _case("a rewritten authfail_message")
    assert messages.judge(authfail, messages.AUTHFAIL_LINE + "\n", ignorable=_ignorable()) == []
    # sudo's own lecture, where no lecture file is set, and the lines sudo prints unchanged.
    plain = _case("no terminal, without -S")
    stderr = "\n".join(
        (*messages.BUILT_IN_LECTURE, "Sorry, try again.", SAMPLES[messages.NO_TERMINAL], "")
    )
    assert messages.judge(plain, stderr, ignorable=messages.ignorable(())) == []


@pytest.mark.parametrize(
    ("stderr", "found"),
    [
        ("", "Sorry, user %s is not allowed to execute '...' as %s on %s.\" on stderr"),
        ("Sorry, user x is not allowed to execute 'y' as z on h.\n", "drop-in's own line"),
        (
            "Sorry, user x is not allowed to execute 'y' as z on h.\n"
            "Voltry capture: the drop-in denies this command.\nsudo: something new\n",
            "starts with sudo: and matches no template",
        ),
        (
            "Sorry, user x is not allowed to execute 'y' as z on h.\n"
            "Voltry capture: the drop-in denies this command.\nsudo: a password is required\n",
            "of class AUTHENTICATION, which this case does not expect",
        ),
        (
            "Sorry, user x is not allowed to execute 'y' as z on h.\n"
            "Voltry capture: the drop-in denies this command.\nsomething new, no prefix\n",
            "matches no template and is not a line sudo prints unchanged, the lecture or the "
            "case's own",
        ),
    ],
    ids=["nothing", "no denial line", "a new sudo line", "another class", "a new plain line"],
)
def test_a_case_missing_its_lines_or_with_another_is_refused(stderr, found):
    problems = _messages().judge(
        _case("a command the drop-in denies, with a cmddenial_message"),
        stderr,
        ignorable=_ignorable(),
    )
    assert any(found in problem for problem in problems), problems


def test_a_line_of_another_lecture_is_no_line_to_ignore():
    # Only the image's own lecture, sudo's built-in one and the lines sudo prints unchanged
    # pass: any other unprefixed line is new, and new is what the capture exists to see.
    messages = _messages()
    plain = _case("no terminal, without -S")
    stderr = f"A lecture this image does not have\n{SAMPLES[messages.NO_TERMINAL]}\n"
    assert messages.judge(plain, stderr, ignorable=_ignorable()) != []
    assert (
        messages.judge(
            plain, stderr, ignorable=messages.ignorable(["A lecture this image does not have"])
        )
        == []
    )


def test_the_classifiers_class_must_be_the_cases():
    messages = _messages()
    case = _case("-n with no cached authorization")
    stderr = (
        "sudo: a password is required\nsudo: account validation failure, is your account locked?\n"
    )
    problems = messages.judge(case, stderr, ignorable=_ignorable())
    assert any("expected the classifier to give AUTHENTICATION" in problem for problem in problems)


STATE = "sudo: account validation failure, is your account locked?"


def test_an_account_state_case_is_judged_only_where_the_image_allowed_it():
    messages = _messages()
    locked = _case("a locked account, where the image allows it")
    assert not messages.reproduced(locked, "sudo: 1 incorrect password attempt\n", 1)
    assert messages.reproduced(locked, f"{STATE}\nsudo: a password is required\n", 1)
    assert messages.judge(locked, f"{STATE}\nsudo: a password is required\n", ignorable=()) == []


@pytest.mark.parametrize(
    "stderr",
    [f"{STATE}\n", f"sudo: a password is required\n{STATE}\n"],
    ids=["alone", "after the authentication line"],
)
def test_an_account_state_line_must_come_before_an_authentication_line(stderr):
    # The spec's bullet: "its account-state line followed by an authentication line".
    messages = _messages()
    for name in (
        "a locked account, where the image allows it",
        "an expired password, where the image allows it",
    ):
        problems = messages.judge(_case(name), stderr, ignorable=())
        assert any(
            "expected an authentication line after the account-state line" in p for p in problems
        )


LOCKED = "a locked account, where the image allows it"
EXPIRED = "an expired password, where the image allows it"


def test_the_first_account_state_line_is_the_one_an_authentication_line_must_follow():
    messages = _messages()
    later = "sudo: Password expired, contact your system administrator"
    stderr = f"{STATE}\nsudo: a password is required\n{later}\n"
    assert messages.judge(_case(LOCKED), stderr, ignorable=()) == []


def test_on_stock_macos_the_capture_says_why_no_account_state_line_can_print():
    # Change record 13: /etc/pam.d/sudo's account stack is pam_permit.so alone, so sudo's
    # account check always passes; a disabled account fails at the password, and a password
    # that must change is accepted. The capture says so, from the image's own file, and holds
    # what sudo did instead to that record where pwpolicy set the state.
    messages = _messages()
    for name in (LOCKED, EXPIRED):
        said = messages.not_reproduced(_case(name), STOCK, 0)
        assert "pam_permit.so alone" in said and "change record 13" in said
        assert "held to that record below" in said
        assert "recorded, not judged" not in said
        failed = messages.not_reproduced(_case(name), STOCK, 3)
        assert "pwpolicy could not set this account's state (exit 3)" in failed
        assert "held to that record" not in failed
    other = messages.not_reproduced(_case(LOCKED), ("pam_opendirectory.so", "pam_foo.so"), 0)
    assert other.endswith("checks accounts with pam_opendirectory.so, pam_foo.so")
    unread = messages.not_reproduced(_case(LOCKED), None, 0)
    assert unread.endswith("this image's /etc/pam.d/sudo could not be read")


@pytest.mark.parametrize(
    "modules",
    [("pam_permit.so", "pam_opendirectory.so"), ("pam_opendirectory.so", "pam_permit.so"), ()],
    ids=["pam_permit.so and another", "another first", "none"],
)
def test_only_the_exact_stock_stack_is_called_stock(modules):
    # A stack that holds pam_permit.so beside another module may check accounts, so record
    # 13 says nothing of it, and nothing is held to that record there.
    messages = _messages()
    said = messages.not_reproduced(_case(LOCKED), modules, 0)
    assert "pam_permit.so alone" not in said and "change record 13" not in said
    lines = messages.pinned_lines(set(), set(), version=NEWEST, account_modules=modules)
    assert not any("change record 13" in line for line in lines)
    assert messages.stock_check(_case(LOCKED), 0, "", account_modules=modules, state=0) is None


@pytest.mark.parametrize(
    ("name", "code", "stderr", "holds"),
    [
        (LOCKED, 1, "sudo: 1 incorrect password attempt\n", True),
        (LOCKED, 0, "", False),
        (LOCKED, 0, "sudo: 1 incorrect password attempt\n", False),
        (LOCKED, 1, "sudo: PAM account management error: x\n", False),
        (EXPIRED, 0, "", True),
        (EXPIRED, 1, "sudo: 1 incorrect password attempt\n", False),
    ],
    ids=[
        "disabled refused",
        "disabled accepted",
        "disabled exit 0 in the class",
        "disabled another class",
        "expired accepted",
        "expired refused",
    ],
)
def test_on_the_stock_stack_what_sudo_did_is_held_to_record_13(name, code, stderr, holds):
    # A disabled account fails at the password, as a wrong one does: sudo exits non-zero in
    # the authentication class. A password that must change is accepted: sudo exits 0.
    messages = _messages()
    check = messages.stock_check(_case(name), code, stderr, account_modules=STOCK, state=0)
    assert check is not None
    held, what, seen = check
    assert held is holds
    assert what.startswith(f"{name}: ") and "change record 13" in what
    assert seen == f"exit {code}, class {sudo_messages.classify(stderr).name}"
    # Nothing is held where pwpolicy could not set the state.
    assert messages.stock_check(_case(name), code, stderr, account_modules=STOCK, state=5) is None


def test_every_line_of_a_case_left_unjudged_is_one_template_or_one_to_ignore():
    messages = _messages()
    case = _case(EXPIRED)
    clean = "\n".join((*APPLE_LECTURE, "sudo: 1 incorrect password attempt", ""))
    assert messages.unjudged(case, clean, ignorable=_ignorable()) == []
    for stderr, found in (
        ("A line sudo never printed before\n", "matches no template and is not one to ignore"),
        ("sudo: PAM account management error: x\n", "matches no template and is not one to ignore"),
        (f"{TWICE[0]}\n", "matches more than one template"),
    ):
        problems = messages.unjudged(case, stderr, ignorable=_ignorable())
        assert any(found in problem for problem in problems), problems


def test_the_capture_reads_the_account_stack_from_the_pam_file():
    capture = _capture()
    apple = (
        "# sudo: auth account password session\n"
        "auth       include        sudo_local\n"
        "auth       sufficient     pam_smartcard.so\n"
        "auth       required       pam_opendirectory.so\n"
        "account    required       pam_permit.so\n"
        "password   required       pam_deny.so\n"
        "session    required       pam_permit.so\n"
    )
    assert capture.account_modules(apple) == STOCK
    changed = (
        apple + "account    required    pam_opendirectory.so  no_warn # a comment\n#account x y\n"
    )
    assert capture.account_modules(changed) == ("pam_permit.so", "pam_opendirectory.so")
    # An include names a file, not a module, and says so.
    included = apple + "account    include        sudo_local\n"
    assert capture.account_modules(included) == ("pam_permit.so", "include sudo_local")
    # A file that cannot be read is no stack at all.
    assert capture.pam_account_modules() is None  # the test's own folder has no such file
    capture.PAM_SUDO.write_text(apple, encoding="utf-8")
    assert capture.pam_account_modules() == STOCK


LOCKED_OUT = (
    "the right password once a failed attempt locked the account, where the image allows it"
)


def test_a_locked_out_owner_is_refused_as_an_authentication_failure():
    # Change record 13: macOS refuses the right password once the account is locked, as a
    # disabled account (a wrong password to sudo) or with a lock code of its own (sudo's
    # PAM authentication error, then a password is required). Either way the classifier's
    # class is authentication: administrator access was not granted.
    messages = _messages()
    case = _case(LOCKED_OUT)
    assert (case.account, case.stdin, case.primed, case.prefix) == (
        "vmcap_lockout",
        "password",
        True,
        "sudo: PAM authentication error: ",
    )
    assert "-S" in case.argv and not case.terminal
    for stderr in (
        "sudo: PAM authentication error: Unknown error -12345\nsudo: a password is required\n",
        "sudo: 1 incorrect password attempt\n",
    ):
        assert messages.reproduced(case, stderr, 1)
        assert messages.judge(case, stderr, ignorable=_ignorable()) == []
        assert messages.outcomes(stderr) == "AUTHENTICATION, so S2 denied and a payload auth_failed"
    # A PAM error alone would be sudo's fourth class, sudo reported an error: refused.
    assert messages.judge(case, "sudo: PAM authentication error: x\n", ignorable=()) != []
    assert messages.judge(case, "sudo: PAM account management error: x\n", ignorable=()) != []
    # sudo took the right password: why, from pwpolicy's own result.
    assert not messages.reproduced(case, "", 0)
    locked = messages.not_reproduced(case, STOCK, 0)
    assert "pwpolicy set the lockout policy" in locked and "did not lock the account" in locked
    unset = messages.not_reproduced(case, STOCK, 3)
    assert "pwpolicy could not set the lockout policy (exit 3)" in unset
    assert "did not lock the account" not in unset


def test_the_labels_carry_templates_and_lengths_never_a_line():
    messages = _messages()
    stderr = "Sorry, user secret-name is not allowed to execute 'x' as root on secret-host.\n"
    shown = messages.labels(stderr + "a line with secret-host\n")
    assert shown == [f"template {messages.REFUSED_COMMAND!r}", "another line of 23 characters"]
    assert "secret" not in str(shown)
    locked = messages.labels(
        "WARNING: Improper use of the sudo command could lead to data loss\n"
        "sudo: PAM authentication error: secret text\n",
        case=_case(LOCKED_OUT),
        ignorable=_ignorable(),
    )
    assert locked == [
        "a line of the lecture",
        "'sudo: PAM authentication error:' and 11 characters",
    ]


# --- the cases, clause by clause (Test strategy part 5, second bullet) --------------------

S = "/usr/bin/sudo"
PROMPTED = (S, "-p", "Your Mac password, for the two steps above: ")
FROM_STDIN = (S, "-S", "-p", "")
TRUE = ("--", "/usr/bin/true")
ID = ("--", "/usr/bin/id")


def _how(
    account: str,
    argv: tuple[str, ...],
    *,
    terminal: bool = False,
    stdin: str = "devnull",
    answers: tuple[str, ...] = (),
    ssh: bool = False,
    primed: bool = False,
) -> tuple[object, ...]:
    return (account, argv, terminal, stdin, answers, ssh, primed)


PASSWORD = ("password",)
# Each case's account, argv, terminal, what -S reads, what is typed, ssh and the failed
# attempt first, as the clause it serves needs them.
FIELDS = {
    "-n with no cached authorization": _how("vmcap_plain", (S, "-n", *TRUE)),
    "no terminal, without -S": _how("vmcap_plain", (*PROMPTED, *TRUE)),
    "no terminal, without -S, over ssh without -t": _how(
        "vmcap_plain", (*PROMPTED, *TRUE), ssh=True
    ),
    "end of input through -S": _how("vmcap_plain", (*FROM_STDIN, *TRUE), stdin="empty"),
    "a wrong password through -S": _how("vmcap_once", (*FROM_STDIN, *TRUE), stdin="wrong"),
    "three wrong passwords on a terminal": _how(
        "vmcap_thrice", (*PROMPTED, *TRUE), terminal=True, answers=("wrong",) * 3
    ),
    "a password read that times out": _how("vmcap_timeout", (*PROMPTED, *TRUE), terminal=True),
    "a command the drop-in denies": _how(
        "vmcap_plain", (*PROMPTED, *ID), terminal=True, answers=PASSWORD
    ),
    "a command the drop-in denies, with a cmddenial_message": _how(
        "vmcap_denial", (*PROMPTED, *ID), terminal=True, answers=PASSWORD
    ),
    "an account sudo does not list, running a command": _how(
        "vmcap_unlisted", (*PROMPTED, *TRUE), terminal=True, answers=PASSWORD
    ),
    "an account sudo does not list, asking sudo -v": _how(
        "vmcap_unlisted", (S, "-v", *PROMPTED[1:]), terminal=True, answers=PASSWORD
    ),
    "an account the drop-in lists for another host": _how(
        "vmcap_elsewhere", (*PROMPTED, *TRUE), terminal=True, answers=PASSWORD
    ),
    "a rewritten authfail_message": _how("vmcap_authfail", (*FROM_STDIN, *TRUE), stdin="wrong"),
    "a locked account, where the image allows it": _how(
        "vmcap_locked", (*FROM_STDIN, *TRUE), stdin="password"
    ),
    "an expired password, where the image allows it": _how(
        "vmcap_expired", (*FROM_STDIN, *TRUE), stdin="password"
    ),
    LOCKED_OUT: _how("vmcap_lockout", (*FROM_STDIN, *TRUE), stdin="password", primed=True),
}


AUTH, POLICY = Class.AUTHENTICATION, Class.POLICY_REFUSAL
REQUIRED = "sudo: a password is required"
ATTEMPTS = "sudo: %u incorrect password attempt"
NO_TERMINAL = (
    "sudo: a terminal is required to read the password; either use the -S option to read "
    "from standard input or configure an askpass helper"
)
NO_TERMINAL_SSH = (
    "sudo: a terminal is required to read the password; either use ssh's -t option or "
    "configure an askpass helper"
)
REFUSED_COMMAND = "Sorry, user %s is not allowed to execute '...' as %s on %s."
# What each case's stderr must hold: its class, the templates on it, and its own line. An
# account sudo does not list is refused as not in the sudoers file for a command, and as
# unable to run sudo for -v, since pseudo-commands never set FLAG_NO_USER (sudo 1.9.17p2's
# plugins/sudoers/lookup.c and logging.c).
EXPECTS = {
    "-n with no cached authorization": (AUTH, (REQUIRED,), None),
    "no terminal, without -S": (AUTH, (NO_TERMINAL,), None),
    "no terminal, without -S, over ssh without -t": (AUTH, (NO_TERMINAL_SSH,), None),
    "end of input through -S": (AUTH, ("sudo: no password was provided",), None),
    "a wrong password through -S": (AUTH, (ATTEMPTS,), None),
    "three wrong passwords on a terminal": (AUTH, (ATTEMPTS,), None),
    "a password read that times out": (AUTH, ("sudo: timed out reading password",), None),
    "a command the drop-in denies": (POLICY, (REFUSED_COMMAND,), None),
    "a command the drop-in denies, with a cmddenial_message": (
        POLICY,
        (REFUSED_COMMAND,),
        "Voltry capture: the drop-in denies this command.",
    ),
    "an account sudo does not list, running a command": (
        POLICY,
        ("%s is not in the sudoers file.",),
        None,
    ),
    "an account sudo does not list, asking sudo -v": (
        POLICY,
        ("Sorry, user %s may not run sudo on %s.",),
        None,
    ),
    "an account the drop-in lists for another host": (
        POLICY,
        ("%s is not allowed to run sudo on %s.",),
        None,
    ),
    "a rewritten authfail_message": (
        Class.OTHER_SUDO,
        (),
        "sudo: Voltry capture rewrote this message after 1 attempt",
    ),
    "a locked account, where the image allows it": (Class.ACCOUNT_STATE, (), None),
    "an expired password, where the image allows it": (Class.ACCOUNT_STATE, (), None),
    LOCKED_OUT: (AUTH, (), None),
}


def test_each_case_expects_what_its_clause_makes_sudo_print():
    cases = {case.name: (case.kind, tuple(case.expects), case.extra) for case in _messages().CASES}
    assert cases == EXPECTS


def test_each_case_runs_sudo_as_the_clause_it_serves_needs():
    cases = {
        case.name: (
            case.account,
            case.argv,
            case.terminal,
            case.stdin,
            case.answers,
            case.ssh,
            case.primed,
        )
        for case in _messages().CASES
    }
    assert cases == FIELDS


def test_only_the_ssh_case_looks_like_ssh_and_none_has_a_terminal_there():
    capture, messages = _capture(), _messages()
    for case in messages.CASES:
        env = capture.environment(case)
        assert "SSH_TTY" not in env
        if case.ssh:
            assert env == {**capture.ENV, "SSH_CONNECTION": "192.0.2.1 50000 192.0.2.2 22"}
        else:
            assert env == dict(capture.ENV)


# --- the capture's drop-ins, as text ------------------------------------------------------


def test_the_drop_ins_grant_nothing_without_a_password_and_mark_themselves():
    capture = _capture()
    texts = [capture.messages_drop_in(), capture.denial_drop_in(), capture.direct_drop_in("runner")]
    for text in texts:
        lines = text.rstrip("\n").split("\n")
        assert lines[0] == capture.MARK
        assert "NOPASSWD" not in text and "!authenticate" not in text
        assert all(line.startswith(("Defaults:", "vmcap_")) for line in lines[1:])
    rules = [line for line in texts[0].split("\n") if line.startswith("vmcap_")]
    # Each account the cases use has its rule but the one sudo must not list, and none can
    # run anything as root but true, except the administrator, who needs a password.
    named = {line.split()[0] for line in rules}
    cases = {case.account for case in _messages().CASES}
    assert named == (cases - {"vmcap_unlisted"}) | {capture.ADMIN}
    assert set(capture.ACCOUNTS) == cases | {capture.ADMIN}
    assert f"{capture.ADMIN} ALL = (ALL) PASSWD: ALL" in rules
    assert f"Defaults:{capture.ADMIN} timestamp_timeout=0" in texts[0]
    assert all(
        line.endswith("= (root) /usr/bin/true")
        for line in rules
        if not line.startswith(capture.ADMIN)
    )


def test_the_accounts_whose_state_a_case_tries_get_it_from_pwpolicy():
    capture = _capture()
    assert capture.STATES == (
        ("vmcap_locked", ("-disableuser",), "disabled"),
        ("vmcap_expired", ("-setpolicy", "newPasswordRequired=1"), "a password that must change"),
        (
            "vmcap_lockout",
            ("-setpolicy", "maxFailedLoginAttempts=1"),
            "locked after one failed attempt",
        ),
    )
    # One try each, so the failed attempt before the locked-out case is the one that locks.
    assert (
        "Defaults:vmcap_lockout timestamp_timeout=0, passwd_tries=1" in capture.messages_drop_in()
    )
    # What record 13 says stock macOS does instead, for each account whose state is set.
    stock = {case.account: case.stock for case in _messages().CASES if case.stock is not None}
    assert stock == {"vmcap_locked": "refused", "vmcap_expired": "accepted"}


def test_the_direct_drop_in_turns_off_exactly_what_makes_sudo_fork():
    # Decision 2: with use_pty, pam_session, pam_setcred and log_exit_status all off, and
    # no I/O log, log server or command timeout, sudo executes the command directly.
    capture = _capture()
    text = capture.direct_drop_in("runner")
    assert text == (
        f"{capture.MARK}\nDefaults:runner !use_pty, !pam_session, !pam_setcred, !log_exit_status\n"
    )


def test_the_drop_in_carries_the_cases_own_lines():
    capture, messages = _capture(), _messages()
    text = capture.messages_drop_in()
    assert capture.denial_drop_in() == (
        f'{capture.MARK}\nDefaults:vmcap_denial cmddenial_message="{messages.CMDDENIAL}"\n'
    )
    assert "cmddenial_message" not in text, "sudo before 1.9.16 would refuse the whole drop-in"
    assert f'authfail_message="{messages.AUTHFAIL}"' in text
    assert "passwd_timeout=0.05" in text  # three seconds, so the read times out at once
    assert all(
        '"' not in value and "\\" not in value for value in (messages.CMDDENIAL, messages.AUTHFAIL)
    )


# --- the capture's safety code, every tool faked -------------------------------------------


def test_no_test_here_can_start_a_real_tool():
    capture = _capture()
    with pytest.raises(AssertionError, match="a test reached a real command"):
        capture._run(["/usr/sbin/visudo", "-c"])


@pytest.mark.parametrize(
    "error",
    [
        subprocess.TimeoutExpired(["/usr/bin/dscl", ".", "-passwd", "/Users/x", "SECRET-PW"], 60),
        FileNotFoundError(2, "No such file or directory", "/usr/bin/dscl SECRET-PW"),
    ],
    ids=["a timeout", "a tool that cannot start"],
)
def test_a_tool_that_fails_is_named_alone_never_its_argv(monkeypatch, error):
    capture = _capture()

    def fails(*args: object, **kwargs: object) -> None:
        raise error

    tools = SimpleNamespace(
        run=fails,
        TimeoutExpired=subprocess.TimeoutExpired,
        DEVNULL=subprocess.DEVNULL,
        CompletedProcess=subprocess.CompletedProcess,
    )
    monkeypatch.setattr(capture, "subprocess", tools)
    with pytest.raises(capture.Failed) as failed:
        capture._run(["/usr/bin/dscl", ".", "-passwd", "/Users/x", "SECRET-PW"])
    said = f"{failed.value} {failed.value!r}"
    assert "SECRET-PW" not in said and "dscl" in said
    assert failed.value.__suppress_context__, "the original error, argv and all, is dropped"


def test_a_test_account_gets_its_password_on_dscls_standard_input_only(monkeypatch):
    capture = _capture()
    tools = _Tools()
    monkeypatch.setattr(capture, "_run", tools)
    account = capture._make("vmcap_plain", 7401)
    assert re.fullmatch(r"[0-9a-f]{32}", account.password), "no parser can take it for an option"
    assert all(account.password not in " ".join(argv) for argv, _ in tools.calls)
    given = [text for _, text in tools.calls if text is not None]
    assert given == [f"passwd /Users/vmcap_plain {account.password}\nquit\n"]
    session = [argv for argv, text in tools.calls if text is not None]
    assert session == [["/usr/bin/dscl", "-q", "."]]
    assert account.password not in repr(account)


def test_each_password_is_checked_on_dscls_standard_input_too(monkeypatch):
    capture = _capture()
    tools = _Tools()
    sessions: list[tuple[list[str], str]] = []
    made = {
        name: capture.Account(name, 7401 + index, 20, f"{index:032x}")
        for index, name in enumerate(capture.ACCOUNTS)
    }
    monkeypatch.setattr(capture, "_run", tools)
    monkeypatch.setattr(
        capture, "_dscl", lambda commands, what: sessions.append((list(commands), what))
    )
    monkeypatch.setattr(capture, "_make", lambda name, uid: made[name])
    monkeypatch.setattr(capture, "_free_uids", lambda count: [7401 + n for n in range(count)])
    monkeypatch.setattr(capture, "_looked_up", lambda account: account.uid)
    assert capture.make_accounts() == made
    assert [commands for commands, _ in sessions] == [
        [f"authonly {account.name} {account.password}"] for account in made.values()
    ]
    for argv, _ in tools.calls:
        assert not any(account.password in " ".join(argv) for account in made.values())
    assert [argv for argv, _ in tools.calls if argv[0] == capture.PWPOLICY] == []


def test_each_state_is_set_by_pwpolicy_on_its_own_account_and_its_result_kept(monkeypatch, capsys):
    capture = _capture()
    tools = _Tools(lambda argv: (7 if "-disableuser" in argv else 0, ""))
    monkeypatch.setattr(capture, "_run", tools)
    assert capture.set_states() == {"vmcap_locked": 7, "vmcap_expired": 0, "vmcap_lockout": 0}
    assert [argv for argv, _ in tools.calls] == [
        [capture.PWPOLICY, "-u", name, *options] for name, options, _ in capture.STATES
    ]
    printed = capsys.readouterr().out
    assert "vmcap_locked, disabled: no, pwpolicy exit 7" in printed
    assert "vmcap_expired, a password that must change: yes" in printed


@pytest.mark.parametrize(
    ("code", "printed", "passes"),
    [
        (0, "", True),
        (0, "\n  \n", True),
        (0, "DS Error: -14090 SECRET-PW\n", False),
        (1, "", False),
    ],
    ids=["silent", "blank lines", "an error printed", "a failing exit"],
)
def test_a_dscl_session_passes_only_silent_and_says_nothing_of_what_dscl_printed(
    monkeypatch, code, printed, passes
):
    capture = _capture()
    tools = _Tools(lambda argv: (code, printed))
    monkeypatch.setattr(capture, "_run", tools)
    if passes:
        capture._dscl(["authonly vmcap_plain SECRET-PW"], "a check")
    else:
        with pytest.raises(capture.Failed) as failed:
            capture._dscl(["authonly vmcap_plain SECRET-PW"], "a check")
        assert "SECRET-PW" not in str(failed.value) and "DS Error" not in str(failed.value)
    assert tools.calls == [(["/usr/bin/dscl", "-q", "."], "authonly vmcap_plain SECRET-PW\nquit\n")]


TEXT = "# voltry-mac capture (MAC 4.2): disposable, removed when the capture ends\nDefaults:x y\n"


def _visudo(staged: int, whole: int) -> _Tools:
    """visudo -c: ``staged`` for the staged file, ``whole`` for the whole policy."""
    return _Tools(lambda argv: (staged if "-f" in argv else whole, ""))


def test_a_drop_in_is_checked_then_installed_mode_0440_whatever_the_umask(monkeypatch):
    capture = _capture()
    tools = _visudo(0, 0)
    monkeypatch.setattr(capture, "_run", tools)
    old = os.umask(0o077)
    try:
        capture.install("zz-test", TEXT)
    finally:
        os.umask(old)
    final = capture.SUDOERS_D / "zz-test"
    assert final.read_text(encoding="utf-8") == TEXT
    assert stat.S_IMODE(final.lstat().st_mode) == 0o440
    assert sorted(path.name for path in capture.SUDOERS_D.iterdir()) == ["zz-test"]
    assert [argv for argv, _ in tools.calls] == [
        ["/usr/sbin/visudo", "-c", "-f", str(capture.SUDOERS_D / "zz-test.staged")],
        ["/usr/sbin/visudo", "-c"],
    ]


class _ShortWrites:
    """The os module as the capture sees it, but each write takes three bytes at most."""

    def __getattr__(self, name: str) -> object:
        return getattr(os, name)

    @staticmethod
    def write(descriptor: int, data: bytes) -> int:
        return os.write(descriptor, bytes(data[:3]))


def test_a_drop_in_is_written_whole_however_short_each_write(monkeypatch):
    capture = _capture()
    monkeypatch.setattr(capture, "_run", _visudo(0, 0))
    monkeypatch.setattr(capture, "os", _ShortWrites())
    capture.install("zz-test", TEXT)
    assert (capture.SUDOERS_D / "zz-test").read_text(encoding="utf-8") == TEXT


@pytest.mark.parametrize(
    ("staged", "whole"), [(1, 0), (0, 1)], ids=["the drop-in", "the whole policy"]
)
def test_a_drop_in_either_check_refuses_is_never_left(monkeypatch, staged, whole):
    capture = _capture()
    monkeypatch.setattr(capture, "_run", _visudo(staged, whole))
    with pytest.raises(capture.Failed, match="visudo -c refused"):
        capture.install("zz-test", TEXT)
    assert list(capture.SUDOERS_D.iterdir()) == []


def test_a_drop_in_is_never_staged_over_a_file_or_through_a_link(monkeypatch, tmp_path):
    capture = _capture()
    tools = _visudo(0, 0)
    monkeypatch.setattr(capture, "_run", tools)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.write_text("kept\n", encoding="utf-8")
    staged = capture.SUDOERS_D / "zz-test.staged"
    staged.symlink_to(elsewhere)
    with pytest.raises(FileExistsError):
        capture.install("zz-test", TEXT)
    assert elsewhere.read_text(encoding="utf-8") == "kept\n" and staged.is_symlink()
    assert tools.calls == [], "no check ran, and nothing was renamed into place"


def test_the_images_own_policy_is_checked_before_anything_is_added(monkeypatch):
    capture = _capture()
    monkeypatch.setattr(capture, "_run", _visudo(0, 1))
    with pytest.raises(capture.Failed, match="the image's own sudoers policy fails visudo -c"):
        capture.check_base_policy()
    monkeypatch.setattr(capture, "_run", _visudo(0, 0))
    capture.check_base_policy()
    # In the capture itself, before any account or drop-in is made.
    tree = ast.parse((LIVE / "capture.py").read_text(encoding="utf-8"))
    (body,) = [
        node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "capture"
    ]
    first: dict[str, int] = {}
    for node in ast.walk(body):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            first[node.func.id] = min(node.lineno, first.get(node.func.id, node.lineno))
    assert first["check_base_policy"] < first["make_accounts"] < first["install"]


def test_only_the_captures_drop_ins_are_removed(tmp_path):
    capture = _capture()
    folder = capture.SUDOERS_D
    (folder / "zz-voltry-mac-capture").write_text(
        capture.MARK + "\nDefaults:x y\n", encoding="utf-8"
    )
    (folder / "zz-voltry-mac-capture.staged").write_text("", encoding="utf-8")  # stopped at O_CREAT
    (folder / "zz-voltry-mac-denial.staged").write_text(capture.MARK[:20], encoding="utf-8")
    assert capture.remove_drop_in("zz-voltry-mac-capture") is True
    assert capture.remove_drop_in("zz-voltry-mac-denial") is True
    assert list(folder.iterdir()) == []
    # Anything else by those names is not the capture's, and stays.
    (folder / "zz-voltry-mac-capture").write_text("Defaults:x y\n", encoding="utf-8")
    (folder / "zz-voltry-mac-denial.staged").write_text("something else", encoding="utf-8")
    marked = tmp_path / "marked"
    marked.write_text(capture.MARK + "\n", encoding="utf-8")
    (folder / "zz-voltry-mac-runner-direct").symlink_to(marked)
    assert capture.remove_drop_in("zz-voltry-mac-capture") is False
    assert capture.remove_drop_in("zz-voltry-mac-denial") is False
    assert capture.remove_drop_in("zz-voltry-mac-runner-direct") is False
    assert sorted(path.name for path in folder.iterdir()) == [
        "zz-voltry-mac-capture",
        "zz-voltry-mac-denial.staged",
        "zz-voltry-mac-runner-direct",
    ]
    assert marked.exists()
    assert capture.remove_drop_in("zz-voltry-mac-admin-direct") is True  # nothing there


@pytest.mark.parametrize("held", ["", "# voltry-mac capture"], ids=["empty", "a partial mark"])
def test_an_empty_or_partial_drop_in_under_its_final_name_is_never_the_captures(held):
    # Only a staged copy can hold part of the mark: the capture renames a drop-in into place
    # whole, after visudo checked it, so a final name holding less is someone else's.
    capture = _capture()
    final = capture.SUDOERS_D / "zz-voltry-mac-capture"
    final.write_text(held, encoding="utf-8")
    assert capture.remove_drop_in("zz-voltry-mac-capture") is False
    assert final.read_text(encoding="utf-8") == held


@pytest.mark.parametrize(
    ("read", "removed", "deleted"),
    [
        ((56, ""), True, False),
        ((0, "RealName:\n Someone Else\n"), False, False),
        ((0, "RealName:\n Voltry capture test account\n"), True, True),
    ],
    ids=["no such account", "not the capture's", "the capture's"],
)
def test_only_the_captures_accounts_are_removed(monkeypatch, read, removed, deleted):
    capture = _capture()
    tools = _Tools(lambda argv: read if "-read" in argv else (0, ""))
    monkeypatch.setattr(capture, "_run", tools)
    assert capture.remove_account("vmcap_plain") is removed
    deletes = [argv for argv, _ in tools.calls if "-delete" in argv]
    assert deletes == ([["/usr/bin/dscl", ".", "-delete", "/Users/vmcap_plain"]] if deleted else [])


def test_the_cleanup_tries_every_item_whatever_happened_to_the_one_before(monkeypatch):
    capture = _capture()
    tried: list[str] = []

    def drop_in(name: str) -> bool:
        tried.append(name)
        if name == capture.DROP_INS[0]:
            raise capture.Failed("dscl did not finish within 60 s")
        return True

    def account(name: str) -> bool:
        tried.append(name)
        return True

    monkeypatch.setattr(capture, "remove_drop_in", drop_in)
    monkeypatch.setattr(capture, "remove_account", account)
    assert capture.cleanup() is False
    assert tried == [*capture.DROP_INS, *capture.ACCOUNTS]


@pytest.mark.parametrize(
    ("answer", "virtual"),
    [
        ((0, "1\n"), True),
        ((0, "0\n"), False),
        ((1, "1\n"), False),
        ((0, ""), False),
        ((0, "11\n"), False),
    ],
    ids=["one", "zero", "a failing read", "nothing", "eleven"],
)
def test_a_virtual_machine_is_kern_hv_vmm_present_1_and_nothing_else(monkeypatch, answer, virtual):
    capture = _capture()
    tools = _Tools(lambda argv: answer)
    monkeypatch.setattr(capture, "_run", tools)
    assert capture._virtual_machine() is virtual
    assert [argv for argv, _ in tools.calls] == [["/usr/sbin/sysctl", "-n", "kern.hv_vmm_present"]]


def test_a_virtual_machine_check_that_cannot_run_says_no(monkeypatch):
    capture = _capture()

    def fails(argv: list[str], **kwargs: object) -> None:
        raise capture.Failed("sysctl did not finish within 10 s")

    monkeypatch.setattr(capture, "_run", fails)
    assert capture._virtual_machine() is False


@pytest.mark.parametrize("raw", [None, "", "0", "-1", "abc", " 501"], ids=repr)
def test_the_capture_runs_only_through_sudo_from_an_account_that_is_not_root(monkeypatch, raw):
    capture = _capture()
    if raw is None:
        monkeypatch.delenv("SUDO_UID", raising=False)
    else:
        monkeypatch.setenv("SUDO_UID", raw)
    with pytest.raises(capture.Failed, match="runs through sudo from the runner user's account"):
        capture._invoker()


def test_the_invoking_account_must_have_a_name_a_drop_in_can_hold(monkeypatch):
    capture = _capture()
    monkeypatch.setenv("SUDO_UID", "501")
    entry = SimpleNamespace(pw_name="runner", pw_uid=501, pw_gid=20)
    monkeypatch.setattr(capture.pwd, "getpwuid", lambda uid: entry)
    assert capture._invoker() == capture.Account("runner", 501, 20)
    entry.pw_name = "run ner"
    with pytest.raises(capture.Failed, match="cannot stand in a drop-in"):
        capture._invoker()


def test_the_worst_case_counts_every_drive_to_its_deadline_and_its_drain():
    # Each sudo run and each probe is one drive: it may run to its deadline and then keep its
    # pipes open DRAIN_S more. The cases make one drive each, the locked-out case two.
    capture, messages = _capture(), _messages()
    drives = [capture.CASE_S] * (len(messages.CASES) + 1)
    drives += [capture.DIRECT_S, capture.SLOW_S, capture.SLOW_S, capture.BROKER_S, capture.BROKER_S]
    worst = sum(drives) + len(drives) * capture.DRAIN_S
    assert worst == capture.WORST_S


# --- what a failed check prints (m7) --------------------------------------------------------


def test_a_failed_check_prints_what_was_seen_beside_it(capsys):
    capture = _capture()
    checks = capture.Checks()
    checks.that(True, "a check that holds", "not printed")
    checks.that(False, "a check that fails", ["eperm", "terminated"])
    checks.that(False, "a check with nothing seen")
    assert capsys.readouterr().out == (
        "  ok    a check that holds\n"
        "  FAIL  a check that fails\n"
        "        seen: ['eperm', 'terminated']\n"
        "  FAIL  a check with nothing seen\n"
    )
    assert checks.failed == ["a check that fails", "a check with nothing seen"]


# --- step 4, direct execution: what the probe sent back ----------------------------------


def _run_summary(**changes: object) -> dict:
    summary = {
        "command": "S4n",
        "ending": "parsed",
        "cleanup": "verified",
        "identified": True,
        "identified_at_0": True,
        "descendants": 0,
        "armed": [],
        "subtree": [[0, 0, "powermetrics"]],
        "early": [],
    }
    return {**summary, **changes}


def _failing(checks: list) -> list[str]:
    return [check.what for check in checks if not check.holds]


def test_direct_execution_holds_on_a_payload_identified_at_level_0():
    capture = _capture()
    s3n = [_run_summary(identified=False, identified_at_0=False), _run_summary()]
    assert _failing(capture.direct_checks({"S3n": s3n, "S4n": _run_summary()})) == []


def test_direct_execution_says_when_no_listing_saw_the_count():
    capture = _capture()
    s3n = [_run_summary(identified=False, identified_at_0=False)] * 3
    checks = capture.direct_checks({"S3n": s3n, "S4n": _run_summary()})
    (failed,) = [check for check in checks if not check.holds]
    assert failed.what == "S3n: the tracker identified sqlite3 at level 0"
    assert failed.seen == "no listing saw it in 3 runs"


def test_direct_execution_fails_on_a_process_below_level_0():
    capture = _capture()
    checks = capture.direct_checks(
        {"S3n": [_run_summary()], "S4n": _run_summary(descendants=1, identified_at_0=False)}
    )
    assert _failing(checks) == [
        "S4n: no process below level 0: sudo executed the payload directly",
        "S4n: the tracker identified powermetrics at level 0",
    ]


# --- step 5, the slow prompt (M2, M1) -----------------------------------------------------

PROMPTS = [1.0, 12.0]
ANSWERS = [11.0, 22.0]  # each answered 10 s after its prompt


def _slow(*, s3: dict | None = None, s4: dict | None = None) -> dict:
    """What the slow probe sends back: by default the count unseen after its answer, as a
    200 ms listing almost always leaves it, and the power sample identified after its."""
    return {
        "S3": {**_run_summary(identified=False, identified_at_0=False, subtree=[]), **(s3 or {})},
        "S4": {
            **_run_summary(armed=[[22.4, "launch"], [22.6, "runtime"]]),
            **(s4 or {}),
        },
    }


def _slow_failing(found: dict, *, version: tuple = NEWEST, monitor: bool = False) -> list[str]:
    return _failing(
        _capture().slow_checks(found, PROMPTS, ANSWERS, version=version, monitor=monitor)
    )


def test_the_slow_prompt_asserts_nothing_a_200_ms_listing_cannot_see_of_the_count():
    # S3's sqlite3 lives for milliseconds: nothing of it seen after the answer is no failure,
    # directly or through sudo's defaults.
    assert _slow_failing(_slow()) == []
    monitor = {"subtree": [[0, 0, "sudo"], [1, 0, "sudo"], [2, 0, "powermetrics"]]}
    assert _slow_failing(_slow(s4=monitor), monitor=True) == []


def test_a_clock_armed_during_the_wait_fails_for_either_payload():
    found = _slow(
        s3={"armed": [[5.0, "launch"]]}, s4={"armed": [[15.0, "launch"], [22.6, "runtime"]]}
    )
    assert _slow_failing(found) == [
        "executed directly, S3: no launch clock started during the wait",
        "executed directly, S4: no launch clock started during the wait",
    ]


def test_a_tracker_that_arms_no_clock_cannot_pass_for_the_power_sample():
    # S4 runs for seconds, so a runtime clock armed after its answer is certain: without
    # one, the check that no clock started during the wait would hold vacuously.
    assert _slow_failing(_slow(s4={"armed": []})) == [
        "executed directly, S4: a runtime clock started after the answer, so the check above "
        "could see a clock start"
    ]


def test_executed_directly_the_power_sample_is_identified_at_level_0():
    found = _slow(
        s4={"identified_at_0": False, "subtree": [[0, 0, "sudo"], [1, 0, "powermetrics"]]}
    )
    assert _slow_failing(found) == [
        "executed directly, S4: the tracker identified powermetrics at level 0"
    ]


def test_the_monitor_is_roots_own_sudo():
    subtree = [[0, 0, "sudo"], [1, 501, "sudo"], [2, 0, "powermetrics"]]
    failing = _slow_failing(_slow(s4={"subtree": subtree}), version=NEWEST, monitor=True)
    assert failing == [
        "through sudo's defaults, S4: sudo's monitor at level 1, and powermetrics below it at "
        "level 2"
    ]


@pytest.mark.parametrize(
    ("version", "subtree", "holds"),
    [
        (
            NEWEST,
            [
                [0, 0, "sudo"],
                [1, 0, "sudo"],
                [2, 0, "/usr/bin/sandbox-exec"],
                [2, 0, "powermetrics"],
            ],
            True,
        ),
        (NEWEST, [[0, 0, "sudo"], [1, 0, "powermetrics"]], False),
        (NEWEST, [[0, 0, "sudo"], [1, 0, "sudo"]], False),
        (OLDEST, [[0, 0, "sudo"], [1, 0, "sandbox-exec"], [1, 0, "/usr/bin/powermetrics"]], True),
        (OLDEST, [[0, 0, "sudo"], [1, 0, "sudo"], [2, 0, "powermetrics"]], False),
        ((1, 9, 14, 0), [[0, 0, "sudo"], [1, 0, "sudo"], [2, 0, "powermetrics"]], True),
    ],
    ids=[
        "1.9.17p2 behind the monitor",
        "1.9.17p2 without one",
        "1.9.17p2 no payload",
        "1.9.13p2 own child",
        "1.9.13p2 with a monitor",
        "1.9.14 behind the monitor",
    ],
)
def test_with_sudos_defaults_the_power_sample_sits_where_that_sudo_puts_it(version, subtree, holds):
    # Change record 12: sudo 1.9.14 and later run it behind the monitor on a terminal, and
    # 1.9.13p2 as its own child. The count is never asserted here.
    failing = _slow_failing(_slow(s4={"subtree": subtree}), version=version, monitor=True)
    assert (failing == []) is holds, failing


# --- step 6, the broker's stop that meets EPERM (m5, m6) -------------------------------------

STARTED = "Mon Sep 28 12:00:00 2026"


def _note(pid: int, uid: int, name: str) -> str:
    return tracking.survivor_note(tracking.Survivor(pid, uid, STARTED, name))


def _broker_found(**changes: object) -> dict:
    """What the probe sends back for the real S4n alone, as Decision 2's tables make it."""
    capture = _capture()
    found = {
        "record": capture.POWER_ALONE_RECORD,
        "ledger": ["unsupported", "service_account_missing"],
        "power": ["timeout", "runtime_deadline"],
        "survivors": [[4321, 0, STARTED, "powermetrics"]],
        "notes": [_note(4321, 0, "powermetrics")],
        "stops": ["eperm"],
        "payloads": [
            {
                "spawned": 4321,
                "identity": [0, "powermetrics"],
                "identified_at_0": True,
                "subtree": [[0, 0, "powermetrics"]],
                "final": "alive",
            }
        ],
        "commands": ["P1", "S1", "S2n", "S4n", "S5"],
        "held": 1,
        "left": 0,
        "gone": True,
    }
    return {**found, **changes}


def _power_alone(found: dict) -> tuple[list, list[str]]:
    capture = _capture()
    return capture.broker_checks(
        "The real S4n alone", found, identity=[0, "powermetrics"], **capture.POWER_ALONE_EXPECTED
    )


def test_each_broker_run_expects_what_decision_2_gives_it():
    # Decision 2's tables: the stand-in, stopped by its 1 s runtime clock, is a survivor, so
    # the power sample is skipped after the unsafe stop; the real S4n alone, the count
    # skipped for want of the service account, is the survivor itself.
    capture = _capture()
    # The records, from the package's own record of a granted run by the flag, -n forms.
    flag = {"consent": "flag", "mode": "noninteractive"}
    stand_in = reports.record(**flag, count=("runtime_deadline", "survivor"), power=reports.NOT_RUN)
    power_alone = reports.record(
        **flag,
        service_account="missing",
        count=reports.NOT_RUN,
        power=("runtime_deadline", "survivor"),
    )
    assert (stand_in, power_alone) == (capture.STAND_IN_RECORD, capture.POWER_ALONE_RECORD)
    # Change record 23: the power sample alone may have ended right after EPERM; the
    # record is then the same with the cleanup verified. The stand-in never may.
    ended = reports.record(
        **flag,
        service_account="missing",
        count=reports.NOT_RUN,
        power=("runtime_deadline", "verified"),
    )
    assert ended == capture.POWER_ALONE_ENDED_RECORD
    assert capture.STAND_IN_EXPECTED["ended"] is None
    assert capture.POWER_ALONE_EXPECTED["ended"] == capture.POWER_ALONE_ENDED_RECORD
    assert dict(capture.STAND_IN_EXPECTED) == {
        "ended": None,
        "record": capture.STAND_IN_RECORD,
        "outcomes": (["timeout", "runtime_deadline"], ["tool_error", "skipped_after_unsafe_stop"]),
        "shown_as": "an unexpected process",
        "not_run": "S4n",
    }
    assert dict(capture.POWER_ALONE_EXPECTED) == {
        "ended": capture.POWER_ALONE_ENDED_RECORD,
        "record": capture.POWER_ALONE_RECORD,
        "outcomes": (["unsupported", "service_account_missing"], ["timeout", "runtime_deadline"]),
        "shown_as": "powermetrics",
        "not_run": "S3n",
    }
    # The note the tool renders for each survivor names it as each run expects.
    for expected, uid, name in (
        (capture.STAND_IN_EXPECTED, 283, "sleep"),
        (capture.POWER_ALONE_EXPECTED, 0, "powermetrics"),
    ):
        assert capture.note_problems(_note(4321, uid, name), 4321, expected["shown_as"]) == []


def test_the_real_power_sample_alone_survives_as_the_spec_says():
    checks, explained = _power_alone(_broker_found())
    assert _failing(checks) == [] and explained == []


def test_the_stand_in_survives_as_the_spec_says():
    capture = _capture()
    found = _broker_found(
        record=capture.STAND_IN_RECORD,
        ledger=["timeout", "runtime_deadline"],
        power=["tool_error", "skipped_after_unsafe_stop"],
        survivors=[[4321, 283, STARTED, "sleep"]],
        notes=[_note(4321, 283, "sleep")],
        payloads=[{**_broker_found()["payloads"][0], "identity": [283, "sleep"]}],
        commands=["P1", "S1", "S2n", "S3n", "S5"],
    )
    checks, explained = capture.broker_checks(
        "The count's stand-in", found, identity=[283, "sleep"], **capture.STAND_IN_EXPECTED
    )
    assert _failing(checks) == [] and explained == []


def test_the_stand_in_is_named_an_unexpected_process_never_sleep():
    capture = _capture()
    note = _note(4321, 283, "sleep")
    assert capture.note_problems(note, 4321, "an unexpected process") == []
    assert "sleep" not in note
    assert capture.note_problems(note, 4321, "sleep") != []


@pytest.mark.parametrize(
    ("note", "problem"),
    [
        (
            "process 4321, powermetrics, user ID 0, started x. Stop it with\n"
            "  sudo /bin/kill -TERM 4321",
            "it has no ps -p line to check the four fields",
        ),
        (
            "process 4321, powermetrics, user ID 0, started x.\n  sudo /bin/kill -TERM 4321\n"
            "then check it with\n  ps -p 4321 -o pid,uid,lstart,comm\n"
            "and only if all four still match",
            "its stop does not come after 'only if all four still match'",
        ),
        (
            "process 4321, powermetrics, user ID 0, started x. Check it first with\n"
            "  ps -p 4321 -o pid,uid,lstart,comm\nand only if all four still match, kill 4321",
            "it has no stop line, or a kill command besides it",
        ),
        (
            "process 4321, powermetrics, user ID 0, started x. Or just kill 4321. Check it first "
            "with\n  ps -p 4321 -o pid,uid,lstart,comm\nand only if all four still match, stop "
            "it with\n  sudo /bin/kill -TERM 4321",
            "it has no stop line, or a kill command besides it",
        ),
        (
            _note(4321, 0, "powermetrics").replace(", powermetrics,", ", an unexpected process,"),
            "it does not name the process as 'powermetrics'",
        ),
    ],
    ids=[
        "no check",
        "a stop before the check",
        "a bare kill",
        "a kill beside the stop",
        "another name",
    ],
)
def test_a_note_that_is_not_verification_first_fails(note, problem):
    assert problem in _capture().note_problems(note, 4321, "powermetrics")


@pytest.mark.parametrize(
    "notes",
    [[], [_note(4321, 0, "sleep")], [_note(4321, 0, "powermetrics").replace("only if", "if")]],
    ids=["no note", "another name", "no check before the stop"],
)
def test_a_missing_or_wrong_note_fails_the_run(notes):
    checks, _ = _power_alone(_broker_found(notes=notes))
    assert _failing(checks) == [
        "The real S4n alone: the owner's note names it as 'powermetrics', gives ps -p to check "
        "the four fields, and the stop only after 'only if all four still match'"
    ]


def _final(state: str) -> str:
    """What a made-up final listing shows of the payload, process 4321, through the probe's
    own reading: still running, ended and not collected, or not listed at all."""
    rows = {
        "alive": [(4321, 40, 0, "powermetrics")],
        "<defunct>": [(4321, 40, 0, "<defunct>")],
        "gone": [],
    }[state]
    return _topology().final_state(_listing(*rows), 4321)


def _ended(state: str, **changes: object) -> dict:
    """The real S4n alone as the tool leaves it when powermetrics ended before the final
    listing: the cleanup verified, so no survivor and no note."""
    payload = {**_broker_found()["payloads"][0], "final": _final(state)}
    found = _broker_found(
        record=_capture().POWER_ALONE_ENDED_RECORD, survivors=[], notes=[], payloads=[payload]
    )
    return {**found, **changes}


@pytest.mark.parametrize("state", ["<defunct>", "gone"])
def test_a_power_sample_ended_right_after_eperm_passes_and_says_why(state):
    # Change record 23: after EPERM the tool closes its pipes, and powermetrics' next write
    # ends it on SIGPIPE, often before the final listing, which then shows it ended. The
    # tool's cleanup is verified, which is true of that run: a pass, and the log says why.
    checks, explained = _power_alone(_ended(state))
    assert _failing(checks) == []
    (line,) = explained
    assert f"already ended ({state}) right after EPERM" in line
    assert "SIGPIPE" in line and "change record 23" in line


def test_a_power_sample_still_running_passes_as_the_survivor_with_its_note():
    payload = {**_broker_found()["payloads"][0], "final": _final("alive")}
    checks, explained = _power_alone(_broker_found(payloads=[payload]))
    assert _failing(checks) == [] and explained == []
    # Still running, it is the survivor: the record that says verified is not its.
    ended = _broker_found(record=_capture().POWER_ALONE_ENDED_RECORD, payloads=[payload])
    assert _failing(_power_alone(ended)[0]) == ["The real S4n alone: the elevation record"]


@pytest.mark.parametrize(
    ("changes", "failed"),
    [
        (
            {"power": ["tool_error", "payload_failed"]},
            "The real S4n alone: the count ['unsupported', 'service_account_missing'] and the "
            "power sample ['timeout', 'runtime_deadline']",
        ),
        (
            {"survivors": [[4321, 0, STARTED, "powermetrics"]]},
            "The real S4n alone: it had ended when the tool looked, so no survivor and no note",
        ),
        (
            {"notes": [_note(4321, 0, "powermetrics")]},
            "The real S4n alone: it had ended when the tool looked, so no survivor and no note",
        ),
        (
            {"commands": ["P1", "S1", "S2n", "S3n", "S4n", "S5"]},
            "The real S4n alone: S3n never started",
        ),
        (
            {"left": 1},
            "The real S4n alone: the nonblocking wait collected it once it ended on its own",
        ),
        ({"record": _capture().POWER_ALONE_RECORD}, "The real S4n alone: the elevation record"),
    ],
    ids=[
        "another outcome",
        "a survivor",
        "a note",
        "the count started",
        "not collected",
        "the survivor's record",
    ],
)
def test_every_other_check_of_the_ended_power_sample_stays(changes, failed):
    checks, _ = _power_alone(_ended("<defunct>", **changes))
    assert _failing(checks) == [failed]


def test_an_ended_payload_without_eperm_or_for_the_stand_in_still_fails():
    capture = _capture()
    # Without EPERM the tool signalled it, so a payload ended by the stop is no race to take.
    checks, explained = _power_alone(_ended("<defunct>", stops=["terminated"]))
    assert "The real S4n alone: the one stop met EPERM" in _failing(checks)
    assert "The real S4n alone: the final listing still showed that payload running" in (
        _failing(checks)
    )
    assert explained == []
    # The stand-in, a sleep, writes nothing, so SIGPIPE cannot end it: it must survive.
    sleep = {**_ended("<defunct>")["payloads"][0], "identity": [283, "sleep"]}
    verified = {"ending": "runtime_deadline", "cleanup": "verified"}
    stand_in = _stand_in_found(
        record={**capture.STAND_IN_RECORD, "count": verified},
        survivors=[],
        notes=[],
        payloads=[sleep],
    )
    checks, explained = capture.broker_checks(
        "The count's stand-in", stand_in, identity=[283, "sleep"], **capture.STAND_IN_EXPECTED
    )
    failing = _failing(checks)
    assert "The count's stand-in: the elevation record" in failing
    assert "The count's stand-in: the final listing still showed that payload running" in failing
    assert explained == []


def test_each_broker_check_says_what_it_saw():
    checks, _ = _power_alone(_broker_found(stops=["terminated"], left=1, gone=False))
    seen = {check.what: check.seen for check in checks if not check.holds}
    assert seen == {
        "The real S4n alone: the one stop met EPERM": ["terminated"],
        "The real S4n alone: the nonblocking wait collected it once it ended on its own": (
            "1 left, gone False"
        ),
    }


# --- the probes' watching, on made-up listings (nothing is started) ------------------------

HEADER = "  PID  PPID   UID STARTED                      COMM"
AT = "Mon Sep 28 12:00:00 2026"


def _listing(*rows: tuple[int, int, int, str]) -> str:
    lines = [f"{pid:5d} {ppid:5d} {uid:5d} {AT} {comm}" for pid, ppid, uid, comm in rows]
    return "\n".join([HEADER, "    1     0     0 " + AT + " /sbin/launchd", *lines]) + "\n"


def test_the_stand_in_is_the_counts_own_shape_around_a_sandboxed_sleep():
    topology = _topology()
    s3n = allowlist.BY_ID["S3n"].template
    assert topology.STAND_IN[:9] == s3n[:9]  # sudo -u _mmaintenanced -H -n -- sandbox-exec -p
    assert topology.STAND_IN[9:] == ("/bin/sleep", "8")
    assert topology.RUNTIME_S == 1.0


def test_the_stand_in_goes_through_the_chokepoints_own_checks(monkeypatch):
    topology = _topology()
    for name in ("COMMANDS", "BY_ID", "forbidden_shape"):
        monkeypatch.setattr(allowlist, name, getattr(allowlist, name))
    monkeypatch.setattr(topology.tracking, "PAYLOAD_NAMES", topology.tracking.PAYLOAD_NAMES)
    runner = topology.spawn.Runner()
    assert allowlist.match(topology.STAND_IN) is None, "off the list until the patch"
    assert allowlist.forbidden_shape(topology.STAND_IN) is not None
    topology._stand_in()
    assert allowlist.match(topology.STAND_IN).id == "S3n"
    assert runner._checked_argv("S3n", broker=True) == list(topology.STAND_IN)
    assert topology.tracking.PAYLOAD_NAMES["S3n"] == "sleep"
    assert runner._checked_argv("S4n", broker=True) == list(allowlist.BY_ID["S4n"].template)
    # Nothing else becomes runnable: the same sleep as root, or without the sandbox.
    for argv in (
        ("/usr/bin/sudo", "-H", "-n", "--", *topology.STAND_IN[6:]),
        ("/usr/bin/sudo", "-u", "_mmaintenanced", "-H", "-n", "--", "/bin/sleep", "8"),
    ):
        assert allowlist.forbidden_shape(argv) is not None


def test_the_subtree_keeps_what_ps_printed_for_comm():
    listing = _listing(
        (40, 1, 501, "/usr/local/bin/python3"),
        (100, 40, 0, "sudo"),
        (101, 100, 0, "/usr/bin/sudo"),
        (102, 101, 283, "sandbox-exec"),
        (103, 102, 283, "sqlite3"),
        (104, 103, 283, "deeper still"),
    )
    assert _topology()._subtree(listing, 100) == {
        (0, 0, "sudo"),
        (1, 0, "/usr/bin/sudo"),
        (2, 283, "sandbox-exec"),
        (3, 283, "sqlite3"),
    }
    assert _topology()._subtree(listing, 999) == set()


def test_the_final_listing_shows_a_payload_alive_ended_or_gone():
    topology = _topology()
    listing = _listing((100, 40, 0, "powermetrics"), (200, 40, 283, "<defunct>"))
    assert topology.final_state(listing, 100) == "alive"
    assert topology.final_state(listing, 200) == "<defunct>"
    assert topology.final_state(listing, 300) == "gone"


def test_a_broker_run_sends_back_the_owners_note_and_what_the_final_listing_showed(monkeypatch):
    topology = _topology()
    payload = topology.tracking.Payload(uid=0, name="powermetrics")
    watched = topology.Watched.__new__(topology.Watched)
    watched.spawned, watched.payload, watched.subtree = 4321, payload, {(0, 0, "powermetrics")}
    watched._seen = {}
    monkeypatch.setattr(topology, "_TRACKERS", [watched])
    monkeypatch.setattr(topology, "_STOPS", ["eperm"])
    monkeypatch.setattr(topology._Tap, "text", _listing((4321, 40, 0, "<defunct>")))
    monkeypatch.setattr(topology.spawn, "collect_abandoned", lambda: 0)

    class Runner:
        def run(self, command_id: str) -> SimpleNamespace:
            assert command_id == "P1"
            return SimpleNamespace(stdout=_listing())

    monkeypatch.setattr(topology.spawn, "Runner", Runner)
    survivor = tracking.Survivor(4321, 0, AT, "powermetrics")
    outcome = SimpleNamespace(reason="timeout", detail="runtime_deadline")
    found = SimpleNamespace(record={}, ledger=outcome, power=outcome, survivors=(survivor,))
    sent = topology._broker(found, SimpleNamespace(records=lambda: []))
    assert sent["notes"] == [tracking.survivor_note(survivor)]
    assert [one["final"] for one in sent["payloads"]] == ["<defunct>"]


def test_the_watched_tracker_notes_its_clocks_and_what_came_before_any_sign(monkeypatch):
    topology = _topology()
    monkeypatch.setattr(topology, "_TRACKERS", [])
    payload = topology.tracking.Payload(uid=283, name="sqlite3")
    watched = topology.Watched(spawned=100, payload=payload, runtime_s=10.0, now=0.0)

    def apply(at: float, *rows: tuple[int, int, int, str]) -> None:
        text = _listing(*rows)
        monkeypatch.setattr(topology._Tap, "text", text)
        watched.apply(topology.listing.processes(text), at)

    apply(1.0, (100, 40, 0, "sudo"))
    apply(2.0, (100, 40, 0, "sudo"), (150, 100, 0, "authhelper"))  # before any sign
    apply(12.0, (100, 40, 283, "/usr/bin/sandbox-exec"))  # sudo executed it directly
    apply(12.2, (100, 40, 283, "sqlite3"))
    assert watched.armed == [(12.0, "launch"), (12.2, "runtime")]
    assert watched.early == {(1, 0, "authhelper")}
    assert watched.identified_at_0
    (registered,) = topology._TRACKERS
    assert registered is watched, "each tracker registers itself for its probe to read"


def test_a_payload_identified_below_level_0_is_not_identified_at_it(monkeypatch):
    topology = _topology()
    monkeypatch.setattr(topology, "_TRACKERS", [])
    payload = topology.tracking.Payload(uid=0, name="powermetrics")
    watched = topology.Watched(spawned=100, payload=payload, runtime_s=20.0, now=0.0)
    text = _listing((100, 40, 0, "sudo"), (101, 100, 0, "sudo"), (102, 101, 0, "powermetrics"))
    monkeypatch.setattr(topology._Tap, "text", text)
    watched.apply(topology.listing.processes(text), 1.0)
    assert watched.armed == [(1.0, "runtime")]
    assert not watched.identified_at_0
    assert (1, 0, "sudo") in watched.subtree
    assert watched.early == set(), "the monitor is the sign itself, not a process before it"


# --- the sandbox job's profile, as text ---------------------------------------------------

FOLDER = "/private/var/folders/xy/abc/T/voltry-mac-sandbox-1/report"
INTERPRETERS = ("/runner/temp/venv/bin/python", "/runner/python/cpython-3.14/bin/python3.14")


def _forms(text: str) -> list[list[object]]:
    """A profile's top-level forms, each a nested list of words and quoted strings."""
    stack: list[list[object]] = [[]]
    for token in re.findall(r'\(|\)|"[^"]*"|[^\s()"]+', text):
        if token == "(":
            stack.append([])
        elif token == ")":
            done = stack.pop()
            stack[-1].append(done)
        else:
            stack[-1].append(token)
    assert len(stack) == 1, "the profile's parentheses do not balance"
    return stack[0]  # type: ignore[return-value]


def _profile() -> list[list[object]]:
    return _forms(_sandbox().profile(FOLDER, INTERPRETERS))


def _rules(forms: list[list[object]], action: str, prefix: str) -> list[tuple[int, list[object]]]:
    return [
        (index, form)
        for index, form in enumerate(forms)
        if form[0] == action and str(form[1]).startswith(prefix)
    ]


def test_the_profile_is_version_1_and_allows_by_default_before_anything_else():
    forms = _profile()
    assert forms[:2] == [["version", "1"], ["allow", "default"]]
    assert all(form[0] in ("allow", "deny") for form in forms[1:])


def test_the_profile_denies_the_network_and_allows_none_of_it():
    forms = _profile()
    assert [form for _, form in _rules(forms, "deny", "network")] == [["deny", "network*"]]
    assert _rules(forms, "allow", "network") == []


def test_the_profile_denies_file_writes_outside_its_folder():
    forms = _profile()
    ((denied, _),) = [
        (index, form) for index, form in enumerate(forms) if form == ["deny", "file-write*"]
    ]
    allowed = _rules(forms, "allow", "file")
    # The later rule wins, so each allowance follows the denial. The one outside the folder
    # is data written to /dev/null, which stores nothing and which subprocess opens
    # read-write for every child's standard input.
    assert [form for _, form in allowed] == [
        ["allow", "file-write*", ["subpath", f'"{FOLDER}"']],
        ["allow", "file-write-data", ["literal", '"/dev/null"']],
    ]
    assert all(index > denied for index, _ in allowed)
    assert [form for _, form in _rules(forms, "deny", "file")] == [["deny", "file-write*"]]


def test_the_profile_runs_only_the_user_commands_programs_and_the_interpreter():
    forms = _profile()
    ((denied, _),) = [
        (index, form) for index, form in enumerate(forms) if form == ["deny", "process-exec*"]
    ]
    ((index, allowed),) = _rules(forms, "allow", "process")
    assert index > denied and allowed[:2] == ["allow", "process-exec*"]
    assert all(isinstance(item, list) and item[0] == "literal" for item in allowed[2:])
    programs = {str(item[1]).strip('"') for item in allowed[2:] if isinstance(item, list)}
    # The allow-list's user commands (C1 to C28) start these, C28 the interpreter itself;
    # nothing a --no-root run never starts, sudo above all.
    user = {
        command.template[0]
        for command in allowlist.COMMANDS
        if command.id.startswith("C") and command.template[0] != allowlist.INTERPRETER
    }
    assert programs == user | set(INTERPRETERS)
    assert set(_sandbox().PROGRAMS) == user
    assert not programs & {"/usr/bin/sudo", "/usr/bin/sandbox-exec", "/bin/ps", "/usr/bin/open"}


@pytest.mark.parametrize(
    "folder",
    ["relative/report", '/folder/a"b', "/folder/a\\b", "/folder/a\nb", "/folder/a\x7fb"],
    ids=["relative", "quote", "backslash", "newline", "delete"],
)
def test_the_profile_refuses_a_path_it_cannot_quote(folder):
    with pytest.raises(ValueError):
        _sandbox().profile(folder, INTERPRETERS)


def test_the_probe_is_a_program_and_the_job_expects_each_of_its_attempts():
    # Compiled here, never run: under the profile it is the job's check that the image
    # enforces the profile at all.
    sandbox = _sandbox()
    compile(sandbox.PROBE, "probe", "exec")
    attempts = re.findall(r'^attempt\("([^"]+)"', sandbox.PROBE, re.MULTILINE)
    assert attempts == list(sandbox.ENFORCED)
    assert sorted(set(sandbox.ENFORCED.values())) == ["done", "refused"]


def test_the_job_runs_the_cli_with_no_root_never_yes():
    # The spec's sandbox bullet: --no-root, so the job never mixes its own sandbox with sudo;
    # the same options with no profile, to compare; and render under its own profile.
    sandbox = _sandbox()
    assert sandbox.NO_ROOT == ("--no-root", "--json", "--no-open", "--output")
    profile = Path("/job/profile.sb")
    assert sandbox.cli("/venv/bin/python", profile, *sandbox.NO_ROOT, "/job/report") == [
        "/usr/bin/sandbox-exec",
        "-f",
        "/job/profile.sb",
        "/venv/bin/python",
        "-m",
        "voltry_mac",
        "--no-root",
        "--json",
        "--no-open",
        "--output",
        "/job/report",
    ]
    assert sandbox.cli("/venv/bin/python", None, "render") == [
        "/venv/bin/python",
        "-m",
        "voltry_mac",
        "render",
    ]
    tree = ast.parse((LIVE / "sandbox.py").read_text(encoding="utf-8"))
    (run,) = [
        node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "run"
    ]
    runs = [
        ast.unparse(node)
        for node in ast.walk(run)
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "cli"
    ]
    assert sorted(runs) == sorted(
        [
            "cli(sys.executable, profile_path, *NO_ROOT, str(folder))",
            "cli(sys.executable, None, *NO_ROOT, str(plain))",
            "cli(sys.executable, render_profile, *('render', str(saved), '--output', "
            "str(rendered), '--no-open'))",
        ]
    )


def test_a_no_root_report_has_the_specs_record_and_the_user_commands_alone():
    sandbox = _sandbox()
    assert reports.declined_record("skipped", "no_root_flag") == sandbox.SKIPPED
    assert sandbox.USER_COMMANDS == allowlist.USER_COMMAND_IDS
    assert len(sandbox.USER_COMMANDS) == 27


def test_the_interpreter_is_allowed_by_each_path_it_is_started_by(monkeypatch, tmp_path):
    sandbox = _sandbox()
    real = tmp_path / "python3.14"
    real.write_text("", encoding="utf-8")
    link = tmp_path / "python"
    link.symlink_to(real)
    monkeypatch.setattr(sandbox, "_running_image", lambda: None)
    monkeypatch.setattr(sandbox.sys, "executable", str(link))
    assert sandbox.interpreters() == (str(link), os.path.realpath(real))
    monkeypatch.setattr(sandbox.sys, "executable", os.path.realpath(real))
    assert sandbox.interpreters() == (os.path.realpath(real),)
    # python.org's launcher for macOS becomes the framework's app: that file too, once.
    app = tmp_path / "Python.app" / "Contents" / "MacOS" / "Python"
    monkeypatch.setattr(sandbox, "_running_image", lambda: str(app))
    assert sandbox.interpreters() == (os.path.realpath(real), str(app))
    monkeypatch.setattr(sandbox, "_running_image", lambda: os.path.realpath(real))
    assert sandbox.interpreters() == (os.path.realpath(real),)


def test_the_running_image_is_a_program_on_macos_and_none_elsewhere():
    image = _sandbox()._running_image()
    if sys.platform == "darwin":
        assert image is not None and os.path.isfile(image) and os.access(image, os.X_OK)
    else:
        assert image is None


def test_nothing_may_be_left_in_the_working_folder_or_outside_the_output(tmp_path):
    sandbox = _sandbox()
    work, outside = tmp_path / "cwd", tmp_path / "outside"
    work.mkdir()
    outside.mkdir()
    assert _failing(sandbox.leftover_checks(work, outside)) == []
    (work / "left").write_text("", encoding="utf-8")
    (outside / "written").write_text("", encoding="utf-8")
    checks = sandbox.leftover_checks(work, outside)
    assert _failing(checks) == [
        "nothing left in the working folder",
        "nothing left outside the output folder",
    ]
    assert [check.seen for check in checks] == [1, 1]


def test_an_image_without_sandbox_exec_fails_the_job(tmp_path):
    sandbox = _sandbox()
    missing = sandbox.sandbox_exec_problem(str(tmp_path / "sandbox-exec"))
    assert missing is not None and "fails rather than skips" in missing
    plain = tmp_path / "not-a-program"
    plain.write_text("")
    assert sandbox.sandbox_exec_problem(str(plain)) is not None
    assert sandbox.sandbox_exec_problem(sys.executable) is None


# --- the sandbox job's checks, on made-up runs (m9, n9) ------------------------------------


def test_the_probe_must_find_the_profile_enforced():
    sandbox = _sandbox()
    assert sandbox.probe_check(dict(sandbox.ENFORCED)).holds
    open_writes = {**sandbox.ENFORCED, "a write outside the folder": "done"}
    check = sandbox.probe_check(open_writes)
    assert not check.holds and check.seen == open_writes
    assert sandbox.probe_check(None).seen == "the probe reported nothing"


def test_a_probe_that_reports_nothing_prints_what_sandbox_exec_said(capsys):
    sandbox = _sandbox()
    stderr = "\n".join(f"sandbox-exec: line {n}" for n in range(1, 9))
    assert sandbox.probe_report("", stderr, 65) is None
    printed = capsys.readouterr().out.split("\n")
    assert printed[0] == "  the probe exited 65 and reported nothing; sandbox-exec's stderr:"
    assert printed[1:6] == [f"    sandbox-exec: line {n}" for n in range(1, 6)]
    assert sandbox.probe_report('{"a": "done"}', "", 0) == {"a": "done"}


def _entry(
    suffix: str, *, mode: int = stat.S_IFREG | 0o600, uid: int = 501, links: int = 1
) -> object:
    return _sandbox().Entry(suffix, "Voltry Mac Report 2026-09-28 1200", mode, uid, links)


def test_the_report_files_are_the_runners_own_mode_0600():
    sandbox = _sandbox()
    assert _failing(sandbox.file_checks([_entry(".json"), _entry(".pdf")], 501)) == []
    for entries, failed in (
        ([_entry(".json")], "a PDF and a JSON sharing one base name, and nothing else"),
        ([_entry(".json"), _entry(".pdf", uid=0)], "each a regular file the runner user owns"),
        (
            [_entry(".json"), _entry(".pdf", mode=stat.S_IFLNK | 0o600)],
            "each a regular file the runner user owns",
        ),
        (
            [_entry(".json", mode=stat.S_IFREG | 0o644), _entry(".pdf")],
            "each with mode 0600 and one name",
        ),
        ([_entry(".json", links=2), _entry(".pdf")], "each with mode 0600 and one name"),
    ):
        assert _failing(sandbox.file_checks(entries, 501)) == [failed]


def _report(*, failed: tuple[str, ...] = (), reasons: tuple[str, ...] = ()) -> dict:
    sandbox = _sandbox()
    return {
        "collection": {"unexpected_reasons": list(reasons)},
        "elevation": dict(sandbox.SKIPPED),
        "commands": [
            {"id": command, "runs": 1, "failed_runs": int(command in failed)}
            for command in sandbox.USER_COMMANDS
        ],
    }


def test_a_complete_report_passes():
    sandbox = _sandbox()
    checks = sandbox.report_checks(_report(), returncode=0, plain=_report())
    assert _failing(checks) == []
    failed = _report(failed=("C13",), reasons=("tool_error",))
    assert _failing(sandbox.report_checks(failed, returncode=1, plain=failed)) == []


def test_the_exit_is_the_one_the_packages_own_rule_gives(monkeypatch):
    # The package's rule, model.unexpected and model.exit_code, not a copy of it.
    sandbox = _sandbox()
    monkeypatch.setattr(sandbox.model, "unexpected", lambda report: True)
    assert _failing(sandbox.report_checks(_report(), returncode=1, plain=_report())) == []
    assert _failing(sandbox.report_checks(_report(), returncode=0, plain=_report())) == [
        "exit 1, the code the report implies"
    ]


def test_a_profile_that_breaks_a_command_fails_the_job():
    # Every command failing under the profile would leave the report implying exit 1, and
    # the job green: the run without the profile is the comparison.
    sandbox = _sandbox()
    everything = _report(failed=sandbox.USER_COMMANDS, reasons=("tool_error",))
    checks = sandbox.report_checks(everything, returncode=1, plain=_report())
    (failed,) = [check for check in checks if not check.holds]
    assert (
        failed.what == "the same commands failed with the profile as without it, so it broke none"
    )
    assert failed.seen.endswith("without it []")
    assert _failing(sandbox.report_checks(_report(), returncode=0, plain=None)) == [
        "the same commands failed with the profile as without it, so it broke none"
    ]


def test_the_elevation_record_and_the_commands_are_a_no_root_runs():
    sandbox = _sandbox()
    report = _report()
    report["elevation"] = {**sandbox.SKIPPED, "skip_cause": "not_admin"}
    report["commands"] = report["commands"][:-1]
    assert _failing(sandbox.report_checks(report, returncode=0, plain=_report())) == [
        "the elevation record of a --no-root run",
        "one run of each user command, and nothing else run",
    ]


@pytest.mark.parametrize(
    ("pdf", "rendered", "code", "failed"),
    [
        (b"%PDF-1.4\n...\n%%EOF\n", b"%PDF-1.4\n...\n%%EOF\n", 0, []),
        (b"%PDF-1.4\n...", b"%PDF-1.4\n...", 0, ["the PDF begins with %PDF- and ends with %%EOF"]),
        (
            b"%PDF-1.4\n...\n%%EOF\n",
            b"%PDF-1.4\n..!\n%%EOF\n",
            0,
            ["render, under the profile, rebuilt the PDF from the JSON byte for byte"],
        ),
        (
            b"%PDF-1.4\n...\n%%EOF\n",
            None,
            4,
            ["render, under the profile, rebuilt the PDF from the JSON byte for byte"],
        ),
    ],
    ids=["whole and rebuilt", "cut short", "rebuilt otherwise", "not rebuilt"],
)
def test_the_pdf_is_whole_and_render_rebuilds_it_byte_for_byte(pdf, rendered, code, failed):
    assert _failing(_sandbox().pdf_checks(pdf, rendered, render_code=code)) == failed


def test_the_job_removes_its_folder_whatever_happened(tmp_path):
    sandbox = _sandbox()
    root = tmp_path / "job"
    root.mkdir()
    (root / "report.json").write_text("{}", encoding="utf-8")
    assert sandbox.within(root, lambda folder: ["a failed check"]) == ["a failed check"]
    assert not root.exists()
    root.mkdir()

    def broken(folder: Path) -> list[str]:
        raise RuntimeError("the run stopped")

    with pytest.raises(RuntimeError):
        sandbox.within(root, broken)
    assert not root.exists()
    tree = ast.parse((LIVE / "sandbox.py").read_text(encoding="utf-8"))
    (main,) = [
        node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main"
    ]
    calls = [
        node
        for node in ast.walk(main)
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "within"
    ]
    assert len(calls) == 1 and ast.unparse(calls[0].args[1]) == "run"


# --- both scripts refuse to run here --------------------------------------------------------


@pytest.mark.parametrize(
    ("argv", "refused"),
    [
        (["capture.py"], "The voltry-mac capture changes the machine it runs on"),
        (["capture.py", "--cleanup"], "The voltry-mac capture changes the machine it runs on"),
        (["sandbox.py"], "The voltry-mac sandbox run starts the real command under sandbox-exec"),
    ],
    ids=["capture", "cleanup", "sandbox"],
)
def test_the_script_refuses_to_run_here(tmp_path, argv, refused):
    """The only run of the job code here: nothing of the gate is set, so each script says
    why it will not run and ends, before it reads or changes anything."""
    environ = {name: value for name, value in os.environ.items() if name not in GATE_VARIABLES}
    environ["PYTHONDONTWRITEBYTECODE"] = "1"
    workspace = tmp_path / "cwd"
    workspace.mkdir()
    found = subprocess.run(
        [sys.executable, str(LIVE / argv[0]), *argv[1:]],
        cwd=workspace,
        env=environ,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert found.returncode == 2, found.stderr
    assert found.stderr.startswith(refused)
    assert "Not set that way here" in found.stderr or "Not so here" in found.stderr
    assert found.stdout == ""
    assert list(workspace.iterdir()) == []


# --- each step, sudo and the probes faked: a bad result reaches the verdict (round 2's m1) --

REFUSED_LINE = (
    "Sorry, user vmcap_plain is not allowed to execute '/usr/bin/id' as root on capture-host."
)
# What sudo prints in each case on a stock image with sudo 1.9.17p2, by the case's name and
# what -S reads: the good run each test below changes one thing of. The no-terminal cases
# print the lecture first, as on an account's first use.
GOOD = {
    ("-n with no cached authorization", "devnull"): (1, "sudo: a password is required\n"),
    ("no terminal, without -S", "devnull"): (1, "\n".join((*APPLE_LECTURE, NO_TERMINAL, ""))),
    ("no terminal, without -S, over ssh without -t", "devnull"): (1, f"{NO_TERMINAL_SSH}\n"),
    ("end of input through -S", "empty"): (
        1,
        "sudo: no password was provided\nsudo: a password is required\n",
    ),
    ("a wrong password through -S", "wrong"): (1, "sudo: 1 incorrect password attempt\n"),
    ("three wrong passwords on a terminal", "devnull"): (
        1,
        "sudo: 3 incorrect password attempts\n",
    ),
    ("a password read that times out", "devnull"): (
        1,
        "sudo: timed out reading password\nsudo: a password is required\n",
    ),
    ("a command the drop-in denies", "devnull"): (1, f"{REFUSED_LINE}\n"),
    ("a command the drop-in denies, with a cmddenial_message", "devnull"): (
        1,
        f"{REFUSED_LINE}\nVoltry capture: the drop-in denies this command.\n",
    ),
    ("an account sudo does not list, running a command", "devnull"): (
        1,
        "vmcap_unlisted is not in the sudoers file.\n",
    ),
    ("an account sudo does not list, asking sudo -v", "devnull"): (
        1,
        "Sorry, user vmcap_unlisted may not run sudo on capture-host.\n",
    ),
    ("an account the drop-in lists for another host", "devnull"): (
        1,
        "vmcap_elsewhere is not allowed to run sudo on capture-host.\n",
    ),
    ("a rewritten authfail_message", "wrong"): (
        1,
        "sudo: Voltry capture rewrote this message after 1 attempt\n",
    ),
    (LOCKED, "password"): (1, "sudo: 1 incorrect password attempt\n"),
    (EXPIRED, "password"): (0, ""),
    (LOCKED_OUT, "wrong"): (1, "sudo: 1 incorrect password attempt\n"),
    (LOCKED_OUT, "password"): (
        1,
        "sudo: PAM authentication error: Unknown error -12345\nsudo: a password is required\n",
    ),
}
STATES = {"vmcap_locked": 0, "vmcap_expired": 0, "vmcap_lockout": 0}


def _messages_step(
    monkeypatch,
    *,
    changes: dict | None = None,
    killed: tuple = (),
    version: tuple = NEWEST,
    modules: tuple | None = STOCK,
    states: dict | None = None,
) -> tuple[list[str], list[tuple[str, str]]]:
    """Step 3 with sudo faked: each case's run answers from GOOD, as changed; returns the
    checks that failed and each run made, as its case and what -S read."""
    capture = _capture()
    answers = {**GOOD, **(changes or {})}
    runs: list[tuple[str, str]] = []

    def sudo_as(case: object, account: object) -> tuple[object, str]:
        key = (case.name, case.stdin)
        runs.append(key)
        assert account.name == case.account, "each case runs as its own account"
        code, stderr = answers[key]
        return capture.Seen(code=code, killed=key in killed), stderr

    monkeypatch.setattr(capture, "_sudo_as", sudo_as)
    accounts = {
        name: capture.Account(name, 7401 + index, 20, f"{index:032x}")
        for index, name in enumerate(capture.ACCOUNTS)
    }
    checks = capture.Checks()
    capture.capture_messages(
        accounts,
        checks,
        version=version,
        lecture=APPLE_LECTURE,
        modules=modules,
        states=STATES if states is None else states,
    )
    return checks.failed, runs


def test_the_messages_step_passes_a_good_run_and_makes_each_run_once(monkeypatch):
    failed, runs = _messages_step(monkeypatch)
    assert failed == []
    # Every case runs once, in order, and the locked-out case's failed attempt comes right
    # before its right password.
    expected = []
    for case in _messages().CASES:
        expected += [(case.name, "wrong")] if case.primed else []
        expected.append((case.name, case.stdin))
    assert runs == expected
    assert runs.index((LOCKED_OUT, "wrong")) + 1 == runs.index((LOCKED_OUT, "password"))


def test_on_sudo_1_9_13p2_the_messages_step_passes_what_that_sudo_prints(monkeypatch):
    changes = {("no terminal, without -S, over ssh without -t", "devnull"): (1, f"{NO_TERMINAL}\n")}
    failed, runs = _messages_step(monkeypatch, changes=changes, version=OLDEST)
    assert failed == []
    assert ("a command the drop-in denies, with a cmddenial_message", "devnull") not in runs


JUDGED = ": sudo failed, and each stderr line matches its pinned template and no other"


@pytest.mark.parametrize(
    ("changes", "failed"),
    [
        (
            {
                ("-n with no cached authorization", "devnull"): (
                    1,
                    "sudo: a password is required\nsudo: new\n",
                )
            },
            f"-n with no cached authorization{JUDGED}",
        ),
        (
            {("a wrong password through -S", "wrong"): (0, "sudo: 1 incorrect password attempt\n")},
            f"a wrong password through -S{JUDGED}",
        ),
        (
            {(LOCKED_OUT, "password"): (1, "sudo: PAM authentication error: x\n")},
            f"{LOCKED_OUT}{JUDGED}",
        ),
        (
            {(LOCKED, "password"): (0, "")},
            f"{LOCKED}: macOS refused the disabled account at the password, as it does a wrong "
            "one, so sudo failed in the authentication class (change record 13)",
        ),
        (
            {(EXPIRED, "password"): (1, "sudo: 1 incorrect password attempt\n")},
            f"{EXPIRED}: macOS accepted the password that must change, so sudo succeeded "
            "(change record 13)",
        ),
        (
            {(EXPIRED, "password"): (0, "A line sudo never printed before\n")},
            f"{EXPIRED}: each stderr line matches one template or is one to ignore",
        ),
        (
            {(LOCKED_OUT, "wrong"): (1, "sudo: a line sudo never printed before\n")},
            f"{LOCKED_OUT}: the failed attempt's stderr, each line one template or one to ignore",
        ),
    ],
    ids=[
        "a new sudo line",
        "an exit of 0",
        "the lockout in another class",
        "the disabled account accepted",
        "the expired password refused",
        "a new line where nothing is judged",
        "a new line in the failed attempt",
    ],
)
def test_a_bad_result_from_any_case_reaches_the_verdict(monkeypatch, changes, failed):
    found, _ = _messages_step(monkeypatch, changes=changes)
    assert found == [failed]


def test_a_killed_case_fails_and_its_template_is_never_said_to_be_held_elsewhere(
    monkeypatch, capsys
):
    # It hung before printing anything, and was killed at its deadline.
    hung = ("no terminal, without -S", "devnull")
    found, _ = _messages_step(monkeypatch, changes={hung: (-9, "")}, killed=(hung,))
    assert found == ["no terminal, without -S: sudo ended within 30 s"]
    printed = capsys.readouterr().out
    assert f"not reproduced: {NO_TERMINAL!r}; the case that asks for it failed above" in printed
    assert f"not reproduced on this image: {NO_TERMINAL!r}" not in printed


def test_where_pwpolicy_failed_nothing_is_held_to_record_13(monkeypatch, capsys):
    states = {"vmcap_locked": 4, "vmcap_expired": 4, "vmcap_lockout": 4}
    changes = {
        (LOCKED, "password"): (0, ""),
        (LOCKED_OUT, "password"): (0, ""),
    }
    found, _ = _messages_step(monkeypatch, changes=changes, states=states)
    assert found == []
    printed = capsys.readouterr().out
    assert "pwpolicy could not set the lockout policy (exit 4)" in printed
    assert "did not lock the account" not in printed


def test_on_another_stack_nothing_is_held_to_record_13(monkeypatch, capsys):
    changes = {(LOCKED, "password"): (0, "")}
    modules = ("pam_opendirectory.so",)
    found, _ = _messages_step(monkeypatch, changes=changes, modules=modules)
    assert found == []
    assert "checks accounts with pam_opendirectory.so" in capsys.readouterr().out


def test_a_pam_file_that_cannot_be_read_is_said_so(monkeypatch, capsys):
    found, _ = _messages_step(monkeypatch, modules=None)
    assert found == []
    printed = capsys.readouterr().out
    assert "/etc/pam.d/sudo's account stack: could not be read" in printed


class _Probes:
    """The capture's probes faked: each run answers with ``found`` and ``seen``, and notes
    who it ran as and how."""

    def __init__(self, found: dict, seen: object = None) -> None:
        self.found, self.seen = found, seen
        self.calls: list[tuple] = []

    def __call__(self, account, work, *, terminal, answers=(), delay_s=0.0, deadline_s):
        self.calls.append((account.name, terminal, tuple(answers), delay_s, deadline_s))
        return self.found, self.seen if self.seen is not None else _capture().Seen()


TOPOLOGY = SimpleNamespace(
    S3N_S=90.0, STAND_IN_NAME="sleep", direct=None, slow=None, stand_in=None, power_alone=None
)
RUNNER = ("runner", 501, 20)


def _step(monkeypatch, probes: _Probes, step: Callable[..., None], *args, **kwargs) -> list[str]:
    capture = _capture()
    monkeypatch.setattr(capture, "_probe_as", probes)
    monkeypatch.setattr(capture, "topology", TOPOLOGY)
    checks = capture.Checks()
    step(*args, checks, **kwargs)
    return checks.failed


def test_direct_execution_records_its_checks(monkeypatch):
    capture = _capture()
    runner = capture.Account(*RUNNER)
    good = {"S3n": [_run_summary()], "S4n": _run_summary()}
    assert _step(monkeypatch, _Probes(good), capture.direct, runner, 283) == []
    bad = {"S3n": [_run_summary()], "S4n": _run_summary(descendants=1)}
    assert _step(monkeypatch, _Probes(bad), capture.direct, runner, 283) == [
        "S4n: no process below level 0: sudo executed the payload directly"
    ]


def test_the_slow_prompt_answers_after_10_s_and_holds_clocks_to_the_answers(monkeypatch):
    capture = _capture()
    admin = capture.Account("vmcap_admin", 7412, 20, "0" * 32)
    seen = capture.Seen(prompts=list(PROMPTS), answers=list(ANSWERS))
    probes = _Probes(_slow(), seen)
    assert _step(monkeypatch, probes, capture.slow, admin, 283, version=NEWEST, monitor=False) == []
    ((name, terminal, answers, delay, _),) = probes.calls
    assert (name, terminal, answers, delay) == ("vmcap_admin", True, ("0" * 32,) * 2, 10.0)
    # A clock armed after the prompt and before its answer started during the wait.
    during = _Probes(_slow(s3={"armed": [[5.0, "launch"]]}), seen)
    assert _step(monkeypatch, during, capture.slow, admin, 283, version=NEWEST, monitor=False) == [
        "executed directly, S3: no launch clock started during the wait"
    ]


def _stand_in_found(**changes: object) -> dict:
    capture = _capture()
    found = _broker_found(
        record=capture.STAND_IN_RECORD,
        ledger=["timeout", "runtime_deadline"],
        power=["tool_error", "skipped_after_unsafe_stop"],
        survivors=[[4321, 283, STARTED, "sleep"]],
        notes=[_note(4321, 283, "sleep")],
        payloads=[{**_broker_found()["payloads"][0], "identity": [283, "sleep"]}],
        commands=["P1", "S1", "S2n", "S3n", "S5"],
    )
    return {**found, **changes}


def test_each_broker_run_records_its_checks(monkeypatch):
    capture = _capture()
    runner = capture.Account(*RUNNER)
    assert _step(monkeypatch, _Probes(_stand_in_found()), capture.stand_in, runner, 283) == []
    assert _step(monkeypatch, _Probes(_stand_in_found(held=0)), capture.stand_in, runner, 283) == [
        "The count's stand-in: still held when the broker returned"
    ]
    assert _step(
        monkeypatch, _Probes(_stand_in_found(stops=["terminated"])), capture.stand_in, runner, 283
    ) == ["The count's stand-in: the one stop met EPERM"]
    assert _step(monkeypatch, _Probes(_broker_found()), capture.power_alone, runner) == []
    assert _step(monkeypatch, _Probes(_broker_found(left=1)), capture.power_alone, runner) == [
        "The real S4n alone: the nonblocking wait collected it once it ended on its own"
    ]


class _Gate:
    """The capture's gate, open, for a test that runs main() with everything past it faked."""

    @staticmethod
    def refusal_to_change(environ, *, euid, virtual):
        return None


@pytest.mark.parametrize(("removed", "code"), [(True, 0), (False, 1)])
def test_main_fails_when_the_captures_own_cleanup_leaves_anything(
    monkeypatch, capsys, removed, code
):
    capture = _capture()
    ran: list[str] = []
    monkeypatch.setattr(capture, "gate", _Gate)
    monkeypatch.setattr(capture, "capture", lambda checks: ran.append("capture"))
    monkeypatch.setattr(capture, "cleanup", lambda: removed)
    assert capture.main([]) == code
    assert ran == ["capture"]
    printed = capsys.readouterr().out
    line = "every drop-in and test account the capture made is gone"
    assert (f"FAIL  {line}" in printed) is not removed
    assert capture.main(["--cleanup"]) == code
    assert capture.main(["--other"]) == 2


@pytest.mark.parametrize(
    ("version", "denial"),
    [(OLDEST, False), ((1, 9, 15, 0), False), ((1, 9, 16, 0), True), (NEWEST, True)],
    ids=["1.9.13p2", "1.9.15", "1.9.16", "1.9.17p2"],
)
def test_the_capture_installs_the_denial_drop_in_only_where_sudo_has_the_option(
    monkeypatch, version, denial
):
    capture = _capture()
    done: list[str] = []
    accounts = {name: capture.Account(name, 7401, 20, "0" * 32) for name in capture.ACCOUNTS}
    for name, value in {
        "_invoker": lambda: capture.Account(*RUNNER),
        "pwd": SimpleNamespace(getpwnam=lambda name: SimpleNamespace(pw_uid=283)),
        "topology": SimpleNamespace(SERVICE_ACCOUNT="_mmaintenanced"),
        "sudo_defaults": lambda: (version, None),
        "_includes_drop_ins": lambda: True,
        "_read": lambda name: subprocess.CompletedProcess([], 56, "", ""),
        "check_base_policy": lambda: done.append("check_base_policy"),
        "make_accounts": lambda: done.append("make_accounts") or accounts,
        "set_states": lambda: done.append("set_states") or dict(STATES),
        "install": lambda name, text: done.append(name),
        "lecture_lines": lambda path: (),
        "pam_account_modules": lambda: STOCK,
        "capture_messages": lambda *args, **kwargs: done.append("messages"),
        "direct": lambda *args: done.append("direct"),
        "slow": lambda *args, **kwargs: done.append("slow"),
        "remove_drop_in": lambda name: done.append(f"removed {name}") or True,
        "stand_in": lambda *args: done.append("stand_in"),
        "power_alone": lambda *args: done.append("power_alone"),
    }.items():
        monkeypatch.setattr(capture, name, value)
    checks = capture.Checks()
    capture.capture(checks)
    assert checks.failed == []
    drop_ins = [capture.MESSAGES_DROP_IN, capture.RUNNER_DIRECT, capture.ADMIN_DIRECT]
    if denial:
        drop_ins.insert(1, capture.DENIAL_DROP_IN)
    assert done == [
        "check_base_policy",
        "make_accounts",
        "set_states",
        *drop_ins,
        "messages",
        "direct",
        "slow",
        f"removed {capture.ADMIN_DIRECT}",
        "slow",
        "stand_in",
        "power_alone",
    ]


# --- the sandbox job's run, its commands faked (round 2's m1) -------------------------------

PDF = b"%PDF-1.4\n1 0 obj\n<< >>\nendobj\n%%EOF\n"
INVALID = "not the validator's"


class _Validator:
    """The package's validator, as the job calls it: it refuses a report that carries
    INVALID, and takes any other."""

    @staticmethod
    def read(data: bytes) -> dict:
        if INVALID.encode() in data:
            raise ValueError("report_id: the report ID does not recompute from this document")
        return {}


def _written(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    path.chmod(0o600)


def _sandbox_run(monkeypatch, tmp_path, **bad: object) -> list[str]:
    """The job's run() with sandbox-exec, the CLI and the validator faked: each run writes
    the report files its argv names, as the real one would; ``bad`` changes one thing."""
    sandbox = _sandbox()
    report = _report()

    def cli(argv: list[str], work: Path) -> int:
        arguments = argv[argv.index("voltry_mac") + 1 :]
        folder = Path(arguments[arguments.index("--output") + 1])
        if arguments[0] == "render":
            _written(folder / "Voltry Mac Report 2026-09-28 12.00.pdf", bad.get("rendered", PDF))
            return 0
        profiled = argv[0] == sandbox.SANDBOX_EXEC
        if profiled and bad.get("silent"):
            return 1
        document = bad.get("report", report) if profiled else bad.get("plain", report)
        stem = folder / "Voltry Mac Report 2026-09-28 12.00"
        _written(Path(f"{stem}.json"), json.dumps(document).encode())
        _written(Path(f"{stem}.pdf"), PDF)
        if profiled and bad.get("leftover"):
            (work / "left.txt").write_text("", encoding="utf-8")
        if profiled and bad.get("outside"):
            (work.parent / "outside" / "written.txt").write_text("", encoding="utf-8")
        return bad.get("code", 0) if profiled else 0

    monkeypatch.setattr(
        sandbox, "_probe", lambda *paths: bad.get("enforced", dict(sandbox.ENFORCED))
    )
    monkeypatch.setattr(sandbox, "_cli", cli)
    monkeypatch.setattr(sandbox, "validate", _Validator)
    root = tmp_path / "job"
    root.mkdir()
    return sandbox.run(root)


def test_the_sandbox_run_passes_a_good_run(monkeypatch, tmp_path):
    assert _sandbox_run(monkeypatch, tmp_path) == []


@pytest.mark.parametrize(
    ("bad", "failed"),
    [
        (
            {"enforced": {"a write outside the folder": "done"}},
            [
                "the profile holds: a write in the folder and /dev/null opened read-write go "
                "through; a write outside it, /usr/bin/touch and a connection are refused"
            ],
        ),
        ({"silent": True}, ["the report came out"]),
        ({"report": {**_report(), INVALID: True}}, ["the package's validator takes the JSON"]),
        ({"code": 1}, ["exit 0, the code the report implies"]),
        (
            {"plain": _report(failed=("C13",), reasons=("tool_error",))},
            ["the same commands failed with the profile as without it, so it broke none"],
        ),
        (
            {"plain": {**_report(), INVALID: True}},
            ["the same commands failed with the profile as without it, so it broke none"],
        ),
        (
            {"rendered": PDF.replace(b"<< >>", b"<< /A 1 >>")},
            ["render, under the profile, rebuilt the PDF from the JSON byte for byte"],
        ),
        ({"leftover": True}, ["nothing left in the working folder"]),
        ({"outside": True}, ["nothing left outside the output folder"]),
    ],
    ids=[
        "the profile not enforced",
        "no report",
        "a JSON the validator refuses",
        "another exit",
        "another command failed without the profile",
        "the run without the profile refused",
        "render not byte for byte",
        "a file left in the working folder",
        "a file written outside",
    ],
)
def test_a_bad_result_from_any_sandbox_run_reaches_the_verdict(monkeypatch, tmp_path, bad, failed):
    assert _sandbox_run(monkeypatch, tmp_path, **bad) == failed


class _SandboxGate:
    SANDBOX_REFUSAL = "refused: {missing}"

    @staticmethod
    def refusal(environ, text):
        return None


@pytest.mark.parametrize(
    ("missing", "failed", "code", "runs"),
    [
        ("/usr/bin/sandbox-exec is not on this image", [], 1, []),
        (None, [], 0, ["run"]),
        (None, ["a check"], 1, ["run"]),
    ],
    ids=["no sandbox-exec", "every check passed", "a check failed"],
)
def test_the_sandbox_job_fails_without_sandbox_exec_and_on_any_failed_check(
    monkeypatch, missing, failed, code, runs
):
    sandbox = _sandbox()
    ran: list[str] = []
    monkeypatch.setattr(sandbox, "gate", _SandboxGate)
    monkeypatch.setattr(sandbox, "sandbox_exec_problem", lambda: missing)
    monkeypatch.setattr(sandbox, "run", lambda root: ran.append("run") or list(failed))
    assert sandbox.main() == code
    assert ran == runs


# --- the live checks' helpers (tests_live/live.py) -------------------------------------------


def _live() -> ModuleType:
    return _load("voltry_mac_live_helpers", "live.py")


def test_powermetrics_arguments_read_as_ps_shows_them_once_it_cut_its_samplers():
    # The first live run (2026-09-29): powermetrics cuts --samplers at each comma in its own
    # argument memory, and ps prints as many strings as it started with.
    live = _live()
    assert live.parsed_in_place(live.POWERMETRICS) == (
        "/usr/bin/powermetrics -n 5 -i 1000 --samplers cpu_power gpu_power thermal"
    )
    assert live.parsed_in_place(("/bin/x", "-a", "b")) == "/bin/x -a b"


def test_sudos_prompt_counts_only_bare_never_in_a_debug_lines_template():
    live = _live()
    prompt = "Your Mac password, for the two steps above: "
    debug = f'S2 /usr/bin/sudo -v -p "{prompt}": exit 0, 12 ms\n'
    assert not live.prompted(debug)
    assert live.prompted(debug + prompt)
    assert live.prompted(prompt)


@pytest.mark.parametrize(
    ("line", "kept"),
    [
        ('Error: unable to open database "file:/x.db": unable to open database file', True),
        ("Parse error near line 1: no such table: ecc_errors_v2", True),
        ("Runtime error: database disk image is malformed", True),
        ("sandbox-exec: sandbox_apply: Operation not permitted", True),
        ("Sorry, user runner is not allowed to execute '/bin/x' as root on host-1.", False),
        ("sudo: a password is required", False),
    ],
)
def test_the_count_diagnosis_prints_sqlite3s_and_sandbox_execs_lines_and_no_other(line, kept):
    said = _live()._said(line)
    assert said == (line if kept else f"a line of {len(line)} characters")
