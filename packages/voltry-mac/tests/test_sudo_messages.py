"""How sudo's stderr is classified (docs/VOLTRY_MAC_SPEC.md, Decision 2, the classifier and
its 15 pinned templates for sudo 1.9.17p2; Test strategy part 3, "sudo stderr
classification").

Lines are matched anchored at both ends after trailing whitespace is dropped: %s is any
text, '...' a quoted command, %u one or more digits. The first class present decides, in
the order account state, policy refusal, authentication, any other sudo: line, anything
else. At S2 the classes give blocked, refused, denied, error and error; at a payload
account_blocked, policy_refusal, auth_failed, sudo_error and payload_error.
"""

from __future__ import annotations

import itertools
import time

import pytest

from voltry_mac import sudo_messages as m

ACCOUNT = [
    "sudo: account validation failure, is your account locked?",
    "sudo: Account or password is expired, reset your password and try again",
    "sudo: unable to change expired password: Authentication token manipulation error",
    "sudo: Password expired, contact your system administrator",
    'sudo: Account expired or PAM config lacks an "account" section for sudo, contact your '
    "system administrator",
]
POLICY = [
    "Sorry, user owner is not allowed to execute '/usr/bin/true' as root on host.",
    "Sorry, user owner may not run sudo on host.",
    "owner is not allowed to run sudo on host.",
    "owner is not in the sudoers file.",
]
AUTHENTICATION = [
    "sudo: 1 incorrect password attempt",
    "sudo: 3 incorrect password attempts",
    "sudo: 12 incorrect password attempts",
    "sudo: a password is required",
    "sudo: a terminal is required to read the password; either use the -S option to read "
    "from standard input or configure an askpass helper",
    "sudo: a terminal is required to read the password; either use ssh's -t option or "
    "configure an askpass helper",
    "sudo: timed out reading password",
    "sudo: no password was provided",
]
OTHER_SUDO = [
    "sudo: unable to read password: Input/output error",
    "sudo: PAM account management error: Permission denied",
    "sudo: three strikes and you are out",  # a rewritten authfail_message
]
OTHER = ["sqlite3: unable to open database file", "Error: no such table: ecc_errors_v2"]
IGNORED = [
    "Sorry, try again.",
    "This incident has been reported to the administrator.",
    "",
    "WARNING: Improper use of the sudo command could lead to data loss",
    "We trust you have received the usual lecture from the local System",
]
BY_CLASS = {
    m.Class.ACCOUNT_STATE: ACCOUNT,
    m.Class.POLICY_REFUSAL: POLICY,
    m.Class.AUTHENTICATION: AUTHENTICATION,
    m.Class.OTHER_SUDO: OTHER_SUDO,
    m.Class.OTHER: OTHER,
}
S2 = {
    m.Class.ACCOUNT_STATE: "blocked",
    m.Class.POLICY_REFUSAL: "refused",
    m.Class.AUTHENTICATION: "denied",
    m.Class.OTHER_SUDO: "error",
    m.Class.OTHER: "error",
}
PAYLOAD = {
    m.Class.ACCOUNT_STATE: "account_blocked",
    m.Class.POLICY_REFUSAL: "policy_refusal",
    m.Class.AUTHENTICATION: "auth_failed",
    m.Class.OTHER_SUDO: "sudo_error",
    m.Class.OTHER: "payload_error",
}
EXAMPLES = [(line, kind) for kind, lines in BY_CLASS.items() for line in lines]


def test_there_are_fifteen_pinned_templates_in_three_classes():
    assert len(m.TEMPLATES) == 15
    counts = {kind: sum(1 for k, _ in m.TEMPLATES if k is kind) for kind in m.Class}
    assert counts == {
        m.Class.ACCOUNT_STATE: 5,
        m.Class.POLICY_REFUSAL: 4,
        m.Class.AUTHENTICATION: 6,
        m.Class.OTHER_SUDO: 0,
        m.Class.OTHER: 0,
    }


@pytest.mark.parametrize(("line", "kind"), EXAMPLES, ids=[line[:48] for line, _ in EXAMPLES])
def test_each_line_alone_gives_its_class_at_s2_and_at_a_payload(line, kind):
    stderr = line + "\n"
    assert m.classify(stderr) is kind
    assert m.s2_outcome(stderr) == S2[kind]
    assert m.payload_ending(stderr) == PAYLOAD[kind]


def test_trailing_whitespace_is_dropped_before_matching():
    assert m.classify("sudo: a password is required  \t\r\n") is m.Class.AUTHENTICATION


PAIRS = [(first, second) for first, second in itertools.permutations(list(m.Class), 2)]


@pytest.mark.parametrize(("first", "second"), PAIRS, ids=[f"{a.name}+{b.name}" for a, b in PAIRS])
def test_each_pair_of_classes_in_either_order_gives_the_one_that_comes_first(first, second):
    stderr = BY_CLASS[first][0] + "\n" + BY_CLASS[second][0] + "\n"
    assert m.classify(stderr) is min(first, second)


def test_an_account_state_line_before_an_authentication_one_is_blocked():
    # An expired password prints its account-state line, then fails the change under -n.
    stderr = ACCOUNT[1] + "\nsudo: a password is required\n"
    assert (m.s2_outcome(stderr), m.payload_ending(stderr)) == ("blocked", "account_blocked")


TEMPLATE_EXAMPLES = [
    (line, kind)
    for kind in (m.Class.ACCOUNT_STATE, m.Class.POLICY_REFUSAL, m.Class.AUTHENTICATION)
    for line in BY_CLASS[kind]
]


def test_every_template_has_an_example_below():
    assert len(TEMPLATE_EXAMPLES) >= len(m.TEMPLATES) == 15
    for kind, template in m.TEMPLATES:
        matching = [line for line, found in TEMPLATE_EXAMPLES if found is kind]
        assert any(m._line(line) is kind for line in matching), template


@pytest.mark.parametrize(
    ("line", "kind"), TEMPLATE_EXAMPLES, ids=[line[:48] for line, _ in TEMPLATE_EXAMPLES]
)
def test_the_ignored_lines_around_a_template_change_nothing(line, kind):
    stderr = "\n".join([*IGNORED, line, *reversed(IGNORED)]) + "\n"
    assert m.classify(stderr) is kind


def test_a_refusal_followed_by_a_cmddenial_message_is_still_a_refusal():
    stderr = POLICY[0] + "\nThis command is not permitted on managed Macs.\n"
    assert m.payload_ending(stderr) == "policy_refusal"


def test_a_silent_non_zero_exit_is_the_last_class():
    assert m.classify("") is m.Class.OTHER
    assert (m.s2_outcome(""), m.payload_ending("")) == ("error", "payload_error")


def test_only_ignored_lines_are_the_last_class():
    assert m.classify("\n".join(IGNORED)) is m.Class.OTHER


@pytest.mark.parametrize(
    "line",
    [
        "note: sudo: a password is required",  # text before
        "sudo: a password is required, twice",  # text after
        "sudo: a password was required",  # one word changed
        "sudo: incorrect password attempts",  # no count
        "sudo: 3 incorrect password attemptss",
        "Sorry, user owner is not allowed to execute /usr/bin/true as root on host.",  # unquoted
        "owner is not in the sudoers file",  # no full stop
        "is not in the sudoers file.",  # no name
    ],
)
def test_a_near_miss_does_not_match_its_template(line):
    kind = m.classify(line + "\n")
    assert kind in (m.Class.OTHER_SUDO, m.Class.OTHER)
    assert kind is (m.Class.OTHER_SUDO if line.startswith("sudo:") else m.Class.OTHER)


def test_the_classes_order_is_the_precedence():
    assert list(m.Class) == sorted(m.Class)
    assert [kind.name for kind in m.Class] == [
        "ACCOUNT_STATE",
        "POLICY_REFUSAL",
        "AUTHENTICATION",
        "OTHER_SUDO",
        "OTHER",
    ]


# --- the #346 review ----------------------------------------------------------------------------

UNIT = "x is not allowed to execute 'a' as b on c. "


@pytest.mark.parametrize(
    "stderr",
    [
        "Sorry, user " + UNIT * 400 + "!",
        " is not allowed to run sudo on " * 16000 + "!",
        "Sorry, user " + "a " * (2 * 1024 * 1024),
        "sudo: x\n" * (512 * 1024),
    ],
    ids=[
        "a refusal's separators, failing at the end",
        "a leading wildcard",
        "one long line",
        "4 MiB of lines",
    ],
)
def test_classifying_hostile_stderr_takes_linear_time(stderr):
    # Linear work on 4 MiB takes well under a second here and about 10 s under coverage on
    # a loaded CI runner; backtracking took minutes to hours on these inputs, so the bound
    # sits between the two.
    started = time.perf_counter()
    m.classify(stderr)
    assert time.perf_counter() - started < 60.0


def test_the_linear_matcher_still_needs_each_wildcard_to_hold_something():
    assert m._line("Sorry, user  may not run sudo on host.") is m.Class.OTHER
    assert m._line("Sorry, user owner is not allowed to execute '' as root on host.") is (
        m.Class.POLICY_REFUSAL
    ), "a quoted command may be empty"
    assert m._line("owner is not allowed to run sudo on .") is m.Class.OTHER
    assert m._line("is not in the sudoers file.") is m.Class.OTHER


@pytest.mark.parametrize(
    "line",
    [
        "sudo: three incorrect password attempts",
        "sudo: 3a incorrect password attempts",
        "sudo:  incorrect password attempts",
    ],
)
def test_the_attempt_count_is_digits_only(line):
    assert m._line(line) is m.Class.OTHER_SUDO


def test_a_wildcard_may_hold_the_text_that_follows_it():
    # The first " may not run sudo on " leaves the account empty; the second one fits.
    line = "Sorry, user  may not run sudo on x may not run sudo on host."
    assert m._line(line) is m.Class.POLICY_REFUSAL


def test_only_a_newline_ends_a_line_of_stderr():
    # A line separator inside a host or account name stays inside its line.
    stderr = "Sorry, user own" + chr(0x2028) + "er may not run sudo on host.\n"
    assert m.classify(stderr) is m.Class.POLICY_REFUSAL
