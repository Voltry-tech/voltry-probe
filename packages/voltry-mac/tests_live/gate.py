"""The live tests' safety gate (docs/VOLTRY_MAC_SPEC.md, Test strategy part 5, "Live macOS
CI"; board items MAC 4.1 and 4.2).

The live tests run the real voltry-mac, and it runs sudo. They run only in a GitHub
Actions job, on a GitHub-hosted runner, that asked for them: GITHUB_ACTIONS is true,
RUNNER_ENVIRONMENT is github-hosted, and VOLTRY_MAC_LIVE, which only the steps of
.github/workflows/voltry-mac.yml that run gated code set, is 1. Anywhere else conftest.py
stops the run with ``Refused`` before any test module is imported, so a mistaken run on a
Mac can neither reach sudo nor look green. The two scripts beside them take the same gate:
sandbox.py, which runs the CLI under the sandbox job's own profile, and capture.py, which
changes the machine it runs on, so it also needs root, through sudo from GitHub's runner
account, and a virtual machine. This module reads nothing at import and needs the standard
library alone: tests/test_live_gate.py imports it on every platform.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Final

# Each variable and the one value that lets the live tests run. GitHub sets the first two
# on its own runners; a self-hosted runner reports RUNNER_ENVIRONMENT=self-hosted.
REQUIRED: Final = (
    ("GITHUB_ACTIONS", "true"),
    ("RUNNER_ENVIRONMENT", "github-hosted"),
    ("VOLTRY_MAC_LIVE", "1"),
)
REFUSAL: Final = (
    "The voltry-mac live tests run the real command through sudo, so they run only in a "
    "GitHub Actions job on a GitHub-hosted runner that asks for them: GITHUB_ACTIONS=true, "
    "RUNNER_ENVIRONMENT=github-hosted and VOLTRY_MAC_LIVE=1. Not set that way here: "
    "{missing}. Nothing was run. The package's own tests are in agents/voltry-mac/tests."
)
# The sandbox job's script (MAC 4.2): the same three conditions, in its own words.
SANDBOX_REFUSAL: Final = (
    "The voltry-mac sandbox run starts the real command under sandbox-exec, so it runs only "
    "in a GitHub Actions job on a GitHub-hosted runner that asks for it: "
    "GITHUB_ACTIONS=true, RUNNER_ENVIRONMENT=github-hosted and VOLTRY_MAC_LIVE=1. Not set "
    "that way here: {missing}. Nothing was run."
)
# The capture (MAC 4.2) changes the machine, so it adds three conditions: it runs as root,
# through sudo from the account GitHub's macOS images run every job as (their READMEs put
# its home at /Users/runner), and on a virtual machine, as those images are. The three
# variables and the account name can be copied onto a developer's own macOS virtual
# machine, but not by accident.
RUNNER_ACCOUNT: Final = "runner"
CHANGE_REFUSAL: Final = (
    "The voltry-mac capture changes the machine it runs on: it installs a sudoers drop-in "
    "and makes test accounts with passwords. So it runs only as root on a GitHub-hosted "
    "virtual machine, in the job that asks for it: GITHUB_ACTIONS=true, "
    "RUNNER_ENVIRONMENT=github-hosted, VOLTRY_MAC_LIVE=1, root through sudo from the runner "
    "account, and a virtual machine. Not so here: {missing}. Nothing was changed."
)


class Refused(Exception):
    """The live tests were asked to run where they may not."""


def missing(environ: Mapping[str, str]) -> list[str]:
    """Each of the three variables that ``environ`` does not set to its value."""
    return [name for name, value in REQUIRED if environ.get(name) != value]


def refusal(environ: Mapping[str, str], text: str = REFUSAL) -> str | None:
    """Why the live tests may not run in ``environ``, naming each variable that is not set
    to its value, or None when all three are. ``text`` is the refusal a script says it in."""
    names = missing(environ)
    return text.format(missing=", ".join(names)) if names else None


def refusal_to_change(
    environ: Mapping[str, str], *, euid: int, virtual: Callable[[], bool]
) -> str | None:
    """Why the capture may not change this machine, naming every condition that fails, or
    None when all six hold. sudo names the account that ran it in SUDO_USER. ``virtual``
    says whether this is a virtual machine; it is asked only once the other five hold, so a
    refused run reads nothing, and one that raises or answers anything but True is a
    refusal."""
    failing = missing(environ)
    if euid != 0:
        failing.append("root")
    if environ.get("SUDO_USER") != RUNNER_ACCOUNT:
        failing.append("sudo from the runner account")
    if not failing:
        try:
            found = virtual() is True
        except Exception:  # noqa: BLE001 - a check that cannot answer refuses
            found = False
        if not found:
            failing.append("a virtual machine")
    return CHANGE_REFUSAL.format(missing=", ".join(failing)) if failing else None
