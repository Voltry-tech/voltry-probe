"""The live macOS tests' setup (docs/VOLTRY_MAC_SPEC.md, Test strategy part 5, "Live macOS
CI"; board item MAC 4.1, issue #323).

The gate comes first. Anywhere but a GitHub Actions job on a GitHub-hosted runner that set
VOLTRY_MAC_LIVE=1 (tests_live/gate.py), this file raises the gate's refusal before it
defines anything, so pytest stops at collection with that message and imports no test
module. It never skips: a mistaken run on a Mac can neither reach sudo nor look green.
Past the gate, tests_live/live.py is registered as ``voltry_mac_live`` (import mode
importlib puts no folder on the import path), and the one real run the checks share is
made once per session.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from types import ModuleType

import pytest

HERE = Path(__file__).resolve().parent


def _load(name: str, file: str) -> ModuleType:
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, HERE / file)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


_gate = _load("voltry_mac_live_gate", "gate.py")
_refused = _gate.refusal(os.environ)
if _refused is not None:
    raise _gate.Refused(_refused)

live = _load("voltry_mac_live", "live.py")


@pytest.fixture(scope="session")
def main_run(tmp_path_factory: pytest.TempPathFactory) -> object:
    """The run the checks share: ``voltry-mac --yes --json --no-open --output <folder>``
    with no terminal, so the elevated path takes S2n to S4n."""
    return live.collect(tmp_path_factory.mktemp("run"))
