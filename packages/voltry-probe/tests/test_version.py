"""The runtime version equals the installed metadata and the pyproject source of truth."""

from __future__ import annotations

import re
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

import pytest

import voltry_probe

PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def _declared_version() -> str:
    match = re.search(r'^version\s*=\s*"([^"]+)"', PYPROJECT.read_text(encoding="utf-8"), re.M)
    assert match, "pyproject.toml declares no [project] version"
    return match.group(1)


def test_runtime_version_matches_installed_metadata_and_pyproject():
    try:
        installed = version("voltry-probe")
    except PackageNotFoundError:
        pytest.skip("voltry-probe is not installed; running from a bare source checkout")
    assert voltry_probe.__version__ == installed
    assert installed == _declared_version()
