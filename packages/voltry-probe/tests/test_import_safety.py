"""The package root must load no functional, hardware, or network modules.

Runs in a fresh interpreter so the assertion is about a real cold import, not whatever
the test session happens to have loaded already.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

PKG_DIR = Path(__file__).resolve().parent.parent  # packages/voltry-probe

_PROBE = """
import json, sys
import voltry_probe

functional_names = [
    "FunctionalRunner",
    "DrainConsentError",
    "build_functional_bundle",
    "map_functional_results",
]
print(json.dumps({
    "leaked_symbols": [n for n in functional_names if hasattr(voltry_probe, n)],
    "loaded_modules": [
        m for m in ("voltry_probe.functional", "pynvml", "pydcgm", "DcgmReader", "httpx")
        if m in sys.modules
    ],
    "version": voltry_probe.__version__,
}))
"""


def test_root_import_is_inert_in_a_fresh_process():
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(p for p in (str(PKG_DIR), env.get("PYTHONPATH", "")) if p)
    proc = subprocess.run([sys.executable, "-c", _PROBE], capture_output=True, text=True, env=env)
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert data["leaked_symbols"] == [], f"root re-exports functional API: {data}"
    assert data["loaded_modules"] == [], f"root import loaded boundary modules: {data}"
    assert data["version"]
