"""voltry-mac: a point-in-time hardware observation report for Apple silicon Macs.

The spec of record is docs/VOLTRY_MAC_SPEC.md in the Voltry core repository, and the
package's decisions are ADR 0012. The tool reads the Mac as the logged-in user, hands
exactly two fixed read-only payloads to sudo inside a no-write sandbox, makes no network
connection, and keeps no configuration, history, cache or log of its own.
"""

import sys

# The package's first step, before any import that could load a module from its source:
# the tool writes no compiled file. uv installs its Pythons with no compiled standard
# library, so a first run wrote about 40 of them into uv's Python folder, outside the tool's
# own (change record 8; the audit fixes' review, round 3, M1). The tool's own code is
# compiled at install. So this module takes no __future__ import, which would load
# __future__.py first.
sys.dont_write_bytecode = True

__version__ = "0.1.0"
