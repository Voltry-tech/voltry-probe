"""The command manifests: each released version's command templates, by ID, kept forever.

docs/VOLTRY_MAC_SPEC.md, Decision 4's render rules: Appendix B prints each command's fixed
template from the manifest of the version that produced the report, and when that version
is newer than any manifest this package knows, the IDs alone with a note, never a template
from another version. A released version's manifest never changes; an allow-list that
changes ships with a new version and that version's manifest, written out here as a
literal, not built from the allow-list, so no later edit can reach it. A version is matched
exactly, as the tool writes it: another spelling of it under PEP 440 (0.1 or 0.1.0.0 for
0.1.0) gets the IDs alone, as does any version the tool never wrote (1!0.1.0 is a later
one). Until its release tag, the manifest of the version being built is a draft that moves
with the allow-list, so a development build draws a report of that version from the draft.
Pure.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Final

from voltry_mac import __version__, allowlist


def _frozen(templates: Mapping[str, str]) -> Mapping[str, str]:
    return MappingProxyType(dict(templates))


RELEASED: Final[Mapping[str, Mapping[str, str]]] = MappingProxyType(
    {
        "0.1.0": _frozen(
            {
                "C1": "/usr/bin/sw_vers",
                "C2": "/usr/sbin/system_profiler -json SPHardwareDataType",
                "C3": "/usr/sbin/system_profiler -json SPNVMeDataType",
                "C4": "/usr/sbin/system_profiler -json SPDisplaysDataType",
                "C5": "/usr/sbin/system_profiler -json SPMemoryDataType",
                "C6": "/usr/sbin/system_profiler -json SPPowerDataType",
                "C7": "/usr/sbin/ioreg -r -c AppleSmartBattery -a",
                "C8": "/usr/bin/pmset -g therm",
                "C9": "/usr/bin/memory_pressure -Q",
                "C11": "/usr/sbin/diskutil info -plist /",
                "C12": "/usr/bin/csrutil status",
                "C13": "/usr/sbin/spctl --status",
                "C14": "/usr/bin/fdesetup status",
                "C15": "/usr/sbin/sysctl -n hw.model",
                "C16": "/usr/sbin/sysctl -n hw.target",
                "C17": "/usr/sbin/sysctl -n hw.memsize",
                "C18": "/usr/sbin/sysctl -n hw.ncpu",
                "C19": "/usr/sbin/sysctl -n machdep.cpu.brand_string",
                "C20": "/usr/sbin/sysctl -n hw.optional.arm64",
                "C21": "/usr/sbin/sysctl -n hw.nperflevels",
                "C22": "/usr/sbin/sysctl -n hw.perflevel0.name",
                "C23": "/usr/sbin/sysctl -n hw.perflevel0.physicalcpu",
                "C24": "/usr/sbin/sysctl -n hw.perflevel1.name",
                "C25": "/usr/sbin/sysctl -n hw.perflevel1.physicalcpu",
                "C26": "/usr/sbin/sysctl -n kern.hv_vmm_present",
                "C27": "/usr/sbin/sysctl -n kern.boottime",
                "C28": "<the running interpreter> -I -B -m voltry_mac.smart_iokit",
                "X1": (
                    '/usr/bin/sandbox-exec -p "(version 1) (allow default) (deny file-write*) '
                    '(deny network*)" /usr/bin/true'
                ),
                "P1": "/bin/ps -axo pid,ppid,uid,lstart,comm",
                "O1": "/usr/bin/open <the exact path just published>",
                "S1": "/usr/bin/sudo -k",
                "S2": '/usr/bin/sudo -v -p "Your Mac password, for the two steps above: "',
                "S3": (
                    '/usr/bin/sudo -u _mmaintenanced -H -p "Your Mac password, for the two '
                    'steps above: " -- /usr/bin/sandbox-exec -p "(version 1) (allow default) '
                    '(deny file-write*) (deny network*)" /usr/bin/sqlite3 -init /dev/null '
                    "-safe -nofollow -readonly -json -bail "
                    '"file:/private/var/db/mmaintenanced/memory_errors.db?readonly_shm=1" '
                    '"PRAGMA query_only=ON; PRAGMA temp_store=MEMORY; WITH '
                    "classes(correctable,label) AS "
                    "(VALUES(1,'correctable'),(0,'uncorrectable')) SELECT c.label AS class, "
                    "COUNT(e.ID) AS event_rows, COALESCE(SUM(e.count),0) AS reported_count "
                    "FROM classes c LEFT JOIN ecc_errors_v2 e ON e.correctable=c.correctable "
                    'GROUP BY c.correctable,c.label ORDER BY c.correctable DESC;"'
                ),
                "S4": (
                    '/usr/bin/sudo -H -p "Your Mac password, for the two steps above: " -- '
                    '/usr/bin/sandbox-exec -p "(version 1) (allow default) (deny file-write*) '
                    '(deny network*)" /usr/bin/powermetrics -n 5 -i 1000 --samplers '
                    "cpu_power,gpu_power,thermal --format plist"
                ),
                "S5": "/usr/bin/sudo -k",
                "S2n": "/usr/bin/sudo -v -n",
                "S3n": (
                    "/usr/bin/sudo -u _mmaintenanced -H -n -- /usr/bin/sandbox-exec -p "
                    '"(version 1) (allow default) (deny file-write*) (deny network*)" '
                    "/usr/bin/sqlite3 -init /dev/null -safe -nofollow -readonly -json -bail "
                    '"file:/private/var/db/mmaintenanced/memory_errors.db?readonly_shm=1" '
                    '"PRAGMA query_only=ON; PRAGMA temp_store=MEMORY; WITH '
                    "classes(correctable,label) AS "
                    "(VALUES(1,'correctable'),(0,'uncorrectable')) SELECT c.label AS class, "
                    "COUNT(e.ID) AS event_rows, COALESCE(SUM(e.count),0) AS reported_count "
                    "FROM classes c LEFT JOIN ecc_errors_v2 e ON e.correctable=c.correctable "
                    'GROUP BY c.correctable,c.label ORDER BY c.correctable DESC;"'
                ),
                "S4n": (
                    '/usr/bin/sudo -H -n -- /usr/bin/sandbox-exec -p "(version 1) (allow '
                    'default) (deny file-write*) (deny network*)" /usr/bin/powermetrics -n 5 '
                    "-i 1000 --samplers cpu_power,gpu_power,thermal --format plist"
                ),
            }
        ),
    }
)


def templates(version: str) -> Mapping[str, str] | None:
    """The templates the version that produced a report ran, by command ID: this
    package's own allow-list for its own version, a released version's manifest for that
    version exactly, and None for any other."""
    if version == __version__:
        return _frozen(
            {command.id: allowlist.display(command.template) for command in allowlist.COMMANDS}
        )
    return RELEASED.get(version)
