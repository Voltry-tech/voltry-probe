# voltry-mac

A point-in-time hardware observation report for Apple silicon Macs, made on your own Mac.
Point-in-time observations, not a diagnosis, grade or certificate.

voltry-mac is an English-language command-line preview for technically comfortable owners of
Apple silicon Macs.

voltry-mac reads what macOS and the Mac's own parts report about its storage, battery,
memory, power, heat and security settings. It prints a summary in the terminal and saves the
full report as a PDF on your Desktop. Each item says where it came from: measured (a
reading, or a counter the source samples or accumulates), reported (the source's own
statement, such as a percentage, a judgment, or a configuration or design fact) or derived
(computed by voltry-mac from measured or reported values, with the formula shown). Anything
it could not read says so, and why; it is never shown as zero.

## Install

uv installs the tool, and a Python for it, in your home folder:

```bash
# 1. Install uv into your home folder. No administrator access needed.
#    To read the script first: curl -LsSf https://astral.sh/uv/0.12.18/install.sh | less
curl -LsSf https://astral.sh/uv/0.12.18/install.sh | sh
# 2. Put uv on this shell's PATH. New terminal windows get it automatically.
source "$HOME/.local/bin/env"
# 3. Install and run the report.
uv tool install --compile-bytecode voltry-mac
voltry-mac
```

Step 2 matters: the installer cannot change the shell it was started from, so without it
`uv` and `voltry-mac` are found only in new terminal windows. If a new window cannot find
them either, in that window run `source "$HOME/.local/bin/env"`, then
`uv tool update-shell`, which adds uv's folder to your shell's profile for good.

`--compile-bytecode` has uv compile voltry-mac's Python code once, as it installs, rather
than the first time it runs.

Other ways to get uv: `brew install uv`, or the installer's latest version:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

To install this exact release, or to go back to it later:

```bash
uv tool install --compile-bytecode voltry-mac==0.1.0
```

pipx is the second path, for people who already have Python 3.11 or later and pipx:

```bash
pipx install voltry-mac
```

Files installed with uv or pipx carry no quarantine flag, so macOS shows no prompt about
software downloaded from the internet.

## Run it

```text
voltry-mac [--no-root] [--yes] [--output DIR] [--json] [--no-open]
           [--show-serial] [--paper letter|a4] [--debug]
voltry-mac --dry-run           print every command it can run; run none
voltry-mac render REPORT.json  rebuild the PDF from a saved JSON
voltry-mac --version

--yes skips Voltry's own question only. With a terminal, sudo may still ask for
your password; without one, sudo cannot ask.
--yes and --no-root contradict each other and are refused (exit 2).
```

- `--no-root`: skip the two administrator reads. Nothing asks for your password.
- `--yes`: skip Voltry's own question. With a terminal, sudo may still ask for your
  password; without one, sudo cannot ask, so the administrator reads run only if sudo
  needs no password for them.
- `--output DIR`: save in `DIR`, a folder that already exists, instead of the Desktop.
- `--json`: also save the report's JSON beside the PDF.
- `--no-open`: do not open the PDF.
- `--show-serial`: print the full serial number instead of its last four characters.
- `--paper letter|a4`: the PDF's paper size. By default it follows your region.
- `--debug`: print each command's ID, template, exit code and time to stderr, never its
  output.
- `voltry-mac render REPORT.json [--output DIR] [--no-open]`: make the PDF again from a
  saved JSON, saved and opened by the same rules. It collects nothing.

## What it reads, and as whom

Most of the report comes from commands macOS ships, run as you: `system_profiler`, `ioreg`,
`pmset`, `sysctl`, `diskutil`, `csrutil`, `spctl`, `fdesetup`, `memory_pressure` and
`sw_vers`, plus the SSD's own health log, read through IOKit. `voltry-mac --dry-run` prints
every command this version can run, as it runs them, with its two variable arguments shown
as placeholders.

voltry-mac also reads five things in its own process, with no command: how many names in
`/Library/Logs/DiagnosticReports` end in `.panic` (the names are counted, then discarded);
where `/etc/localtime` points, for the time zone's name; your region, from
`~/Library/Preferences/.GlobalPreferences.plist`, for the paper size (Python's reader parses
the whole file, and only that one setting is kept); the processor type, Rosetta state and
macOS release, through `sysctlbyname`; and, once you allow the two administrator reads, the
`_mmaintenanced` account's entry.

Two reads need administrator access, and voltry-mac explains them and asks before either
runs:

1. Count the memory errors macOS has recorded. This runs `/usr/bin/sqlite3` on one Apple
   database, read-only, as macOS's own memory-maintenance account rather than as root,
   inside a sandbox that forbids writing any file.
2. Measure processor power and thermal pressure for 5 seconds. This runs
   `/usr/bin/powermetrics` as root, read-only, inside the same kind of sandbox.

Nothing else runs with administrator access. If you say no, you still get the report, and
those two items say they need administrator access.

sudo's prompt reads "Your Mac password, for the two steps above:". If Touch ID for sudo
is set up in `/etc/pam.d/sudo_local`, the Touch ID sheet appears instead; voltry-mac never
edits that file. If you have never used sudo on this Mac, sudo first shows its own standard
warning, once: a short lecture about using administrator rights carefully. It is sudo's,
and it does not mean anything is wrong.

The two reads change no setting and write no file, and the sandbox makes the second half of
that a rule the kernel enforces. voltry-mac does change one thing: it clears the sudo
authorization remembered for your account (for this terminal, or for every terminal if your
Mac is set up that way) before and after the two reads, so a sudo command you ran a minute
earlier asks for your password again. If that last clear fails, it tells you, and prints the
command to run.

## What it saves

The PDF, named for the time of the report, such as
`Voltry Mac Report 2026-09-23 14.05.pdf`, and with `--json` the report's JSON beside it.
A name already taken gets a number, and the file that had it is left alone. The files are
made readable by you alone (mode 0600); a folder with its own access rules, which is rare,
can extend them to new files there.

If macOS does not let your terminal app use the Desktop, the report goes to the top of your
home folder instead, and the terminal says how to allow the Desktop next time.

voltry-mac makes no network connection, sends no report data over the network, and keeps
no settings, history or log of its own. It creates only the report files you ask for, plus
one temporary file beside them while it writes. A report saved in a synced folder, such as
an iCloud Desktop, syncs the way any file there does. The report keeps the serial number's
last four characters, or all of it with `--show-serial`. It never keeps the Mac's hardware
UUID or UDID, disk serial numbers, or the names of the computer, the host or your account.

## If a run is killed

A run stopped with Ctrl-C cleans up after itself. One killed outright, by a force quit or a
power loss, can leave a `.voltry-mac-<random>.tmp` file beside the report, a JSON without
its PDF, or both; each is safe to delete, and a later run never touches them. The sudo
authorization that voltry-mac clears at the end then lasts until sudo's own timeout, 5
minutes unless your Mac is set otherwise; `sudo -k` clears it at once. A run that cannot
remove a file it made says so and prints its path.

## What it cannot tell you

- Whether the memory has ever had errors. Apple offers no public memory error counter, and
  its private log has unknown retention.
- Its complete prior use. Controller counters give limited device-reported history
  (power-on hours, data written); nothing here shows how it was used, or how long it will
  last.
- Repair history. System Settings, General, About, Parts and Service shows Apple's own view.
- Value or price. Voltry does not assess either.

## Which Macs

Apple silicon Macs (M1 and later) on macOS 15 or later. On an Intel Mac, or on macOS 14 or
earlier, voltry-mac says so and collects nothing.

A validated configuration is one Voltry has checked the whole report on. The report says
whether yours is one. Any other eligible Mac gets a full report with a warning, and anything
that does not answer shows as unavailable.

| Mac | Model identifier | macOS |
| --- | --- | --- |
| MacBook Pro, Apple M5 | Mac17,2 | 26.6.2 |

## Security

- No runtime dependencies: the Python standard library only.
- The commands voltry-mac can run are fixed in the package, and `--dry-run` lists them.
- Releases reach PyPI through trusted publishing, with attestations that make each
  release's origin checkable afterwards; uv and pip do not check them when they install.
- What no tool you install yourself can prevent: software already running as you can change
  voltry-mac on disk, or wrap sudo in your shell, before you type your password.

## Uninstall

```bash
uv tool uninstall voltry-mac
uv cache clean
```

The first removes the tool and its environment; the second clears uv's download cache.
uv's own Python and tool folders are shared with anything else installed through uv, so
they stay; uv's own documentation covers removing uv itself. Installed with pipx,
`pipx uninstall voltry-mac` removes it. After an ordinary run, voltry-mac leaves only the
reports you chose to keep, plus any file it told you it could not remove.

## Reporting a problem

When voltry-mac asks you to report a problem, contact Voltry through
https://www.voltry.io.

For a run, send the message that asked you to report it, and what `voltry-mac --version`
prints. Then run it again with `--debug` added, as in `voltry-mac --debug`, and send the
lines `--debug` adds. Each starts with a command ID, such as C1, and gives the command, how
it ended and its time, never what it read. Leave out the summary.

`voltry-mac render` has no `--debug`. For it, send the message it printed, the command you
ran, and what `voltry-mac --version` prints.

## Related

Looking for Voltry's GPU agent? That is `voltry-probe`.

Apache-2.0. Changes are listed in `CHANGELOG.md`.
