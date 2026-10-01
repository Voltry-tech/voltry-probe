# Changelog

All notable changes to `voltry-mac` are documented here, newest first, one dated entry per
release under a heading of the form `## [X.Y.Z] - YYYY-MM-DD`. The release tests read these
headings: every release listed keeps its command manifest and its pin. The empty stub that
reserves the name on PyPI is not built from this package and has no entry here.

## [Unreleased]

## [0.1.0] - 2026-09-29

The first release, published to TestPyPI for validation. voltry-mac reads an Apple silicon
Mac's hardware as the logged-in user, with two optional administrator reads that run
inside a sandbox, and writes a point-in-time report: a terminal summary, a PDF and, when
asked, a JSON. It reads system information without changing system settings, creates only
the report files you ask for, plus one temporary file while it writes, names any file of its
own the file system will not let it remove, and makes no network connection. It does change
one thing: it clears the sudo authorization remembered for your account before and after
the two administrator reads. `voltry-mac render` rebuilds the PDF from a saved JSON.

Validated on one configuration: a MacBook Pro with Apple M5 (Mac17,2) on macOS 26.6.2. Any
other Apple silicon Mac on macOS 15 or later gets a full report with a warning.

macOS 27, recorded by the owner on 2026-09-29 as the dated exception the spec's
Acceptance criteria allow while GitHub's macOS 27 image is in preview: on that image the
memory error store's folder is empty, so the memory error log read ends unavailable as a
tool error, as Failure modes says for a store sqlite3 cannot open, and the live and
capture jobs' seven checks of that read fail there. Every other check passes on macOS 27.
This release is not validated on macOS 27.

What was built, item by item:

- The package skeleton: the `voltry-mac` command with `--version` and `--dry-run`, every
  flag the spec names, the refusal of `--yes` together with `--no-root` (exit 2), and the
  frozen allow-list of 38 command templates and five in-process reads, with its static
  guards.
- The forbidden-shape scan is closed: every program and its arguments must be one of the
  forms in the scan's own tables, which keep their own copy of every string they check,
  so an edit to the list is caught unless it is made to the scan too. Behind the copies,
  rules check properties the spec names: the sandbox profile uses only its own seven
  words and ends by denying file writes and the network, sqlite3 reads one file read-only
  and never immutable, powermetrics takes only its four options, none twice, writes no
  file and uses only its three samplers, and sysctl reads only plain dotted names, never
  the host name; `sysctl -n` takes only its thirteen names. Shells, launchers,
  interpreters and the named tools are recognized by case-folded name, and sudo's options
  in getopt bundles and prefixes.
  Nothing can name an interpreter for the SMART child but `sys.executable`. `--version`
  also names the Python; `--help` shows the spec's usage block; `--yes` with `--no-root`
  is refused even beside `--version` or `--dry-run`; a closed pipe ends `--dry-run`,
  `--version` and `--help` quietly.
- The preflight, before any read and before an argument error: the root user refused
  (exit 5), then a platform the spec does not cover (exit 3): not macOS, an Intel Mac,
  macOS 14 or older, or a processor type, Rosetta state or macOS release that cannot be
  read; nothing collected or written either way. `render` takes it too; only `--version`
  and `--dry-run` skip it. The processor type, Rosetta and the Darwin release are read
  in-process through sysctlbyname (R4, with change record 2), with ctypes loaded only
  then and without its call to uname, so the preflight never reads the host name. The
  admin check (group ID 80 among the process's groups, no name read, bounded to 5 s) and
  the terminal check are ready for the elevation. `--version` names the interpreter's
  architecture and whether Python runs under Rosetta. A refusal with stderr closed, or
  read by a reader that went away, keeps its exit code and leaves stdout empty.
- The spawn chokepoint, the only module that starts a process: the allow-list checked
  (exact match and forbidden shapes) before anything starts, no shell, a fixed
  two-variable environment, stdin from /dev/null, both streams drained with 4 MiB caps,
  per-command deadlines with the spec's stop sequences, a cancellation check on every
  pass, the child stopped if anything raises mid-run, and one record per command ID
  (runs, failed runs, total duration). The open (O1) takes no path from its caller: it
  opens only the one report the output writer published, once, and leaves no record.
- Numbers as text: source values read from their decimal text into `decimal`, never
  through a float; one canonical spelling for every decimal in the JSON; values Voltry
  computes rounded half up to two places; the 64-bit and 128-bit bounds.
- The canonical JSON form and the report ID (the SHA-256 of that form without the ID),
  and the strict reader `render` will use: a 4 MiB cap, no duplicate keys, floats or
  constants, nesting at most 32 deep, no integer of more than 19 digits, no key over 64
  characters, no control (DEL included), separator, bidirectional or lone surrogate
  character, and failures named by an ASCII field path, never by the value.
- The surface registry, carried verbatim from the spec: the 23 surfaces with their
  interface, privilege, temporal class and value keys (shape, provenance, and the two
  optional keys), each surface's availability domain, the reason codes and the elevated
  details, every numeric key's range, and the storage grammars.
- The validator `render` will use: every shape, availability domain, value reason and
  range in the schema; the registry's relations and the computed-values rule; the storage
  chain and the SMART child's outcome table; each user command against the surfaces it
  feeds; the collection block and the save gate; the elevation record's eight rules, the
  command records it implies and the two elevated surfaces' reasons and details; and a
  report ID that must recompute. A refusal names the field path in ASCII, never the
  value.
- Parsers for the 26 user reads, each reading only the fields the report keeps, by
  name: a field the source omitted or garbled is unread (source_changed), output in
  another shape is refused as a changed source, and the battery reads are not
  applicable on a Mac without a battery. Numbers are read from their text, never
  through a float.
- The SMART child (C28): it lists up to 8 NVMe controllers and their whole disks, reads
  each one's SMART log once through IOKit, closes the SMART client at once, and prints
  one small JSON document; only the read and the calls that obtain and give back its
  interface are callable, never the identify call that carries the drive's serial. The log is decoded by a table pinned to the SDK header.
- The storage identity chain: the startup volume's one physical store and its whole
  disk, then exactly one NVMe entry and exactly one SMART record by that name, so every
  storage fact in a report comes from one device. A failure closes only its own branch,
  by the spec's dependency table, and the SMART child's output is checked against its
  contract and mapped through its 12-row outcome table before anything is decoded.
- The report model: every value with its availability and, when read, the provenance the
  registry gives it; the values Voltry computes (degrees, dates, byte totals, the
  performance levels, the power ranges and averages, the thermal counts) available
  exactly when their inputs are; a surface whose values all failed made unavailable with
  its first value's reason, and a payload's output of which no value survives its range
  left to the broker as unparsed; a value of another shape than the registry's refused
  as a bug; the collection status, the save gate and the exit code, the
  first of 5, 3, 2, 130, 4, 6, 1, 0 that applies; and the fixed notes the terminal and
  the PDF print word for word.
- The elevation broker, up to the payloads' tracking: the question asked only when a yes
  is possible, `--yes` with the `-n` forms when there is no terminal, and the record of
  which; the service account looked up in-process within 5 s, the sandbox probe and the
  listing, each before any sudo call; sudo -k, the one prompt, the count and the power
  sample, each only when the steps before it allow it; the final sudo -k whenever the
  first was attempted, a cancellation included, before any output is parsed, and never
  cut short by Ctrl-C. sudo's messages are classified by its fifteen pinned templates,
  anchored at both ends; the two payloads' outputs are read as text (the power plist with
  the XML parser, never plistlib), and the outcome tables and the skip rule give each
  elevated surface its reason.
- The payloads' tracking: while the count or the power sample runs, the process listing
  every 200 ms records the spawned sudo with every identity it takes and what it starts
  down to three levels; three clocks in turn (the prompt, the payload's launch, its run)
  and the output cap stop it with SIGTERM, then SIGKILL; a process the tool cannot
  signal is left named, not claimed gone; and one listing after each payload decides
  whether every recorded process has ended. A survivor is named with the four fields to
  check before stopping it, and a name outside the four the subtree can hold prints as
  an unexpected process. Each listing closes its pipes once read; an interruption or an
  error inside the tracking still stops the payload and takes the final listing; after
  EPERM the spawned process is found by its ID alone, and a zombie counts as ended.
- The SMART child imports ctypes with os.uname set aside, so it never reads the host name.
- The terminal summary: the report at 80 columns in the layout transcript 1 shows, a pure
  function of the report JSON, with the words for every unavailable item and elevated
  stop, the rounding and units of Decision 6, and the display path that escapes control,
  bidirectional and blank characters and shows the home folder as `~`.
- The PDF writer: PDF 1.4 from the standard library, with the standard Helvetica,
  Helvetica-Bold and Courier fonts and nothing embedded, WinAnsi text measured with
  Adobe's published widths (a character outside WinAnsi prints as "?" and is counted),
  and the same pages giving the same bytes.
- The PDF's page layout: 18 mm margins, the spec's type and colors, word wrap by the AFM
  widths, key-value rows with label chips, tables that repeat their header rows, a heading
  never left at a page's end, one bar chart, and a running header and footer with page X
  of Y.
- The PDF's pages: the title block, At a glance and the limits on page 1; the detail
  sections on pages 2 and 3 with their notes; the power and thermal check on page 4 with
  its five samples and bar chart; and the two appendices, everything tried and how the
  report was made. The words are the terminal's, with the rows the PDF alone prints; each
  value shows its provenance chip, or an availability chip when it is unavailable or not
  applicable. Appendix B links the source and the PyPI page of the exact version and says
  what a run changes: the sudo authorization, cleared before and after the administrator
  reads, or nothing when the reads were declined or skipped. The pages are not compressed,
  so a report drawn by the version that made it is the same bytes everywhere, and one
  drawn by another version names both in Appendix B; three golden PDFs are pinned by their
  SHA-256 and their pages by reference images.
- `render` rebuilds the PDF from a saved JSON, collecting nothing: it reads the file
  strictly, validates it and its report ID before anything else, and prints each command's
  template from the manifest of the version that made the report, or the IDs alone with a
  note; a report another version made is drawn with both versions named. Each released
  version's command manifest is kept in the package, unchanged.
- The output writer: the report is saved on the Desktop, or in a folder you name (which
  must exist), as `Voltry Mac Report <date> <time>.pdf`, with the JSON beside it when
  asked for, one file at a time, each published atomically at mode 0600, never
  overwriting a file (a taken name gets a number, up to 99) and never following a
  symlink at a name it makes; when macOS refuses the Desktop the report goes to the top
  of your home folder instead. A failure, or a cancellation through the run's flag, even
  one that comes as the PDF is linked, removes what the run made, newest first, and a
  cancellation that meets a failure is still a cancellation. Each file is held open until
  the save ends, so no other file can take its number, and a name is removed only while
  it still leads to that file; a name the run's link made for another file that took the
  temporary's place is removed while the temporary's name still leads to that same file.
  Each check comes just before its unlink, so a process that swaps its own file in
  between the two calls can lose it. A temporary file that cannot be removed stops the
  save before another is made, so there is never a second one. A disk with no hard links
  (FAT, exFAT) cannot take the report, and nothing is left on it. A file the run cannot
  remove is named, and safe to delete. A hard kill leaves at most one temporary file and
  a JSON without its PDF, both safe to delete, as is a file an earlier refused removal
  left (change record 21).
- The reads voltry-mac makes in its own process, with no command: the count of kernel
  panic reports (administrators only; a standard account gets no_admin, and the file
  names are counted and discarded), the time zone from where /etc/localtime points, or
  unknown, and the paper from the region of your locale, US Letter for the US and Canada
  and A4 otherwise.
- The run: `voltry-mac` reads this Mac as you on one timed line, then, when the
  administrator reads apply, explains them in Voltry's words and asks, when stdin and
  stdout are both a terminal. Only an answer typed after the question counts: what was
  typed before it, or arrives just as it prints, is dropped. `--yes` skips only the
  question, so sudo still asks for your password wherever stdin is a terminal. Each
  payload prints a line, and the sudo authorization is cleared after them, with a warning
  and exit 6 if that fails. The terminal summary follows; the PDF, and the JSON with
  `--json`, are saved on the Desktop or in the folder you name, and the PDF opens once
  unless `--no-open` or over SSH. Ctrl-C, SIGTERM or SIGHUP stops the run (exit 130).
  Before the save nothing is saved; after it the report stays and is not opened. A stop
  comes before every other failure of the run. A report too thin to save, one that cannot
  be saved and one the PDF writer cannot draw exit 4; so does a bug, or 1 once the report
  is saved. Output to a closed terminal or to a reader that went away is dropped quietly;
  a terminal report that cannot be written in full for another reason, a full disk behind
  it say, is named on stderr. The collection time follows /etc/localtime, the zone the
  report names, whatever `$TZ` says, and `--debug` prints each command's ID, template,
  ending and time to stderr, never its output.
- `voltry-mac render REPORT.json` draws a saved report's PDF again and collects nothing:
  it reads the file with the 4 MiB cap, reading at most one byte past it and only from a
  regular file; refuses a file it cannot read or render with exit 2, naming the field and
  never the value; says in one line when another version or another renderer made the
  report; and saves and opens the PDF by the live run's rules, in its own words. Ctrl-C
  stops it, during a read that stalls too (exit 130), and comes before every other
  failure. A bug is named by a fixed line and exits 4, or 1 once the PDF is saved.
- The copy pass: every message the command prints around the report is golden text, its
  spaces and line breaks included, down to where each stream ends, and so is every word
  no scenario prints whole (render's problems, the output writer's reasons, the command
  line's help and refusal), held to the copy rules with the dry run, the usage, the
  README and every fixture's JSON, terminal summary and PDF. Messages wrap at 80 columns,
  as the summary does, and `--help` and the usage block a usage error prints fit too: its
  `--dry-run` line says "print every command it can run; run none" (change record 24). A
  path, and the survivor note's two commands, stand on a line of their own and are never
  wrapped, so they copy whole, and the words before each command have a line to
  themselves. A refusal names its folder or file on such a line. render's refusal says
  the field below is wrong and why, then names that field on such a line too, the top
  level included. The dry run's prose wraps as well. When the Desktop is refused and the
  home folder fails too, the message says so, and `--debug` says in words how a command
  or a payload ended, such as that it ran past its deadline or went over the output cap.
  The README says the release is a preview and gives the uv install the spec gives, with
  pipx as the second path; what the tool reads and as whom (the five reads it makes
  itself included), what it changes and saves, what a killed run can leave, what it
  cannot tell you, the validated configurations, security notes, the uninstall, and where
  to report a problem and what to send.
- The owner's change records 5 to 11 on the spec. A process from the administrator reads
  that is still running is named as a survivor, even when it now runs under another name
  or user, as one that started the payload after the last listing does; the run used to
  say it had ended. A report whose time zone is not a time zone's name, a file path say,
  is refused. The SMART child runs with `-B`, so it writes no compiled Python files, and
  the README installs with `uv tool install --compile-bytecode voltry-mac`, so a run has
  none left to write. A Mac with Gatekeeper off now reports it off: `spctl --status` exits
  1 then, which left Gatekeeper unread as a tool error and made the run exit 1.
- The GPT audit's first pass: a command starts only if its last check finds the run not
  cancelled. So after Ctrl-C the only commands that start are its cleanup, the final
  `sudo -k` and the process listings that stop a payload the flag cut short (one already
  due when the flag is set, and the last one, after the stop), and one whose last check
  came in the instant, under about a millisecond, before the Ctrl-C, which the first pass
  that watches it stops. A password prompt or a read can no longer start after Ctrl-C and
  run to its deadline. A stop just before the open says the report is saved and was not
  opened, and one that cuts the open short says it may not have opened; a payload the
  stop keeps from starting prints no line. A parser refuses a line, a record, a key or a
  store its source gives twice, rather than keep the first or the last, even when the
  first is garbled, and the paper's read of the preferences file treats a key given twice
  as a file it cannot read. With the drive entry unread, This Mac says the startup disk's
  name was not read instead of printing a name derived from the startup volume.
- The privacy canaries: made-up serials, UUIDs, volume, display, app, panic file and
  process names, boot arguments and text replacements, and an account and a host name in
  every path and every sudo message, are planted in fake runs of the normal path, of
  failures and bugs from the reads to the save, of Ctrl-C from the reads to the open, and
  of render. None reaches the terminal, `--debug`, an error message, the PDF or the JSON,
  even wrapped across two lines. Paths under the home folder print as `~`, a surviving
  process outside the four subtree names prints as an unexpected process, and the serial
  shows only its last four characters unless `--show-serial` is given.
- A path the tool prints shows the home folder as `~` wherever the file system finds it
  in the path, by its device and inode number: typed in another case or form, reached
  through a symlink, `/private` or `/System/Volumes/Data`, or written with `//` or a
  trailing `/.` in the account database. A folder the volume keeps apart from it, such as
  a name in another case on a case-sensitive volume, prints in full. To find it, the tool
  looks up only the home folder and the folders along the path; it reads no file and
  lists no folder.
- A report prints the same on every supported Python: what a character is (its kind, its
  width in the terminal, whether a unit stays with the number before it, and what it
  composes to in the PDF) comes from a table of Unicode 15.0.0 in the package, not from
  the running Python's own, which is older on 3.11 and newer on 3.14. The PDF prints every
  character outside its character set as "?" and counts it in Appendix B, a zero width
  space or a soft hyphen included, where it used to drop some without a count; the
  terminal still leaves them out. Both renderers compare the two memory sizes and read the
  SMART status as the terminal prints them, so they choose the same words there.
- CI: `.github/workflows/voltry-mac.yml` runs the package's own tests on Linux on Python
  3.11 and the newest CPython uv knows, and on macOS 15 on 3.11; and the live tests in
  `tests_live/` on GitHub's macOS 15, 26 and 27 preview runners, on 3.11 and on uv's own
  Python: the installed command through the runner's passwordless sudo, with the exact
  production S3 and S4, and the ledger fixtures, stores of their own read with S3's
  flags in and out of the sandbox profile. The test tools are at uv.lock's versions, and
  both runs read pytest's settings from this package's pyproject.toml alone. It runs for
  pull requests that touch the package and for its release tags, and the live tests
  refuse to run anywhere else.
- Two release prerequisites in CI, on the same three macOS images. The sandbox job runs
  the command with `--no-root` under a `sandbox-exec` profile of its own (no network, no
  program off the allow-list, no write outside the output folder), on 3.11 and on uv's own
  Python, and needs the whole report to come out: a JSON the package's validator takes, a
  PDF that `render` rebuilds byte for byte under the same profile, and the same commands
  failed as without it; an image without `sandbox-exec` fails the job. The capture job, as
  root on the throwaway runner, holds sudo's real messages to the pinned templates with
  disposable test accounts and drop-ins, expecting what the image's own sudo version
  prints, and checks direct execution, the slow prompt and the stop that meets `EPERM`. On
  stock macOS, where no account-state line can print, it holds what sudo does instead to
  what the spec says macOS does; a power sample that ends right after `EPERM`, before the
  last listing, passes with its cleanup verified and the reason in the log. A template the
  image cannot print is held, with its `sudo: ` prefix, to sudo's own source by the
  package's tests. Both scripts refuse to run anywhere else.
- The second pass of the GPT audit. A command line the tool cannot take is refused in its
  own words, the same on every Python it supports, after the usage it belongs to; an
  argument it names prints as a path does, the home folder as `~` and a control or
  bidirectional character escaped. argparse's own lines, which echoed what was typed as it
  was, no longer print, and an option must be spelled in full. A signal once the report is
  saved now stops the run until the run's last look at the flag: while the report opens,
  after it has opened, with `--no-open` or over SSH, and when the open fails or cannot
  start, as a Ctrl-C in the terminal makes it fail. The run exits 130 and says the report
  is saved and whether it may have opened; `render` does the same in its own words. The
  memory error read never runs as root: a service account with user ID 0, a negative one,
  or one of 2^31 or more is a lookup that failed, so the count is skipped as a tool error
  and the power sample still runs. When the home folder cannot be looked up, a path prints
  with `~` only where it spells the home folder exactly, so a folder named in another case
  on a case-sensitive volume prints in full. A terminal report cut short because stdout
  fails as it is written, as with `python -u` or PYTHONUNBUFFERED on a full disk, is said
  once on stderr, as one that fails when flushed is, and a stdout that takes only part of
  a write, or none while it would block, is given the rest. A file the file system will
  not let a run remove never stops a report that can still be saved: the run names it as
  safe to delete, and when it is the PDF's temporary, which leaves the PDF with a second
  name, the PDF is not opened and the run says why.
- Before the GPT audit's third pass, from our own reviews: a run writes no compiled Python
  file, not even of Python's own library, which uv's Pythons ship uncompiled. From the
  first line to the exit, Ctrl-C, SIGTERM and SIGHUP only ask the tool to stop, so none
  prints a traceback or ends it abruptly, and a stop after the report could not be saved
  says so and exits 130. The command line reads the same way, in the same words, on
  Python 3.11 to 3.14: `--` and a word that starts with a dash and a digit are refused, a
  folder typed after `=` shows the home folder as `~`, `--help` is never colored and
  takes the same checks as a run (exit 5 as root, 3 on a Mac the tool does not support),
  and an empty argument is named in words. A terminal that cannot print a character, an
  ASCII one say, gets a `?` for it and one line saying the terminal report is incomplete;
  the report is still saved. At a glance no longer puts the word "errors" after the log's
  own counts when its records were not read, and a sysctl value is judged printable by
  the tool's own character table.
- The GPT audit's third pass: the run's last read of the stop flag is now its last step,
  after the warning it repeats and after collecting the payloads it could not signal, so
  a signal during either stops the run (exit 130). A stream that takes nothing, a pipe
  whose reader never reads say, no longer holds a stop: the console reads the flag while
  it waits and gives the rest up once the tool is asked to stop. Appendix B states the
  guarantee beside each payload's cleanup: what verified covers, and what a survivor or a
  failed listing leaves unclaimed. `--help`, the usage block and the README say that with
  `--yes` and no terminal, sudo cannot ask for a password (change record 26), and the
  spec says Python itself may cache its own standard library as it starts, in its own
  folder, while the tool's own code writes no compiled file (change record 25).
- From the first live run on GitHub's macOS runners: the process listing reads a name ps
  prints in parentheses, as it prints a process that is starting or ending, as that name,
  so a power sample caught ending on its own is named in the survivor note rather than
  called an unexpected process. The live checks read powermetrics' arguments as it leaves
  them once it has cut its sampler list, and look for sudo's prompt apart from the
  `--debug` lines that print it; the sandbox job's profile allows the file python.org's
  Python for macOS becomes as it starts; the capture lists back to back while it waits to
  see the count; and a count that does not parse on a runner prints why, in the words of
  sudo, sandbox-exec and sqlite3.
- The GPT audit's fourth pass: a stop now ends the command while its output takes nothing
  on a normal, blocking pipe or terminal too, where a write used to wait inside the system
  call: each write and flush is non-blocking while it lasts, and the stream is handed back
  as it came. And Appendix B's guarantee speaks for its own step alone, with a survivor
  named only where it was, in the terminal output, since the saved report keeps no
  process's identity.
- The GPT audit's fifth pass: these release notes claimed more than the tool controls, in
  words the Product contract replaces. They now say what it controls, in the contract's
  words, and that it clears the remembered sudo authorization around the administrator
  reads; and the copy tests hold the README, these notes and every printed string to the
  contract, so none makes a claim it replaced.
