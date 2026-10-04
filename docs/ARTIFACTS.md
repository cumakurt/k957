# Platform triage artifacts (0.15.0)

Full mode collects a per-operating-system profile in addition to the live command snapshot. The profiles follow the same targets used by triage collectors: persistence, logs, account names, execution evidence and browser history files. Password hashes and credential stores are left on the machine.

## Collected

Linux adds sudoers, `ld.so.preload`, module and udev rules, init scripts, package metadata (`/var/lib/dpkg/status`, apt/yum/pacman sources) and per-user autostart, systemd user units and recent documents. `/var/log` is still collected as a tree. Live commands add `last`, `w`, systemd timers and package lists (`dpkg`, `rpm`).

Windows adds the SYSTEM, SOFTWARE and DEFAULT registry hives, Amcache, SRUM, setup and Panther logs, per-user `NTUSER.DAT` and `UsrClass.dat`, PowerShell history, Recent and Startup. Prefetch, event logs and scheduled tasks were already collected. SAM, SECURITY and `ntds.dit` are omitted. Live commands add firewall profiles, Winlogon and RunOnceEx, `quser`, and event XML for Sysmon, Defender, Terminal Services, BITS and the firewall. A missing channel is recorded as a snapshot issue. Command text that is not UTF-8 is stored as UTF-8 transcoded from the active Windows code page: `wevtutil` uses the ANSI code page and the other live commands use the OEM code page. The manifest note records that conversion. The stored snapshot is that UTF-8 text, not the original code-page bytes.

macOS adds sudoers, periodic jobs, LaunchAgents and LaunchDaemons, user logs, Safari `History.db`, `knowledgeC.db`, TCC databases and the quarantine events database. Live commands add `kextstat`, system extensions, SIP status, installed packages and a 30-minute `log show` extract. The unified log store under `/var/db/diagnostics` is not copied.

On every platform, Chrome, Chromium, Edge and Firefox history files are collected when the profile directory exists. `Login Data`, `Cookies`, `logins.json` and `key4.db` are not collected.

## Parsed during analysis

| Source | Result |
|---|---|
| Task Scheduler XML, including UTF-16 with a BOM | `scheduled_task` events with user, command and arguments |
| XML/binary launchd plists | `launch_agent` events with label and program arguments |
| systemd units | `systemd_exec` events for `ExecStart`, `ExecStartPre` and `ExecStartPost` |
| Windows Prefetch versions 17, 23, 26 and 30 | executable name from the `SCCA` header |

These rows are on the timeline, in `persistence.csv` and in the HTML report. A command in a file is evidence that the file contained the command. Prefetch is the exception: Windows writes that header after an executable is run. The run count is not reported because its location changes between Windows versions.

## Interpreted activity

`activity.csv` is a second reading of the same collected text and event fields:

- Linux and macOS logs: OpenSSH failures and successes, sudo commands, cron commands, and `useradd` names. The timestamp is kept when it is RFC3339 or the compact form used by `journalctl` and `log show`. A traditional syslog line without a year is still recorded, with an empty absolute time.
- Shell history (bash, zsh, Python) and PowerShell `ConsoleHost_history.txt`: each command is classified as a download, an encoded command, a remote shell, a persistence command, a privilege command, or a plain command. Bash `#unix` lines and zsh `: unix:0;command` prefixes supply the time.
- Windows event XML: logon success and failure (including logon type), explicit credentials, special privileges, process start and exit, service installation, scheduled-task changes, account creation and deletion, group membership, audit-log clearing, PowerShell script blocks, and RDP authentication.
- Prefetch names, scheduled tasks, launchd agents and systemd `ExecStart` lines are repeated here so one table covers execution and persistence.

Activity rows are not findings and are not an identification of a person. The HTML report shows counts; the CSV has every row, up to 10,000.

Literal rules also match `certutil`, `rundll32`, `regsvr32`, `bitsadmin`, `osascript`, `launchctl load`, `schtasks /create` and `wmic process call create`.

## Collected and not fully parsed

Native workers now interpret selected SQLite/WAL Chromium/Firefox/Safari visits, EVTX system/data metadata, clean primary Registry allocated keys/selected values and bounded binary launchd plist fields. Exact record/cell/byte references and original times are retained. See [supported scope and worker limits](EXAMINATION_WORKFLOWS.md). Amcache, SRUM, knowledgeC/TCC, binary journal/unified logs, MFT/USN, transaction replay and compressed Prefetch remain unsupported. Collection alone does not establish interpretation or execution.
