[![documentation](https://img.shields.io/badge/documentation-read-brightgreen)](#contents)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Stars](https://img.shields.io/github/stars/D4Rk-Nu11/fimeyfim?style=social)](https://github.com/D4Rk-Nu11/fimeyfim/stargazers)
[![release](https://img.shields.io/github/v/release/D4Rk-Nu11/fimeyfim?color=orange)](https://github.com/D4Rk-Nu11/fimeyfim/releases)
[![platform](https://img.shields.io/badge/platform-Linux-lightgrey)](#requirements)
[![language](https://img.shields.io/badge/language-Rust-orange)](https://www.rust-lang.org)
[![issues](https://img.shields.io/github/issues/D4Rk-Nu11/fimeyfim?color=yellow)](https://github.com/D4Rk-Nu11/fimeyfim/issues)

# FIMEY-FIM

**FIMEY-FIM is a lightweight File Integrity Monitor (FIM) for Linux, with a built-in forensic "Tampered File Copy" (TFC).**

You tell it which confidential files and folders matter. From then on it watches them in the background, around the clock. The moment someone opens one of them for writing, or changes it, FIMEY-FIM raises an alert on your screen and in your desktop, writes a tamper-evident record, and **saves the original, untouched file** to a separate location so you can recover it and investigate what happened.

It is written in Rust, ships as a single small binary, uses almost no memory while idle, and is built for small teams and labs that want real file-tampering detection without running a heavy security platform.

---

## Contents
1. [Why FIMEY-FIM](#why-fimey-fim)
2. [What you get](#what-you-get)
3. [How it works](#how-it-works)
4. [Requirements](#requirements)
5. [Installation](#installation)
6. [First-time setup (step by step)](#first-time-setup-step-by-step)
7. [Using the console](#using-the-console)
8. [Alerts](#alerts)
9. [Tampered File Copy (TFC)](#tampered-file-copy-tfc)
10. [Background service, boot and stop/start](#background-service-boot-and-stopstart)
11. [Update, disconnect, uninstall and reinstall](#update-disconnect-uninstall-and-reinstall)
12. [Where things live](#where-things-live)
13. [Troubleshooting](#troubleshooting)
14. [Limitations (please read)](#limitations-please-read)
15. [Contributing and license](#contributing-and-license)

---

## Why FIMEY-FIM
Files with read-only permissions are not safe from someone who has enough privileges. If a configuration file, a credentials file or a case document is quietly changed, most systems will not tell you, and the original is gone.

FIMEY-FIM answers three questions the moment something happens:

- **What changed?** The file, with its SHA-256 hash *before* and *after*.
- **Who touched it?** The process that opened or wrote it, where the kernel allows it to be identified.
- **Can I get the original back?** Yes. An exact, hash-verified copy is waiting in your TFC folder.

## What you get
- **SHA-256 integrity monitoring** of single files or whole directories.
- **Two clear alert types**
  - `FILE OPEN IN WRITE MODE` - a program opened the file for writing, replaced it, or a text editor (Mousepad, gedit, nano, vim, Kate and others) opened it.
  - `FILE MODIFICATION` - the file's hash no longer matches its baseline.
- **Tampered File Copy** - the original is preserved as `<name>_tfc_copy.<ext>`, sorted into a folder per extension, and its hash is verified.
- **Alerts where you will see them** - printed in the console, broadcast to open terminals, and shown as a desktop popup, even after you close the tool.
- **An interactive console** with colour, a live status banner, an alert viewer with **Active** and **Closed** tabs, auto-refresh, and an audit table of closed alerts.
- **Runs in the background and starts at boot** (systemd). Closing the console never stops monitoring.
- **No separate tool password.** Important actions ask for your normal system password, the same one `sudo` uses.
- **Fresh-install guarantee.** Delete and reinstall the tool and it starts unconfigured, so nothing is ever set up behind your back.
- **Light on resources.** The monitor sleeps until the kernel wakes it up. The service is capped at 32 MB of memory.

## How it works
```
 you add a file                       something touches the file
       |                                         |
       v                                         v
 SHA-256 baseline  +  exact copy        kernel tells FIMEY-FIM (inotify / fanotify)
 saved in a root-only vault                      |
       |                                         v
       |                          hash compared with the baseline
       |                                         |
       +------------- original ------------>  ALERT  ----> console + popup + log
              copied from the vault             |
                                                v
                                   TFC: <tfc>/<ext>/<name>_tfc_copy.<ext>
                                        (hash verified against the baseline)
```
1. **Baseline.** `fim add` hashes the file and stores an exact copy in a vault only root can read.
2. **Watching.** The background service listens to kernel file events. It also re-checks every protected file at startup and every two minutes, so nothing slips through if an event is missed.
3. **Alert and preserve.** On an alert, the clean original is copied from the vault into your TFC folder and its hash is checked against the baseline. That is why the preserved copy is always the real original, even if the attacker is still halfway through writing.

## Requirements
| | |
|---|---|
| OS | Linux with systemd (tested on Kali; should work on Debian/Ubuntu-family systems) |
| Privileges | `sudo` / root (the tool elevates itself and asks for your password) |
| Libraries | `libpam0g` (already present on most systems) |
| Optional | `libnotify-bin` for desktop popups: `sudo apt install libnotify-bin` |
| To build | Rust (`cargo`) - not needed if you use the prebuilt binary |

## Installation
### Option 1 - prebuilt binary (no Rust needed)
Download `fimeyfim-linux-x86_64` and its `.sha256` file from the project's **Releases** page, then:
```bash
sha256sum -c fimeyfim-linux-x86_64.sha256
chmod +x fimeyfim-linux-x86_64
sudo install -m 0755 fimeyfim-linux-x86_64 /usr/local/bin/fimeyfim
sudo fimeyfim
```

### Option 2 - build from source
```bash
git clone https://github.com/<your-user>/fimeyfim.git
cd fimeyfim
./install.sh
sudo fimeyfim
```
`install.sh` builds the program and installs it to `/usr/local/bin/fimeyfim`.

> **Every `./install.sh` is a fresh install.** Anything left by an older install is archived and the tool starts unconfigured, so you set it up yourself. To update and keep your records, use `./install.sh --upgrade` (see [Update](#update-disconnect-uninstall-and-reinstall)).

> **"Rust (cargo) was not found"?** Run `sudo apt install -y cargo` (Kali/Debian/Ubuntu) or `curl --proto '=https' -sSf https://sh.rustup.rs | sh`, then `./install.sh` again. The installer also finds Rust in your normal user's `~/.cargo` when you run it as root.

## First-time setup (step by step)
Start the tool. It asks for your system password once, to get administrator rights:
```bash
sudo fimeyfim
```
You land in the console. A new install shows that nothing is configured. Do these three things, in this order:

```
fimey > fim init
[+] Initialized. Monitor: RUNNING. Auto-start at boot: enabled.

fimey > fim add -tfc /secure/tfc
Password:
[+] TFC directory set: /secure/tfc

fimey > fim add -a /etc/secret.conf
[+] Protected: /etc/secret.conf

fimey > fim add -all /srv/confidential
[+] Added 12 file(s), 0 already protected, 0 error(s).
```
1. **`fim init`** installs the background service and starts monitoring.
2. **`fim add -tfc <dir>`** sets where preserved originals go. **This is required before you can protect any file.** Pick a folder on separate or append-only storage, not inside anything you protect.
3. **`fim add -a <file>`** or **`fim add -all <dir>`** puts files under protection.

Check everything with `fim status`. You can now type `exit`; monitoring continues in the background.

## Using the console
The console works like a small shell. Type `help` at any time.

### FIM commands
| Command | What it does |
|---|---|
| `fim init` | Install the service, start monitoring, enable start at boot |
| `fim add -a <file>` | Protect one file |
| `fim add -all <dir>` | Protect every file in a directory, including sub-folders |
| `fim remove -r <file>` (or `fim release <file>`) | Release a file from protection - *asks for your system password* |
| `fim remove -all <dir>` | Release a whole directory - *password* |
| `fim add -tfc <dir>` | Set the TFC directory - *password* |
| `fim change -tfc -s <old> -d <new>` | Move the TFC directory and its contents - *password* |
| `fim inspect all` | Table of every protected file with its baseline hash |
| `fim status` | Monitor state, boot setting, TFC, counts, and any file that is not OK |
| `fim verify` | Run an integrity check right now |
| `fim start` / `fim stop` | Start or stop the monitor (`stop` asks for your password) |
| `fim -x init` | Disconnect: stop monitoring but **keep** all records |
| `fim uninstall` | Remove the tool; a later install starts from scratch - *password* |
| `fim notify-test` | Send a test popup to check that alerts reach your desktop |

### Console commands
| Command | What it does |
|---|---|
| `alerts` | Open the alert viewer |
| `audit` | Table of closed alerts (the audit ledger) |
| `monitor` | Live feed of new alerts (Ctrl-C returns to the prompt) |
| `clear` / `banner` | Clear the screen / redraw the banner |
| `help`, `exit` | Help / leave (monitoring keeps running) |

Every `fim ...` command also works straight from your shell, for scripts: `sudo fimeyfim fim status`.

### Actions that ask for your system password
Releasing files, changing the TFC, stopping the monitor, closing alerts and uninstalling all ask for the same password you use for `sudo`. There are three attempts. FIMEY-FIM has no password of its own to remember or leak.

## Alerts
While you sit at the prompt, new alerts appear on their own. Type `alerts` to review them.

### The two alert types
| Alert | Raised when |
|---|---|
| **FILE OPEN IN WRITE MODE** | A program opens a protected file for writing, a file is replaced by a writer, or a known text editor opens the file. |
| **FILE MODIFICATION** | The file's SHA-256 hash differs from its baseline. |

Changing a file normally raises both, in that order, so you see *who got in* and then *what changed*. Merely reading a file (for example with `cat`) does not alert.

### What an alert looks like
```
┌─ ALERT #2 | ACTIVE ──────────────────────────────────────────────────────┐
│ Timestamp          : 2026-10-29 04:30:12 +0000                           │
│ Action detected    : FILE MODIFICATION                                   │
│ File name          : confidential.txt                                    │
│ File path          : /srv/confidential/confidential.txt                  │
│ Before hash        : <SHA-256 of the original>                           │
│ After hash         : <SHA-256 of the changed file>                       │
│ Process            : pid 1234 (mousepad) - file opened in an editor      │
│ TFC status         : PRESERVED (hash verified)                           │
│ TFC path           : /secure/tfc/txt/confidential_tfc_copy.txt           │
│ TFC file name      : confidential_tfc_copy.txt                           │
│ TFC file directory : /secure/tfc/txt                                     │
└──────────────────────────────────────────────────────────────────────────┘
```
When a program writes too fast to be identified for certain, the process line says `[probable: last opener]` or `unknown`, and the alert still fires.

### The alert viewer
`alerts` opens an interactive viewer with an **ACTIVE** tab (open alerts) and a **CLOSED** tab. It refreshes itself every couple of seconds.

| Key | Action |
|---|---|
| `r` | Refresh now |
| `x` | Close the selected alert (asks for your password) |
| `X` | Close all active alerts (asks for your password) |
| `q` | Quit the viewer |

Navigation keys are shown at the bottom of the screen. Closing an alert moves it to the CLOSED tab and appends a full record to `/var/log/fimeyfim/deleted.log`, so the organisation can audit exactly what was handled, when, and by whom. Nothing is ever erased. Use `audit` for a table of closed alerts.

### Desktop popups
Every alert is also pushed to the desktop of each logged-in user (via `notify-send`) and broadcast to open terminals, even when the console is closed. Install `libnotify-bin` for popups and run `fim notify-test` to confirm they appear.

## Tampered File Copy (TFC)
TFC is the forensic heart of the tool: the original file, safely set aside the instant something suspicious happens.

**Naming.** A preserved file is named `<name>_tfc_copy.<extension>` and stored in a folder named after its extension:

```
/secure/tfc/
├── txt/
│   ├── confidential_tfc_copy.txt
│   └── confidential_tfc_copy_2.txt     <- a different file with the same name
├── conf/
│   └── secret_tfc_copy.conf
└── noext/
    └── Makefile_tfc_copy               <- files without an extension
```
- If the same original is preserved again (for example, by the open alert and then the modification alert), they share one copy instead of piling up duplicates.
- If a *different* file has the same name, it gets a numbered name so nothing is overwritten.
- Each copy is checked against the baseline hash. The alert shows `PRESERVED (hash verified)`, or `FAILED (...)` with the reason if something went wrong.
- Preserved files are readable by root only.

**Recovering a file.** Copy it back from the TFC, for example:
```bash
sudo cp /secure/tfc/txt/confidential_tfc_copy.txt /srv/confidential/confidential.txt
```

**Good practice.** Keep the TFC on separate, append-only or remote storage so an attacker who gets into the protected folder cannot also reach the evidence.

## Background service, boot and stop/start
`fim init` installs a systemd service (`fimeyfim.service`) that starts at boot and restarts itself if it ever stops. If systemd is not available, the tool starts the monitor directly and `fim status` tells you that boot start is not enabled.

| Task | Command |
|---|---|
| See if it is running | `fim status` |
| Stop (asks for password) | `fim stop` |
| Start again | `fim start` |
| Stop but keep everything | `fim -x init`, then `fim init` later |

`stop`/`start` and `-x init`/`init` always keep your protected files and TFC setting. Changes made to protected files while monitoring was off are caught and alerted as soon as it starts again.

## Update, disconnect, uninstall and reinstall
| Goal | How |
|---|---|
| **Update and keep records** | `./install.sh --upgrade`, or `sudo ./fimeyfim-linux-x86_64 --upgrade` |
| **Pause and keep records** | `fim -x init`, later `fim init` |
| **Uninstall** | `./uninstall.sh`, or `fim uninstall` inside the tool |
| **Uninstall and delete everything** | `./uninstall.sh --purge --delete-folder` |
| **Install again later** | Always a fresh start: `fim init`, set the TFC, add files |

When the tool is removed, its records are archived (not deleted) as `/var/lib/fimeyfim.archive-<time>` and `/var/log/fimeyfim.archive-<time>` so your audit trail survives; `--purge` deletes them. **TFC copies are never touched.**

A reinstall never configures itself. Any new copy of the program is recognised as a new installation, the old records are archived, and you set everything up again from the start.

## Where things live
| Path | Contents |
|---|---|
| `/usr/local/bin/fimeyfim` | The installed program |
| `/etc/systemd/system/fimeyfim.service` | Background service |
| `/var/lib/fimeyfim/` | Configuration, baselines and the vault of originals (root only) |
| `/var/log/fimeyfim/alerts.log` | Every alert, one record per line |
| `/var/log/fimeyfim/deleted.log` | Closed-alert audit ledger |
| *your TFC folder* | Preserved originals |

## Troubleshooting
| Problem | What to do |
|---|---|
| `Rust (cargo) was not found` | `sudo apt install -y cargo`, then `./install.sh` again |
| `$'\r': command not found` when running the scripts | The files have Windows line endings: `sed -i 's/\r$//' install.sh uninstall.sh && chmod +x install.sh uninstall.sh` |
| `fim add` says to set the TFC first | Run `fim add -tfc <dir>` once - it is required |
| No desktop popups | `sudo apt install libnotify-bin`, then `fim notify-test` |
| Status says the monitor is not running | `fim start`, then `fim status` |
| "New installation detected" at startup | You ran a different copy of the program than the one that was configured. This is by design; the old records were archived. Use `--upgrade` when you want to keep records. |
| Editor opened a file but no alert | Editor detection works by process name; very unusual editors may only alert when they save. Saving always raises `FILE MODIFICATION`. |

## Limitations (please read)
- **Detection, not prevention.** Alerts fire after a file is opened or changed; writes are not blocked. The original is safe because it comes from the baseline copy made when you added the file.
- **Editors are recognised by name** from a built-in list. Other programs are caught when they open the file for writing or replace it.
- **New files** created later inside a protected folder are not added automatically; run `fim add -all <dir>` again.
- **Large files.** Copies are streamed, so memory stays low, but copying a very large file keeps the monitor busy while it runs. Plan disk space of roughly twice your protected data plus the TFC copies.
- **A root attacker can attack the tool itself.** Keep the TFC and logs on separate or append-only storage and forward the logs to a central system.
- Linux and x86_64 builds are provided; other architectures can build from source.

## Contributing and license
Issues and pull requests are welcome. To work on the code:
```bash
git clone https://github.com/<your-user>/fimeyfim.git
cd fimeyfim
cargo build --release --locked      # binary: target/release/fimeyfim
```
Releases are built by GitHub Actions when you push a version tag (for example `git tag v2.4.1 && git push origin v2.4.1`).

Licensed under the **MIT License** - see [LICENSE](LICENSE).
