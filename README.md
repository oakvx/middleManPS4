<div align="center">

# middleManPS4

<<<<<<< HEAD
### PS4 RESEARCH LAB // PAYLOADS · REVERSE ENGINEERING · NETWORK OBSERVABILITY

[![Development](https://img.shields.io/badge/DEVELOPMENT-ACTIVE_WIP-FFB000?style=for-the-badge)](https://github.com/oakvx/middleManPS4)
[![Version](https://img.shields.io/badge/LOCAL_SNAPSHOT-v0.14.0-64748B?style=for-the-badge)](VERSION)
[![Python](https://img.shields.io/badge/PYTHON-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](pyproject.toml)
[![CI](https://img.shields.io/github/actions/workflow/status/oakvx/middleManPS4/ci.yml?branch=main&style=for-the-badge&label=MAIN%20CI)](https://github.com/oakvx/middleManPS4/actions/workflows/ci.yml)

**An evidence-driven research toolkit for PS4 homebrew payloads, Orbis binaries and observable network behavior.**

[Quick start](#-quick-start) · [Toolkit](#-toolkit) · [Architecture](#-architecture) · [Compatibility](#-compatibility--evidence) · [Roadmap](#-roadmap) · [Documentation](#-documentation)

</div>

```text
  PS4 / GoldHEN                  Windows / WSL
  ─────────────                  ─────────────
  payload execution ──────────►  ELF validation + diagnostics
  firmware information ───────►  structured evidence
  observable network metadata ►  offline correlation
                                 │
  ELF / SFO / Orbis artifacts ───┴──► RE Toolkit ──► JSON / Markdown
                                         ▲
                                     Ghidra (optional)
```

> [!IMPORTANT]
> **RESEARCH PROTOTYPE — NOT A PSN UNLOCKER.**
> This project **does not** currently spoof PS4 firmware, bypass PSN authentication, decrypt PSN TLS sessions or enable online play on unsupported firmware. Documentation distinguishes *implemented features*, *local tests* and *unverified hypotheses*.

## What is middleManPS4?

**middleManPS4** (originally developed under the working name `fwSpoofer`) is a modular PS4 research workspace. It brings together four areas that are easier to investigate when they share one evidence format:

| Area | Purpose | What you get |
|:--|:--|:--|
| **Payload Lab** | Build and validate test ELF payloads; interact with a compatible loader | ELF validation, sender, loader diagnostics |
| **Firmware Diagnostics** | Query local system information from a test payload | Read-only firmware version observations |
| **Network Lab** | Determine which PS4 traffic is actually visible to an observer | Capture metadata, baseline comparisons, visibility counters |
| **RE Toolkit** | Inspect PS4-related artifacts offline and integrate Ghidra output | Orbis/ELF, PSF, NIDs, dependencies, JSON/Markdown reports |

The word **middleMan** describes an experimental interest in *network-path observation*. **Being on the same Wi-Fi is not equivalent to being in the traffic path**, and the project makes no claim of having a working transparent MITM.

## ⚡ Quick start

**Host tools only — no PS4 connection required.** The commands below are designed for Python **3.11+** and run from the repository root.

```powershell
# Clone the source (the public main branch may lag behind this local snapshot)
git clone https://github.com/oakvx/middleManPS4.git
cd middleManPS4

# Run the offline test suite
=======
**PS4 Payload Research · Firmware Diagnostics · Network Observation**

[![Status](https://img.shields.io/badge/STATUS-WORK_IN_PROGRESS-F5A623?style=for-the-badge)](https://github.com/oakvx/middleManPS4)
[![Version](https://img.shields.io/badge/VERSION-0.10.0-64748B?style=for-the-badge)](VERSION)
[![Platform](https://img.shields.io/badge/PLATFORM-PS4-2563EB?style=for-the-badge)](https://github.com/oakvx/middleManPS4)
[![Python](https://img.shields.io/badge/PYTHON-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](pyproject.toml)

*An experimental toolkit for understanding how a PS4 loads homebrew payloads and communicates with network services.*

[Overview](#overview) · [Project status](#project-status) · [Architecture](#architecture) · [Quick start](#quick-start) · [Roadmap](#roadmap)

</div>

> [!IMPORTANT]
> **ACTIVE DEVELOPMENT — WIP / RESEARCH PROTOTYPE**
>
> **middleManPS4 does not currently bypass PlayStation Network authentication, spoof the system firmware, or enable PSN sign-in on unsupported firmware.** Those are research questions, **not available features**. This is not a plug-and-play PSN unlocker.

## Overview

**middleManPS4** is an independent PS4 research workspace built around three complementary areas:

- **Payload development:** compile, validate and transfer ELF test payloads using the PS4 Payload SDK and a compatible loader.
- **System diagnostics:** read the software version and observe test-payload output without modifying the installed firmware.
- **Network research:** collect limited DNS/TLS/TCP metadata and compare baseline traffic against a PSN sign-in attempt, without decrypting or rewriting HTTPS sessions.

The original internal tooling is named **`fwSpoofer`**. The repository name **`middleManPS4`** reflects the long-term interest in network-path analysis; it does **not** imply that a working transparent MITM or authentication bypass is available.

## Project status

| Component | Status | Evidence / limitation |
|:--|:--:|:--|
| PS4 Payload SDK build | ✅ Verified | `hello_world.elf` and `firmware_info.elf` compiled under WSL |
| BD-JB → GoldHEN → `elfldr` | ✅ Tested | TCP loader reachable on `9021` in one real-console setup |
| ELF execution | ✅ Tested | Hello World notification observed on console |
| Firmware readout | ✅ Tested | `sceKernelGetSystemSwVersion` returned `12.520.001` (`0x12520001`) |
| Offline ELF checks and host tests | ✅ Available | Automated tests; not a guarantee of compatibility |
| Klog diagnostic tooling | ✅ Available | No PSN-specific log event identified in the test run |
| Passive network analysis | 🧪 In testing | Local capture verified; PS4-to-Internet visibility not established |
| Gateway-based PSN traffic observation | ⏳ Planned | Requires a controlled network path |
| Firmware-version spoofing | ❌ Not implemented | No firmware or kernel version patch |
| PSN login bypass | ❌ Not implemented | No proof that a bypass is feasible |

**Hardware experiment:** one PS4 on system software **12.52**, using **BD-JB** and **GoldHEN 2.4b18.7**. These results are **configuration-specific**; other firmware versions, jailbreak methods and loader builds may behave differently.

## Architecture

```mermaid
flowchart LR
    subgraph Console[PS4 · research target]
        A["BD-JB + GoldHEN"] --> B["elfldr · TCP 9021"]
        B --> C["Test ELF payloads"]
        C --> D["Notification + firmware readout"]
    end

    subgraph Host[Windows / WSL · development host]
        E["PS4 Payload SDK"] --> F["ELF validator + sender"]
        G["Klog diagnostics"]
        H["TShark / NetLab"]
    end

    F -->|"ELF transfer"| B
    A -.->|"Klog, when enabled"| G
    I["Controlled gateway / mirror · planned"] -.-> H
    Console -.->|"Network traffic · only if routed through observer"| I
```

The network lab operates **independently** from the payload loader. Merely connecting a PC and PS4 to the same Wi-Fi network usually does **not** expose the console's Internet-bound unicast traffic to the PC.

## Repository layout

```text
middleManPS4/
├── payloads/     # PS4 test payloads and shared code
├── host/         # Python sender, ELF validation and NetLab
├── scripts/      # Build, bootstrap and offline verification helpers
├── tests/        # Unit and regression tests
├── docs/         # Architecture, experiments and technical notes
├── configs/      # Configuration examples
├── Makefile
└── README.md
```

## Quick start

### Requirements

- **Python 3.11+** for host utilities and offline tests.
- **Linux / WSL Ubuntu + [ps4-payload-dev/sdk](https://github.com/ps4-payload-dev/sdk)** for compiling PS4 payloads.
- **TShark + Npcap** on Windows for network-capture experiments (optional).
- An **owned or explicitly authorized** PS4 and network for hardware tests.

### Clone and verify offline

```bash
git clone https://github.com/oakvx/middleManPS4.git
cd middleManPS4

>>>>>>> 54e33b17e38dd687f0328a4745545dbb8f71d222
python -m unittest discover -s tests -v

# Analyze a local ELF (when dist/firmware_info.elf is available)
python -m host.ps4_sender.rekit analyze .\dist\firmware_info.elf

# Produce a reviewable case report
New-Item -ItemType Directory -Force .\reports | Out-Null
python -m host.ps4_sender.rekit analyze .\dist\firmware_info.elf --output .\reports\case.json
python -m host.ps4_sender.rekit markdown .\reports\case.json --output .\reports\case.md
```

<<<<<<< HEAD
> [!NOTE]
> **v0.14.0 is an experimental local snapshot.** At the time this README was written, GitHub `main` was still at v0.10.0. The v0.14 commands require the **v0.14 project archive/patch**, not just a fresh clone of `main`. The `--output` commands deliberately refuse to overwrite an existing report: use new filenames for subsequent runs.

## 🧰 Toolkit

<details open>
<summary><b>01 / Offline reverse engineering</b> — ELF, Orbis, NIDs, Ghidra and reports</summary>

The RE Toolkit processes **existing files** on the host; it does not patch firmware or execute code on the console.

```powershell
# Binary identity and ELF/Orbis structures
python -m host.ps4_sender.rekit binary .\dist\firmware_info.elf
python -m host.ps4_sender.rekit orbis .\dist\firmware_info.elf
python -m host.ps4_sender.rekit dynlib .\dist\firmware_info.elf

# Symbols and potential NID references
python -m host.ps4_sender.rekit symbols .\dist\firmware_info.elf
python -m host.ps4_sender.rekit nids .\dist\firmware_info.elf

# Inventory a group of ELF files and compare existing reports
python -m host.ps4_sender.rekit batch .\dist --glob "*.elf"
python -m host.ps4_sender.rekit analyze-diff .\reports\before.json .\reports\after.json
```

The analyzer differentiates **validated dynamic string-table candidates** from general string matches. Static references are *not proof that a code path executes*, nor that PSN will accept a version claim.

**Ghidra integration:** optional headless inventory export; provide a local Ghidra installation, input ELF and output path. See [RE Toolkit v0.14](docs/RE-TOOLKIT-v14.md). The export script has undergone offline validation, **not a full run against an installed Ghidra instance**.

</details>

<details>
<summary><b>02 / Payload development</b> — build, inspect, transfer</summary>

A Linux/WSL environment with the [PS4 Payload SDK](https://github.com/ps4-payload-dev/sdk) is used for compilation. Example:

```bash
export PS4_PAYLOAD_SDK="$HOME/ps4-payload-sdk-1252"  # set your actual SDK directory
make
```

The sender is designed around the tested `elfldr` TCP **9021** path. Upload success does **not** prove successful execution; check console-side output and loader responses. Read [Payload development](docs/payload-development.md) and [Loader installation](docs/loader-install.md) before any hardware test.

</details>

<details>
<summary><b>03 / Network diagnostics</b> — passive capture and visibility checks</summary>

```powershell
# Discover local capture interfaces
python -m host.ps4_sender.psn_netdiag interfaces

# Compare two already-collected metadata summaries
python -m host.ps4_sender.psn_triage --baseline baseline.json --attempt psn_attempt.json

# Inspect an existing summary offline
python -m host.ps4_sender.rekit net .\baseline.json
```

Network data is useful **only if the observer is actually on the packet path**. A local ICMP reply does not demonstrate visibility of PS4-to-Internet traffic. See [PSN path visibility](docs/PSN-VISIBILITY-v11.md) and [Network Lab](docs/PSN-NETLAB-v10.md).

The toolkit does **not** intercept credentials, decrypt TLS or impersonate Sony endpoints.

</details>

## 🧬 Architecture

```mermaid
flowchart LR
    subgraph PS4["PS4 · hardware experiment"]
        A["BD-JB + GoldHEN"] --> B["elfldr :9021"]
        B --> C["Read-only test ELF"]
    end
    subgraph HOST["Windows / WSL · host"]
        D["SDK + build"] --> E["ELF validator / sender"]
        F["Network diagnostics"]
        G["RE Toolkit"]
        H["Ghidra · optional"] --> G
        G --> I[("Evidence / JSON / Markdown")]
        F --> I
    end
    E -->|"validated ELF"| B
    C -.->|"console result"| I
    J["Gateway / mirror · unverified"] -.->|"observable metadata"| F
```

For the current design, see [architecture.md](docs/architecture.md). The diagram shows **data flow and intended integration**, not successful PSN authentication or interception.

## 🧪 Compatibility & evidence

| Component | State | Evidence and limits |
|:--|:--:|:--|
| ELF compilation and host validation | **Tested** | Local toolchain and automated tests |
| GoldHEN → `elfldr` on TCP 9021 | **Hardware-tested** | One PS4 test setup |
| Hello World payload | **Hardware-tested** | Notification observed on console |
| Firmware readout | **Hardware-tested** | `sceKernelGetSystemSwVersion` → `12.520.001` |
| Offline RE Toolkit | **Tested locally** | ELF, Orbis, PSF, NID and report analysis |
| Ghidra headless runtime | **Not yet hardware/software-tested** | Script checked offline; live integration pending |
| Public-Internet traffic visibility | **Not yet demonstrated** | Requires controlled gateway / mirror capture |
| Firmware spoofing | **Not implemented** | No system-version patch |
| PSN sign-in bypass | **Not implemented** | No supported end-to-end demonstration |

**Reference hardware:** PS4 system software **12.52** with BD-JB and **GoldHEN 2.4b18.7**. These observations do **not** establish compatibility for other consoles or firmware revisions.

**v0.14 offline validation:** 195 automated tests passed in the development snapshot. This is an *offline test result*, not a certification of runtime safety or remote compatibility.

## 🗺️ Roadmap

- [x] Build and validate PS4 test payloads.
- [x] Exercise one GoldHEN + `elfldr` loading path on actual hardware.
- [x] Capture read-only firmware information.
- [x] Establish host-side regression tests and integrity checks.
- [x] Implement passive network metadata analysis with path-visibility counters.
- [x] Add offline ELF/Orbis, PSF, NID and dynamic-dependency inspection.
- [x] Generate comparable case reports and optional Ghidra inventory correlations.
- [ ] Validate Ghidra headless export on a real Ghidra installation.
- [ ] Demonstrate PS4-to-Internet packet visibility via a controlled gateway or mirror.
- [ ] Correlate reproducible client-side events with network observations.
- [ ] Investigate firmware-version checks without presuming an effective bypass.
- [ ] Improve public release packaging and documentation.

## 📁 Repository map

```text
middleManPS4/
├── payloads/         # PS4 test payloads and shared C code
├── host/             # Python sender, NetLab, diagnostics and rekit
├── scripts/          # Build, checks, optional Ghidra scripts
├── tests/            # Offline regression tests
├── docs/             # Runbooks, analysis and design notes
├── configs/          # Configuration examples
├── dist/             # Locally built/staged test binaries
├── pyproject.toml
├── SHA256SUMS.txt     # Snapshot integrity manifest
└── README.md
```

The offline preflight validates checksums and runs the test suite:

```powershell
python scripts/preflight_offline.py
```

If you edit a tracked file, the snapshot checksum check will correctly detect the change until you update its entry in `SHA256SUMS.txt`.

## 📚 Documentation

| Guide | Topic |
|:--|:--|
| [RE Toolkit v0.14](docs/RE-TOOLKIT-v14.md) | Integrated analysis, report commands, Ghidra inventory |
| [RE Toolkit v0.13](docs/RE-TOOLKIT-v13.md) | Dynamic ELF data, NIDs and Ghidra bridge |
| [Network visibility v0.11](docs/PSN-VISIBILITY-v11.md) | Observing the right traffic path |
| [PSN NetLab v0.10](docs/PSN-NETLAB-v10.md) | Network metadata diagnostics |
| [Payload development](docs/payload-development.md) | Building and executing test payloads |
| [Architecture](docs/architecture.md) | Components and assumptions |
| [Changelog](CHANGELOG.md) | Changes and experiment history |

## Responsible research

> [!CAUTION]
> Only test on hardware and networks you own or are authorized to inspect. Avoid real accounts during experiments. **Never publish credentials, tokens, packet captures containing personal data or identifiable network logs.** The project makes no guarantee of compatibility, safety or access to PSN.

**License:** no license has been published yet. Public visibility of the source does not automatically grant rights to reuse or redistribute it. Reports of reproducible observations are welcome through [GitHub Issues](https://github.com/oakvx/middleManPS4/issues).

---

<div align="center">

**middleManPS4** · *Measure first. Reverse engineer second. Make claims only when the evidence holds.*

`RESEARCH / WIP` · `NO PSN BYPASS` · `v0.14.0 LOCAL SNAPSHOT`

[GitHub](https://github.com/oakvx/middleManPS4) · [Issues](https://github.com/oakvx/middleManPS4/issues) · [Changelog](CHANGELOG.md)
=======
For a full local preflight (including the repository's checksum manifest):

```bash
python scripts/preflight_offline.py
```

> [!NOTE]
> The preflight is **offline**. It cannot confirm that an ELF executed on a PS4, and its checksum check will fail after you modify any file listed in `SHA256SUMS.txt` until you regenerate the corresponding manifest entry.

### Build test payloads

Configure the installed SDK and build from Linux or WSL:

```bash
export PS4_PAYLOAD_SDK="$HOME/ps4-payload-sdk-1252"  # adjust to your installation
make
```

**Do not send experimental payloads to a console without reviewing the loader, firmware support and documentation first.** A successful TCP transfer does not prove remote execution.

### Explore the network lab

```bash
# List capture interfaces
python -m host.ps4_sender.psn_netdiag interfaces

# Compare two existing metadata summaries (no network activity)
python -m host.ps4_sender.psn_triage \
  --baseline baseline.json \
  --attempt psn_attempt.json
```

Read [PSN NetLab technical notes](docs/PSN-NETLAB-v10.md) before attempting a capture. **Do not upload packet captures, credentials, authentication tokens or identifiable network logs to public issues.**

## Roadmap

- [x] PS4 SDK toolchain and ELF payload build.
- [x] GoldHEN / `elfldr` experimental loading path.
- [x] Real-console Hello World and read-only firmware information tests.
- [x] Offline validation, diagnostics and regression-test scaffolding.
- [x] Initial passive packet-capture tooling.
- [ ] Verify visibility of PS4 Internet traffic through a controlled gateway or mirrored port.
- [ ] Characterize the system-update prompt and relevant *observable* network events.
- [ ] Separate client-side checks from server-side requirements using reproducible evidence.
- [ ] Assess whether any proposed spoofing technique is feasible, without assuming success.
- [ ] Improve documentation, repeatability and compatibility reporting.

## Research boundaries

- **No PSN bypass is claimed.** A displayed firmware version is not proof of server acceptance.
- **No TLS decryption or credential interception is provided.** The optional CONNECT tunnel forwards encrypted data without changing the contents.
- **No permanent system update or firmware patch is performed by the current diagnostic payload.**
- **No universal compatibility is claimed.** Payloads can crash a console or require a reboot.
- **PSN access may require Sony-side checks that a local spoof cannot satisfy.** Modified systems may also face account or console restrictions.

Use this repository **only on hardware and networks you own or are authorized to inspect**. Keep experiments reversible, avoid important accounts and never disclose session material.

## Documentation

- [Project architecture](docs/architecture.md)
- [Payload development](docs/payload-development.md)
- [Firmware information](docs/firmware-info.md)
- [PSN NetLab](docs/PSN-NETLAB-v10.md)
- [Changelog](CHANGELOG.md)

> [!WARNING]
> Documentation is evolving with the experiments. Older notes may describe paths that were not yet validated when written; verify claims against the current code and test evidence.

## License and contributions

**No license has been published yet.** The source is viewable on GitHub, but this does not automatically grant permission to redistribute or reuse it. Contributions, issues and technical discussions should focus on reproducible observations, non-sensitive logs and clearly separated facts versus hypotheses.

---

<div align="center">

**middleManPS4** · *Built to investigate, not to overpromise.*

**WORK IN PROGRESS — NOT A RELEASED PSN BYPASS**

[Repository](https://github.com/oakvx/middleManPS4) · [Issues](https://github.com/oakvx/middleManPS4/issues)
>>>>>>> 54e33b17e38dd687f0328a4745545dbb8f71d222

</div>
