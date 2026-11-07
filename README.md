<div align="center">

# middleManPS4

**PS4 payload lab · offline Orbis/ELF reverse engineering · network observability**

<p>
<img src="https://img.shields.io/badge/status-research%20%2F%20WIP-F5A623?style=flat-square"/>
<img src="https://img.shields.io/badge/PSN%20bypass-not%20implemented-E5484D?style=flat-square"/>
<img src="https://img.shields.io/badge/snapshot-v0.15.0-64748B?style=flat-square"/>
<img src="https://img.shields.io/badge/python-3.11%2B-3776AB?style=flat-square&logo=python&logoColor=white"/>
<img src="https://img.shields.io/github/actions/workflow/status/oakvx/middleManPS4/ci.yml?branch=main&style=flat-square&label=CI"/>
</p>

ex `fwSpoofer`. Three things that are easier to study together: how a PS4 loads a payload, what's inside the binaries, what's visible on the wire.

[Quick start](#quick-start) · [The question](#the-actual-question) · [Toolkit](#toolkit) · [Evidence](#hardware-evidence) · [Architecture](#architecture) · [Roadmap](#roadmap)

</div>

```text
PS4 (BD-JB + GoldHEN)       Windows / WSL host
─────────────────────       ──────────────────
elfldr :9021        ──────► ELF validator + sender
firmware readout     ──────► structured evidence (JSON)
network traffic*     ──────► capture + baseline correlation

ELF / SFO / Orbis files ────► rekit ──► JSON / Markdown
                                  ▲
                              Ghidra (optional)

* only if the host is actually on the packet path
```

> **Not a PSN unlocker.** No firmware-version spoof, no PSN auth bypass, no TLS decryption, no online-on-unsupported-firmware. Every claim in this README is tagged tested, untested, or not implemented.

---

## the actual question

Does PSN check the reported system version client-side, server-side, or both — and is that check even reachable from the network path? Unknown. Three things have to hold before "spoofing" is more than a hypothesis, and none of them hold yet:

- [ ] PS4 → Internet traffic is visible to an observer (same Wi-Fi ≠ on-path)
- [ ] the version claim travels somewhere outside TLS — likely blocker
- [ ] the server side even cares, independent of the client

This repo exists to chip away at those three with evidence, not to skip past them.

---

## toolkit

| | |
|---|---|
| payload lab | build/validate test ELF, send over the tested `elfldr` path |
| firmware diagnostics | read-only `sceKernelGetSystemSwVersion`, nothing else |
| network lab | passive DNS/TLS/TCP metadata, baseline vs. sign-in attempt |
| rekit | offline ELF/Orbis/PSF/NID inspection, JSON/Markdown reports, optional Ghidra export |

## observer ELF (experimental, WIP)

The new `observer.elf` is a **read-only self-observation prototype**:
it reads firmware information, prints its own PID and emits 12 timed
heartbeats. Host-C mock tests pass; PS4 cross-build/runtime is **not yet
verified**. It does **not** hook PSN processes, decrypt TLS, collect
credentials, spoof firmware, or bypass authentication.

See [Observer v0.15](docs/OBSERVER-v15.md) for exact limitations and
the optional experimental build.

## hardware evidence

One console: PS4, 12.52, BD-JB, GoldHEN 2.4b18.7. Nothing below generalizes past this config.

| | result |
|---|---|
| build + offline host tests | tested — 195 tests pass |
| GoldHEN → `elfldr` on TCP 9021 | tested |
| hello-world payload | tested — notification on console |
| firmware readout | tested — returns `12.520.001` |
| Ghidra headless export | untested — checked offline only |
| PS4 → Internet traffic visibility | not demonstrated |
| firmware-version spoofing | not implemented |
| PSN sign-in bypass | not implemented, no evidence it's feasible |

## quick start

```powershell
git clone https://github.com/oakvx/middleManPS4.git
cd middleManPS4
python -m unittest discover -s tests -v
```

```powershell
python -m host.ps4_sender.rekit analyze .\dist\firmware_info.elf
python -m host.ps4_sender.rekit analyze .\dist\firmware_info.elf --output .\reports\case.json
python -m host.ps4_sender.rekit markdown .\reports\case.json --output .\reports\case.md
```

`--output` never overwrites — use a new filename per run. v0.14 commands need v0.14 code; a fresh clone of `main` may lag behind.

<details>
<summary><b>rekit — offline binary analysis</b></summary>

Reads files already on disk. Never touches the console.

```powershell
python -m host.ps4_sender.rekit binary  .\dist\firmware_info.elf
python -m host.ps4_sender.rekit orbis   .\dist\firmware_info.elf
python -m host.ps4_sender.rekit symbols .\dist\firmware_info.elf
python -m host.ps4_sender.rekit nids    .\dist\firmware_info.elf
python -m host.ps4_sender.rekit batch   .\dist --glob "*.elf"
python -m host.ps4_sender.rekit analyze-diff .\reports\before.json .\reports\after.json
```

A static string match is not proof a code path runs, and definitely not proof PSN accepts anything.

</details>

<details>
<summary><b>building payloads</b></summary>

```bash
export PS4_PAYLOAD_SDK="$HOME/ps4-payload-sdk-1252"
make
```

Targets the tested `elfldr` TCP 9021 path. A successful upload ≠ successful execution — check the console. Read [payload-development.md](docs/payload-development.md) first. Bad payloads crash consoles.

</details>

<details>
<summary><b>network lab</b></summary>

```powershell
python -m host.ps4_sender.psn_netdiag interfaces
python -m host.ps4_sender.psn_triage --baseline baseline.json --attempt psn_attempt.json
```

Same Wi-Fi ≠ on-path. A local ping reply proves nothing about PS4 → Internet visibility — see [PSN-VISIBILITY-v11.md](docs/PSN-VISIBILITY-v11.md). No credential capture, no TLS decryption, no endpoint impersonation.

</details>

## architecture

```mermaid
flowchart LR
    subgraph PS4
        A["BD-JB + GoldHEN"] --> B["elfldr :9021"]
        B --> C["test ELF"]
    end
    subgraph Host["Windows / WSL"]
        D["SDK"] --> E["validator / sender"]
        F["net diagnostics"]
        G["rekit"]
        H["Ghidra (optional)"] --> G
        G --> I[("JSON / Markdown")]
        F --> I
    end
    E -->|ELF| B
    C -.->|output| I
    J["gateway / mirror, unverified"] -.-> F
```

## roadmap

- [x] payload build + validate
- [x] GoldHEN + `elfldr` on real hardware
- [x] read-only firmware info
- [x] host test scaffolding
- [x] passive network metadata
- [x] offline ELF/Orbis/PSF/NID inspection
- [x] add read-only observer prototype (host mocks only)
- [ ] run the Ghidra export on a real install
- [ ] show PS4 → Internet visibility through a gateway/mirror
- [ ] correlate client-side events with network observations
- [ ] investigate whether the version check is even interceptable
- [ ] packaging, docs

## docs

| | |
|---|---|
| [RE Toolkit v0.14](docs/RE-TOOLKIT-v14.md) | report commands, Ghidra inventory |
| [Network visibility v0.11](docs/PSN-VISIBILITY-v11.md) | what "on-path" actually means |
| [PSN NetLab v0.10](docs/PSN-NETLAB-v10.md) | metadata diagnostics |
| [Payload development](docs/payload-development.md) | building and running test payloads |
| [Architecture](docs/architecture.md) | components and assumptions |
| [Changelog](CHANGELOG.md) | history |

## safety

Your own hardware and network, or explicit authorization — nothing else. Don't use accounts you care about. Never post credentials, tokens, or packet captures with personal data in issues.

## license

None published. Public source ≠ permission to reuse or redistribute.

---

<div align="center">

issues with reproducible evidence > issues asking "does it work yet"

</div>
