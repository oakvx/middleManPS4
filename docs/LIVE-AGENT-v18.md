# middleManPS4 v0.18 — Live Agent (LAN pilot)

**Experimental, not a system-wide syscall tracer or PSN bypass.** Source-only release. No OpenOrbis PKG has been produced, installed, or tested on PS4 firmware 12.52. GoldHEN does **not** grant the ordinary application automatic access to other processes' syscalls.

## Delivered

- `host.ps4_sender.live_agent`: Python 3.11+ TCP receiver, explicit PC bind IP and PS4 allowlist, 256-bit pairing key, HMAC-SHA256 challenge-response using a fresh random nonce and authenticated metadata frames. It rejects malformed/oversized frames, wrong sequences, unrecognized event types and invalid MACs. A 1,000-event ring buffer exposes dropped-count metrics and optionally writes a private, exclusive JSONL file.
- Read-only dashboard bound to `127.0.0.1:8769`; no CDN, tracking or write requests. Shows PID, elapsed time, event type, status, UTC receipt timestamp and drop metrics.
- `live_agent.elf`: optional self-process probe with bounded PID/firmware-status/heartbeat telemetry (8 heartbeats) and no hooks or privileged accesses. Cross-build and PS4 runtime **not verified**; host C mock tests are not console evidence.
- `scripts/build_live_pkg_stage.py`: verifies and stages an **already-built** OpenOrbis `eboot.bin`, `param.sfo`, `icon0.png` for later packaging with external tools. The ELF payload **is not** a homebrew PKG nor automatically convertible into an installable app.

## Host proof, no console

```powershell
python -m unittest tests.test_live_agent -v
```

For a local paired simulation, use two terminals and a private generated key file. `config` requires a non-loopback PC LAN IPv4; for local simulation you may generate a key with `python -c "import secrets; print(secrets.token_hex(32))"` and save it privately to a file.

```powershell
# Terminal 1, private key stored at logs/live_key.txt; no public bind
python -m host.ps4_sender.live_agent listen --bind 127.0.0.1 --ps4-ip 127.0.0.1 --key-file logs/live_key.txt
# Terminal 2
python -m host.ps4_sender.live_agent simulate --key-file logs/live_key.txt
```

Then open `http://127.0.0.1:8769/` on the PC. The simulator sends **invented process events** and never connects to the console.

## Optional experimental connection to the owned PS4

1. Connect PC and PS4 to a trusted isolated LAN. Identify the PC's actual LAN IPv4 and the PS4's actual LAN IPv4; do not assume either is unchanged. Restrict the Windows firewall inbound port to the PS4 IP; do not expose it on a router or the Internet.
2. Run from the project root. The `logs` directory exists in the repository. The two files below must not already exist:

```powershell
python -m host.ps4_sender.live_agent config --pc-ip PC_LAN_IP --key-file logs/live_key.txt --header payloads/live_agent/live_agent_config.h
python -m host.ps4_sender.live_agent listen --bind PC_LAN_IP --ps4-ip PS4_LAN_IP --key-file logs/live_key.txt --output logs/live_01.jsonl
```

3. Build the *optional ELF* in a separate WSL shell with the installed payload SDK (`PS4_PAYLOAD_SDK` must point to it):

```bash
make -C payloads live_agent
```

4. Before any real transfer validate `dist/live_agent.elf` and use the existing documented `elfldr` sender **only if its presence and firmware compatibility have been verified separately**. A network connection or loader ACK does not prove the ELF ran. Do not attempt this if you lack a backup/recovery route for a console crash.

5. Do **not** publish the generated private key, header, ELF binary, raw Klog or telemetry JSONL. The compiled binary embeds the pairing key, which must be rotated after sharing or loss.

## Packaging as a PS4 PKG (toolchain work pending)

OpenOrbis' documented process packages an **application `eboot.bin`** with `sce_sys/param.sfo` and `sce_sys/icon0.png` using `LibOrbisPkg/PkgEditor`; this is a distinct application build target from the current `elfldr` ELF. Use the official OpenOrbis application template/toolchain to produce the app `eboot.bin` and metadata, then:

```powershell
python scripts/build_live_pkg_stage.py --eboot path/to/app/eboot.bin --sfo path/to/param.sfo --icon path/to/icon0.png --output dist/pkg-stage
```

Only after the files pass validation, use the OpenOrbis/LibOrbisPkg packaging tools to make a PKG. **A finished PKG does not currently exist.** Reference: https://github.com/OpenOrbis/OpenOrbis-PS4-Toolchain/blob/master/docs/MD/Building%20Homebrew.md

## Trust and observability limits

- HMAC challenge prevents simple unauthorized/replayed sessions, and per-frame MACs reject altered events. TCP is **not encrypted**; event metadata remain visible to local on-path observers, and the embedded key can be recovered from a distributed ELF. Use an isolated LAN and do not send secrets.
- Authentication does not prove that telemetry originates from a trustworthy system process: this release proves only the *paired code's claimed PID and own lifecycle*; no kernel attestation.
- Only allowlisted self-events are captured; no credential strings, DNS hosts, destination IPs, syscall arguments, socket payload, PSN token or account data are accepted. GoldHEN Klog TCP 3232 remains a separate source requiring privacy review.
- If a real privileged tracer becomes available, it must be a separate firmware-verified adapter with a defined threat model, sampling limits, consent and recovery strategy. No syscalls of arbitrary system processes are intercepted here.
