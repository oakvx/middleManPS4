# middleManPS4 v0.15 — Observer ELF (experimental)

> **WIP — self-observation only.** This is an experimental read-only
> payload, **not** a PSN-interception hook or a firmware spoofer.

## What it actually does

- Queries its **own** process ID with `getpid()`.
- Reads the system firmware using the existing `fw_info_read()` and
  `sceKernelGetSystemSwVersion()` userspace call.
- Emits 12 one-second heartbeat messages on standard output.
- Reports early errors and exits; no background daemon is installed.

This prototype **cannot** inspect other PS4 processes, see their socket
traffic, identify Sony's authentication endpoints, read passwords, decrypt TLS,
modify network messages, patch system memory or bypass a PSN firmware gate.

## Host-level check (no console)

```powershell
python -m unittest tests.test_observer_payload -v
python scripts/preflight_offline.py
```

The host test compiles the actual C source against mocked PS4 APIs. This is
**not** a PS4 runtime test.

## PS4 cross-build in WSL

```bash
export PS4_PAYLOAD_SDK="$HOME/ps4-payload-sdk-1252"
make observer
```

This must produce `dist/observer.elf`. SDK cross-build compatibility is not
confirmed by the host mock. Never treat an ELF validation or a successful TCP
transfer as proof of execution.

## Optional manual runtime test

Only on hardware you own and only after `elfldr` is **already** confirmed to be
listening on TCP 9021:

```powershell
python -m host.ps4_sender.cli --host YOUR_PS4_IP --loader elfldr --file dist/observer.elf --check-elf
```

This is a dry run. After validating the file and accepting the possibility
of console instability, a **single** explicit test can be performed:

```powershell
python -m host.ps4_sender.cli --host YOUR_PS4_IP --loader elfldr --file dist/observer.elf --check-elf --response-timeout 20 --send
```

Observe the console and the resulting `event=start`, `event=heartbeat` and
`event=complete` messages. No user credentials or PSN account interaction
is involved. Do not send this ELF directly to GoldHEN TCP 9090.

## Next research task

Identify documented, version-compatible **read-only** process/network
metadata APIs and assess the console's permissions before extending the
observer. Capturing plaintext authentication data or altering Sony's login
requests is deliberately outside the scope of this release.
