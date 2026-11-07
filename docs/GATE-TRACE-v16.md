# Gate Trace v0.16 — Offline observer / UI prompt correlation

> **WIP.** Experimental metadata-only analysis. Nothing here can intercept,
> decrypt, alter, or replay PSN authentication. No password, credential or
> session-token collection. The on-console Observer v0.15 is unchanged.

## Purpose

The PS4 may display an update prompt **before** reaching PSN authentication.
This tool tests a narrower, measurable question: which **network metadata
categories** were observed shortly before and after a manually annotated
prompt, and did the Observer itself run and exit normally?

A local firmware check, a server-side policy check, and account authentication
can cause similar symptoms. Correlation **does not identify which one fired**.

## Reproduce with entirely synthetic fixtures

Run on a PC with Python 3.11+; no PS4, network access, TShark or SDK required:

```powershell
python -m host.ps4_sender.gate_trace --observer examples/observer_v016_sample.txt --network examples/netmeta_v016_sample.json --prompt-second 5 --window-seconds 3
```

`--prompt-second 5` means the user reports seeing the *update dialog* at
approximately 5 seconds after the **network capture started**. This is
**not** the Observer's heartbeat clock. The fixtures are fabricated for
unit tests and demonstrate no real PSN behavior.

## Using existing private lab outputs

1. Run the existing `observer.elf` through the approved `elfldr:9021` sender
   only after its separate console build/runtime check. Save the console's
   **stdout** on the PC as a private text file. This file may contain other
   terminal text; the parser retains only allowlisted Observer fields.
2. Separately, with the PC genuinely on the PS4's network path, collect a
   `psn_netdiag` metadata-only JSON. The old same-Wi-Fi capture is not proof
   of PS4-to-Internet visibility.
3. Note the approximate second after the beginning of **that capture** when
   the update dialog appeared. Do not accept firmware updates.
4. Run the offline command, using unique filenames:

```powershell
python -m host.ps4_sender.gate_trace --observer private_observer_stdout.txt --network gw_psn_attempt.json --prompt-second 18 --window-seconds 5 --output reports/gate_case_01.json
```

The output file must not exist. Use an existing `reports` directory, or omit
`--output` to print the sanitized JSON. `--prompt-second` and the network
summary are optional: the Observer log can be assessed independently.

## Output and interpretation

- Observer `status=complete` means the captured *stdout sequence* has exactly
  12 ordered heartbeats, start, and completion. It is **not** confirmation of
  the integrity of the console, other processes, or authentication.
- `capture_visibility.status=public_destination_observed` confirms that the
  capture contained **some** public-destination IPv4 packets from the PS4,
  not every flow or any specific PSN exchange.
- `before_prompt` and `after_prompt` count DNS/TCP/TLS **metadata event types**
  within the chosen window. Empty maps do not imply no traffic: packet capture
  may have missed traffic, and the summary stores only selected event types.
- The UI time is entered by a human; the ELF heartbeat cannot synchronize it
  to TShark capture time. Results are **descriptive**, not proof of a local
  update gate, successful authentication, or server-side rejection.
- Input is bounded (256 KiB Observer log, up to 5,000 metadata events); raw
  log lines, URLs, SNI hostnames, IPs, passwords and tokens are **not copied**
  to the generated report.

## Validation

```powershell
python -m unittest tests.test_gate_trace -v
python -m unittest discover -s tests -q
```

PS4 SDK cross-build and runtime of the v0.15 Observer remain independently
unverified. This host-only addition neither modifies the kernel nor sends
packets to Sony.
