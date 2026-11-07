# Research Workbench v0.17 — integrated offline tools

**Research milestone, not a PSN unlock.** The workbench combines existing read-only evidence into a reproducible desktop-local workflow. Its inputs are files; it does not install PS4 hooks, alter firmware, intercept login requests or transmit to Sony.

## Components and what exists today

| Component | v0.17 deliverable | Limitation |
|---|---|---|
| System Observer 2.0 | Structured ingestion and lifecycle check of existing Observer v0.15 stdout | Still observes **only its own process**; read-only system process enumeration needs a separately validated SDK/hardware implementation |
| Network Intelligence | Capture visibility classification, bounded event-kind counts and manually annotated pre/post update-prompt intervals | Without an on-path capture, network conclusions are inconclusive; no process-to-flow attribution |
| Firmware Differential Analyzer | Offline file fingerprinting plus existing `rekit` binary/Orbis/PSF metadata diff | Input binaries must already be legally obtained and unpacked; no SELF decryption or semantic proof of policy |
| Dashboard | `127.0.0.1`-only HTTP interface, read-only, Content-Security-Policy, no external assets | Displays existing report, does not connect to the console |
| Reverse Engineering Assistant | Deterministic rule-based recommendations; optional local Ollama on explicit opt-in | Suggestions are not ground truth; model output may be incorrect |
| Experimental Replay Lab | Purely synthetic / captured *metadata-only* reconstruction in fixed time buckets | Does not retransmit, decrypt, or recreate packets or sign-in requests |
| Evidence Engine | SHA-256 source fingerprints; canonical JSON report seal; verify and exclusive creation | SHA-256 is **not a digital signature** or attestation of PS4 origin |

## Quick start — synthetic examples, no console required

From the repository root (Python >=3.11):

```powershell
python -m unittest tests.test_workbench -v

New-Item -ItemType Directory -Force .\reports | Out-Null
python -m host.ps4_sender.workbench case --observer .\examples\observer_v016_sample.txt --network .\examples\netmeta_v016_sample.json --prompt-second 5 --output .\reports\synthetic_workbench.json

python -m host.ps4_sender.workbench verify --report .\reports\synthetic_workbench.json
python -m host.ps4_sender.workbench explain --report .\reports\synthetic_workbench.json
python -m host.ps4_sender.workbench dashboard --report .\reports\synthetic_workbench.json
```

Visit **http://127.0.0.1:8765** in a browser on the **same machine**. Use Ctrl+C to stop. No CDN, authentication or remote listeners are used, and the dashboard accepts no write requests.

Example file `synthetic_workbench.json` is deliberately generated from invented data; do not call it console evidence. Output files are never overwritten. Use a new filename for every experiment.

### Optional local Ollama

Nothing sends data to a model unless you specify it:

```powershell
python -m host.ps4_sender.workbench explain --report .\reports\synthetic_workbench.json --ollama-model qwen2.5:3b
```

The only intended endpoint is `http://127.0.0.1:11434/api/generate`. The prompt contains limited textual *rules-based findings*, not raw console logs, tokens, IPs or hostnames. Review local model configurations and extensions before use; offline rules are the default. Model explanations are explicitly marked **unverified**.

## Firmware diff — files already on disk

```powershell
python -m host.ps4_sender.workbench diff --before .\path\old.elf --after .\path\new.elf --output .\reports\binary_delta.json
python -m host.ps4_sender.workbench verify --report .\reports\binary_delta.json
python -m host.ps4_sender.workbench dashboard --report .\reports\binary_delta.json --port 8766
```

The diff uses `rekit.report.compare_reports`, compares **static metadata and candidate symbols**, not decrypted firmware, privileged code, or runtime checks. Do not treat a new string/NID as proof of an active gate.

## Research and evidence handling

- Input Observer stdout is capped at 256 KiB. The parser only retains its own PID, firmware version, bounded heartbeat/error markers.
- Packet metadata event lists are capped at 5,000; the workbench copies only timestamps and one of five event types into the output. IPs, DNS/SNI names, raw packet payloads, tokens and other fields are excluded.
- `--prompt-second` refers to a **manually recorded time relative to network capture start**. It cannot be derived from the Observer's heartbeat; the two clocks are not synchronized.
- Source SHA-256 hashes make it possible to recognize which private inputs were used without publishing them. Never upload raw logs containing account information.
- Reports contain `integrity.payload_sha256`. `verify` detects modifications after creation. This is tamper-evidence only, **not** proof of acquisition authenticity.
- No active PS4-to-Internet traffic was proven visible in the original same-Wi-Fi experiment. Re-run a gateway/ICS capture before interpreting PSN behavior.

## Explicitly deferred hardware work

Firmware 12.52 compatibility of the new Observer is **not proven by host tests**. A later hardware milestone must validate the SDK and available read-only process metadata APIs, permission boundaries and telemetry timing on the owner's console. **No system-wide hook, kernel patch, credential interception, PSN request mutation, version spoof or account-login bypass is part of v0.17.**
