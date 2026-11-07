# middleManPS4 v0.14 — Integrated Offline RE Pipeline

**Scope:** Python 3.11+, offline, read-only analysis. This release joins the previously independent `binary`, `orbis`, `nids`, `symbols`, `psf`, `netmap`, and Ghidra inventory helpers into reproducible case reports. It does **not** spoof PS4 firmware, bypass PSN, impersonate Sony services, decrypt SELF content, or perform active network interception.

## Research basis

- OpenOrbis: [PS4 ELF Specification](https://github.com/OpenOrbis/OpenOrbis-PS4-Toolchain/wiki/PS4-ELF-Specification). Documents SCE-specific ELF types, segments and dynamic tags.
- OpenOrbis: [PS4 ELF Specification — Dynlib Data](https://github.com/OpenOrbis/OpenOrbis-PS4-Toolchain/wiki/PS4-ELF-Specification---Dynlib-Data). `PT_SCE_DYNLIBDATA` holds dynamic-linking tables. `DT_SCE_STRTAB` and `DT_SCE_STRSZ` give the string-table range within the segment. This is the basis of the **bounded, file-relative** mapping in `rekit.dynlib`.
- Ghidra: [Headless Analyzer README](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/RuntimeScripts/support/analyzeHeadlessREADME.md). `-import`, `-scriptPath`, `-postScript` and command-line script arguments enable unattended inventory generation.
- Wireshark: [TShark manual](https://www.wireshark.org/docs/man-pages/tshark.html). Network summaries are produced independently by existing host diagnostics and **not** by the offline report tools.

This code references documented formats only. It does not incorporate source code from OpenOrbis or shadPS4.

## New features

| Module / command | What it actually does |
|---|---|
| `rekit.dynlib`, `dynlib FILE` | Read exactly one valid SCE string table, enumerate bounded library/module name records, preserve raw packed metadata, and enumerate **syntactic** NIDs only within that table. Reject ambiguous/incomplete table bounds. |
| `rekit.report`, `analyze FILE` | One bounded input read, SHA-256, ELF/SELF/PSF identification, dynamic tags, libraries, symbols and NID diagnostics. |
| `analyze --ghidra-inventory ...` | Join an existing JSON inventory by symbol name. The report **explicitly labels Ghidra provenance as unverified**, even if the filenames match. |
| `analyze --network-summary ...` | Join a previously saved sanitized `fwSpoofer-netmeta-v1` report and its visibility/timeline. Never claims the observed PS4 traffic belongs to the inspected ELF. Tunnel JSONL is **not** an input to this command. |
| `analyze-diff A.json B.json` | Compare named library references, scoped NID candidate strings and raw symbol strings between reports. Not a semantic or binary patch diff. |
| `batch DIRECTORY --glob '*.elf'` | Inspect a flat directory of at most 32 regular non-symlink files; errors are reported per file. |
| `markdown FILE.json` | Produce a compact audit summary suitable for a GitHub issue or laboratory notes. |
| Ghidra bridge `ghidra-run` | A zero process exit code is **insufficient**: successful execution now also requires a valid schema-checked JSON inventory to exist. |

### One-command case report (PowerShell)

From the repository root:

```powershell
New-Item -ItemType Directory -Force .\reports | Out-Null

python -m host.ps4_sender.rekit analyze .\dist\firmware_info.elf `
  --output .\reports\firmware-info-v14.json

python -m host.ps4_sender.rekit markdown .\reports\firmware-info-v14.json `
  --output .\reports\firmware-info-v14.md
```

Without `--output`, `analyze` emits JSON and `markdown` emits Markdown to standard output. Output files **must not exist** before saving.

### Include an existing Ghidra inventory (optional)

Generate it first via `ghidra-plan` / `ghidra-run` in [v0.13 documentation](RE-TOOLKIT-v13.md). Then join it with the binary:

```powershell
python -m host.ps4_sender.rekit analyze .\dist\firmware_info.elf `
  --ghidra-inventory .\reports\firmware_info_ghidra.json `
  --output .\reports\with-ghidra.json
```

The association is **name-only and untrusted**: Ghidra's JSON export currently does not contain an authenticated hash of the original binary. Inspect the `program` and `source` fields manually before treating it as the same build.

### Include a sanitized network report (optional)

```powershell
python -m host.ps4_sender.rekit analyze .\dist\firmware_info.elf `
  --network-summary .\baseline.json `
  --output .\reports\with-network.json
```

**Interpretation:** For the existing `baseline.json` with zero events, the capture does not establish that Internet-bound PS4 traffic is visible. More generally, attaching a capture to an ELF is a comparison of laboratory observations; it is **not** evidence of the ELF's PSN behavior, a successful login or firmware eligibility.

### Compare or inventory multiple files

```powershell
python -m host.ps4_sender.rekit analyze-diff .\reports\before.json .\reports\after.json
python -m host.ps4_sender.rekit batch .\dist --glob "*.elf" --output .\reports\batch.json
python -m host.ps4_sender.rekit dynlib .\dist\firmware_info.elf
```

### Evidence levels and caveats

- `verified-local-bytes`: SHA-256 is computed from the actual file bytes.
- `validated-header`: format-specific metadata has passed basic bounded structure checks; this does not imply executable trust.
- `structurally-validated`: an Orbis string-table range was mapped within one file-backed `PT_SCE_DYNLIBDATA` segment.
- `syntax-only`: NIDs are printable candidate records; they are not reversibly mapped to plaintext API names and are not proven active imports.
- `unverified-provenance`: a Ghidra inventory was supplied separately; its binary origin is not attested.
- `not-attributed`: network metadata describes a capture session, not the runtime behavior of the ELF.

The `DT_SCE_IMPORT_LIB`/`DT_SCE_NEEDED_MODULE` high 32 bits are preserved as **raw packed metadata** rather than guessed module indices. `DT_NEEDED` is still resolved by the existing standard ELF resolver when valid. The parser does not decode Sony's protected/encrypted executable content.

## Validation and safety

```powershell
python -m unittest discover -s tests -q
python scripts/preflight_offline.py
```

Each binary is bounded to the existing 64 MiB input maximum. The Orbis string table is bounded to 1 MiB, at most 256 name records are materialized, and batch mode refuses more than 32 matching regular files. Reports are created exclusively and are not silently overwritten. No network connections, kernel patches or PS4 interactions occur when invoking these commands.

**Environment limitation:** Ghidra itself is not installed here; the new behavior of `ghidra-run` is exercised using a controlled subprocess mock. Console behavior and live PSN authentication remain untested in v0.14.
