# middleManPS4 v0.13.0 — Dynamic ELF / NID / Ghidra Bridge

**Purpose:** repeatable, read-only reverse engineering of local ELF/Orbis metadata and function inventories. Python 3.11+; Ghidra is optional and installed independently. The toolkit never signs into PSN, replaces HTTPS certificates, patches firmware, or reads/decrypts SELF contents.

## Findings from external documentation

- OpenOrbis **PS4 ELF Specification**: PS4 ELF-specific `e_type` values: `0xFE00=ET_SCE_EXEC`, `0xFE10=ET_SCE_EXEC_ASLR`, `0xFE18=ET_SCE_DYNAMIC`. `PT_SCE_DYNLIBDATA=0x61000000`, `PT_SCE_RELRO=0x61000010`. https://github.com/OpenOrbis/OpenOrbis-PS4-Toolchain/wiki/PS4-ELF-Specification
- OpenOrbis **Dynlib Data**: NID string entries typically encode an 11-character digest plus `#library#index` in a 16-byte NUL-terminated record. Hash-looking strings are **not proof of imports**. https://github.com/OpenOrbis/OpenOrbis-PS4-Toolchain/blob/master/docs/MD/OELF%20Specification/PS4%20ELF%20Specification%20-%20Dynlib%20Data.md
- Ghidra **headless documentation**: `analyzeHeadless` supports `-import`, `-scriptPath` and `-postScript`. https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/RuntimeScripts/support/analyzeHeadlessREADME.md
- Ghidra **FunctionManager API**: program functions, and external functions, can be enumerated for inventory. https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/FunctionManager.html

## Implemented modules

| Command | Behavior | Notes |
|---|---|---|
| `binary FILE` | ELF/SELF header validation | Corrected OpenOrbis `e_type` labels, included `PT_SCE_RELRO` |
| `orbis FILE` | Read PT_DYNAMIC and label regular / Orbis-specific tags | `DT_NEEDED` is resolved **only** when a valid standard ELF virtual address/string table mapping exists; Sony-specific module IDs are intentionally kept as raw values |
| `nids FILE` | Parse syntactically valid NID-shaped strings and decode index characters | **Candidate matches only**; does not establish that bytes belong to a valid Orbis string table |
| `ghidra-plan FILE ...` | Validate ELF + paths and emit a headless Ghidra command as JSON | **Dry-run**: does not run Ghidra |
| `ghidra-run FILE ...` | Explicitly run the external Ghidra binary, emit result/error summary | Builds and runs Ghidra locally; no shell, timeout 10m, does not overwrite report |
| `ghidra-summary FILE` | Summarize Ghidra JSON export | Bounds-checks input, no decompiler body or arbitrary binary strings |
| `ghidra-diff A B` | Compare Ghidra function name inventories | Name comparison only; not a code-diff or semantic proof |

The earlier `psf`, `symbols`, `net` and `net-diff` commands remain available.

## Use on Windows PowerShell

Run from the repository root:

```powershell
python -m host.ps4_sender.rekit orbis .\dist\firmware_info.elf
python -m host.ps4_sender.rekit nids .\dist\firmware_info.elf
```

For Ghidra, first download Ghidra independently from https://github.com/NationalSecurityAgency/ghidra/releases and install a supported Java runtime as directed by the release notes. In the example below, replace the Ghidra path with your actual installation directory. **The project directory must already exist, and the JSON report must not exist yet.**

```powershell
New-Item -ItemType Directory -Force .\ghidra-projects | Out-Null
New-Item -ItemType Directory -Force .\reports | Out-Null

python -m host.ps4_sender.rekit ghidra-plan .\dist\firmware_info.elf `
  --ghidra-home "C:\Tools\ghidra_12.0.4_PUBLIC" `
  --project-dir .\ghidra-projects `
  --output .\reports\firmware_info_ghidra.json
```

If the plan looks correct, run the actual analysis:

```powershell
python -m host.ps4_sender.rekit ghidra-run .\dist\firmware_info.elf `
  --ghidra-home "C:\Tools\ghidra_12.0.4_PUBLIC" `
  --project-dir .\ghidra-projects `
  --output .\reports\firmware_info_ghidra.json

python -m host.ps4_sender.rekit ghidra-summary .\reports\firmware_info_ghidra.json
```

If an existing Ghidra project has already imported the same file, headless `-import` may reject a duplicate. Use a new project name or remove the duplicate through Ghidra's own project UI; this tool never force-overwrites a Ghidra project. Ghidra creates its own project files; it does not write to the source ELF.

For two JSON inventories obtained from different ELF builds:

```powershell
python -m host.ps4_sender.rekit ghidra-diff .\reports\before.json .\reports\after.json
```

**Known limits**

- This environment has no Ghidra installation; the Java exporter was written against documented APIs, but **Ghidra runtime integration is not yet validated here**. The headless executable is only called when `ghidra-run` is requested explicitly.
- A stock Ghidra ELF loader does not automatically understand every Orbis metadata structure. Additional PS4-specific loaders/extensions could be needed; never confuse a partial import with fully resolved symbols.
- Ghidra reports can include function names and namespaces. Review before publishing. No passwords, TLS payloads or decrypted source bytes are intentionally exported.
- `ET_SCE_*` identification is determined by ELF headers only, not guaranteed runtime loadability.
- A firmware-version reference in a homebrew payload does not prove how Sony's PSN validates firmware versions.

## Regression

```powershell
python -m unittest discover -s tests -q
python scripts/preflight_offline.py
```

Version 0.13.0: **181/181 offline tests passing** in the preparation environment, with 16 added tests including malformed dynamic tables, SELF rejection, NID structure and Ghidra bridge argument validation. No console runtime test performed.
