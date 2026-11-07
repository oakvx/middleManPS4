# v0.14.0 — Integrated Offline RE Pipeline (2026-11-06)

- Added bounded `rekit.dynlib` for the documented Orbis `PT_SCE_DYNLIBDATA` string table, scoped syntactic NID candidates, and packed library/module string entries.
- Added `rekit.report` for a single-pass ELF/SELF/PSF case, SHA-256 provenance, Ghidra inventory *name* correlation (unverified provenance), and optional sanitized network timeline (*not* attributable to a binary).
- New CLI: `dynlib`, `analyze`, `analyze-diff`, `batch`, and `markdown`, with exclusive file creation and no network/PS4 side effects.
- Ghidra subprocess success now requires valid JSON inventory, not only exit code zero.
- Added 14 integration/regression tests, including malformed Orbis dynamic data, false-positive NID scoping, end-to-end report, batch and Markdown cases. Existing 181 tests retained.
- Ghidra runtime and console PSN behavior remain **unverified**; no firmware spoofing or PSN bypass is implemented.

# v0.13.0 — Orbis ELF & Ghidra Research Bridge (2026-11-06)

- Corrected ELF type label `0xFE10 → ET_SCE_EXEC_ASLR` and `0xFE18 → ET_SCE_DYNAMIC` from OpenOrbis specifications; recognized `PT_SCE_RELRO`.
- Added bounded `rekit.orbis` dynamic table inspection and virtual-to-file resolution of standard `DT_NEEDED` libraries. Orbis-specific tags remain uninterpreted raw values.
- Added `rekit.nids`: candidate NID inventory with file offset and decoded library/module index characters, no plaintext-name assertion.
- Added optional Ghidra Java exporter and headless plan/run bridge with bounded JSON inventory, read-only function and external symbol listing, run-on-explicit-command and non-overwrite safeguards.
- Added offline Ghidra summary and inventory name-diff commands, 16 additional regression tests: 181 passing on the current snapshot.
- Tested `dist/firmware_info.elf` parser on the included build; `DT_NEEDED`: `libkernel_web.sprx`, `libSceLibcInternal.sprx`, `libSceNet.sprx`.
- Ghidra runtime **not** tested (not installed in preparation environment). No PS4 runtime, firmware spoofing, PSN sign-in or interception bypass implemented.

# v0.12.0 — Offline Reverse Engineering Toolkit (2026-11-06)

- Added `host.ps4_sender.rekit` with read-only modules: generic ELF/Orbis/SELF header identification, bounded raw PSF parser, conservative Orbis-style symbol/NID candidate scanner, and five-second network metadata correlation.
- New CLI: `python -m host.ps4_sender.rekit {binary,psf,symbols,net,net-diff}`.
- Added 23 offline unit/CLI tests (165 total, all passing on the current snapshot), documentation, source references, and checksum manifest refresh.
- Verified with the project's included `firmware_info.elf`: `sceKernelGetSystemSwVersion` and several `libSce*.sprx` strings detected.
- No PS4 runtime testing, firmware spoofing, SELF decryption, PSN authentication modification, or bypass.

# v0.11.0 — Verifica visibilita traffico Internet PS4 (2026-11-06)

- Contatori IPv4 completi nella diagnostica TShark, anche per ICMP, UDP e pacchetti senza metadati DNS/TLS.
- Distinzione tra solo traffico LAN e pacchetti PS4 verso IP pubblici; non confonde il ping con l'osservazione del percorso Internet.
- `psn_triage` segnala lo stato `capture_visibility` e mantiene compatibilita con i JSON v0.10, per cui la visibilita resta `not_measured`.
- Sei test di regressione aggiuntivi: suite offline di 142 test superata.
- Nuovo runbook `docs/PSN-VISIBILITY-v11.md` con due topologie riproducibili: hotspot Windows o condivisione Wi-Fi → Ethernet.
- Nessuna modifica a rete reale, TLS, autenticazione PSN, firmware o kernel.

# v0.10.0 — PSN NetLab: osservazione passiva e confronto (2026-11-05)

- Modulo `psn_netdiag`: cattura e analisi DNS/TLS metadata via TShark, file PCAP temporanei eliminati al termine.
- Modulo `psn_tunnel`: proxy CONNECT opzionale, inoltro cifrato senza lettura/modifica dati applicativi.
- Nuovo `psn_triage`: confronto offline baseline/tentativo PSN, senza inferenze improprie da catture vuote.
- Documentazione operativa e di privacy `docs/PSN-NETLAB-v10.md`.
- Non implementa bypass PSN, modifica richieste autenticazione o patch kernel.

# v0.9.0 — Diagnostica PSN passiva (2026-11-05)

- Aggiunto `host.ps4_sender.psn_diag`: ascolto passivo GoldHEN Klog TCP 3232 senza invii, kernel patch o richieste PSN automatiche.
- I log grezzi non vengono scritti su disco o stampati; il programma emette soltanto contatori di categorie e codici di errore.
- La diagnostica è esplicitamente inconcludente per l’origine locale/remota del controllo di aggiornamento, anche quando non sono presenti righe nel Klog.
- Otto test aggiuntivi per filtraggio privacy, dati frammentati, argomenti invalidi, porta unica 3232, connessione chiusa e streaming non terminato.
- L’utente ha confermato sul proprio hardware la notifica `Hello World` e l’esecuzione di `firmware_info.elf` (`0x12520001`), indipendentemente da questa release. Lo spoofing e l’accesso PSN senza aggiornare non sono stati realizzati.

# v0.8.0 — Hotfix ELF relocation check (2026-11-05)

- Removed the invalid hard rejection of `R_X86_64_RELATIVE` addends outside PT_LOAD; only the memory *write target* must be inside a loaded segment. Non-internal addends are still counted and reported.
- Updated the v7 regression tests to reflect ELF relocation semantics; new targeted v8 regressions.
- `bdjb_send_elfldr.ps1` now suggests diagnostics for the actual `-Ps4Ip` argument and defaults to the user's current PS4 address.
- No PS4 runtime test has been performed by this release; the user confirmed a TCP listener on PS4:9021 after sending a locally built BIN. No ELF payload has yet been executed.

# 0.7.0 — Audit di regressione con prove negative, 05/11/2026

- **Difetto riprodotto nella v6:** richiamando direttamente `python -m host.ps4_sender.cli --loader goldhen --file arbitrary.bin --send`, il programma invocava il trasferimento SENZA il consenso `-AcceptRisk` e SENZA alcun checksum; i controlli erano solo nel wrapper PowerShell. Ora qualsiasi invio BIN tramite il sender Python richiede `--accept-bootstrap-risk`, `--expected-sha256` e, se non corrisponde allo SHA ufficiale di `elfldr` v0.7, anche `--allow-custom-bin`. Il wrapper PowerShell inoltra le opzioni corrispondenti.
- **Difetto riprodotto nella v6:** una risposta del loader terminata con `response_error="connection reset by peer"` produceva exit code `0`, inducendo i sistemi automatici a considerare completato il collaudo del canale. Ora restituisce exit code `3`. Gli errori di caricamento espliciti prodotti da `elfldr` restano exit code `2`; il solo trasferimento TCP senza risposte continua a NON provare esecuzione.
- Aggiunti 11 test negativi/positivi in `tests/test_regression_v7.py`; **96 test locali superati**.
- Sintassi Python e Bash verificata, C con mock delle API PS4 compilato ed eseguito con Clang ASan+UBSan senza segnalazioni negli scenari testati.
- Riscontro con documentazione GoldHEN: BinLoader 9090 resta esplicitamente sperimentale; nessuna conferma riproducibile sulla catena specifica `BD-JB / GoldHEN 2.4b18.7 / elfldr v0.7 / FW 12.52`.
- **Non testato:** PowerShell runtime sulla macchina dell'utente, compilazione cross con SDK PS4 in WSL, PS4 reale e spoofing firmware (non ancora implementato).

# 0.6.0 — Audit ripetuto indipendente, 05/11/2026

- Corretto `hello_world`: l'exit status ora segnala il fallimento della notifica (regressione coperta da mock C).
- Rifiutati ELF con byte di coda non consumati dal reader nativo `elfldr` v0.7 (pericolo di stdin non intenzionale).
- Rifiutati addend di relocation `R_X86_64_RELATIVE` fuori dai segmenti mappati dal profilo statico.
- Un `--port` ELF personalizzato richiede ora `--allow-custom-elfldr-port`; continuano i divieti su 9020, 9026, 9090 e 3232.
- Il comando PowerShell ora distingue `integrita'` da `provenienza`: BIN ufficiale v0.7 con hash pinned, BIN locale solo con `-AllowCustomLoader` quando si invia.
- Nuovi test per ogni caso, 85 test passati; GCC `-fanalyzer`, clang ASan/UBSan e bash -n verificati.
- Confronto con PR upstream elfldr #13: chiusa e non integrata; la release v0.7 conserva il relativo limite.
- L'hardware FW 12.52 non e' stato provato. Lo spoofing non e' stato implementato.

## 0.5.0 — 2026-11-05 — revisione indipendente del parser e sonde TCP

- Rilevati e riprodotti due falsi positivi: ELF senza section table e con `PT_LOAD` a indirizzo virtuale non-zero erano dichiarati validi ma non rispettavano le assunzioni interne di `elfldr.c` v0.7.
- Riprodotto il vincolo di lettura upstream: il parser nativo legge fino a `e_shoff + e_shnum * 64`, estendendo alla fine dei contenuti delle sezioni referenziate; il validatore ora verifica che **tutti i segmenti utilizzati** siano inclusi nei byte effettivamente letti.
- Aggiunti controlli dei target di rilocazione `R_X86_64_RELATIVE` (scrittura di 8 byte all'interno dei segmenti caricati) e limite sulla dimensione dell'immagine di memoria, tenendo conto di tutti i program header.
- Rivisti gli ELF sintetici dei test: ora contengono una section table reale; prima erano input incompatibili con il reader upstream, pur superando la suite.
- Eliminato un rischio operativo: Klog non puo' aprire porte diverse dalla 3232 e `diagnostics` non sonda bootstrap/binloader (9020,9026,9090). La diagnostica esegue una sola sonda 9021 per default.
- Aggiunta integrazione TCP che simula la lettura esatta dell'ELF come nel sorgente upstream, e test negativi su header, sezioni, memoria e rilocazioni.
- Test locali: 80 unit/integration (inclusi test C con API simulate), script Bash `bash -n`, sorgenti C eseguiti con AddressSanitizer e UndefinedBehaviorSanitizer senza segnalazioni negli scenari testati.
- Ambiti non collaudati: PowerShell in esecuzione reale, toolchain PS4 WSL dell'utente, bootstrap/loader su GoldHEN 12.52, spoof firmware (non implementato).

## 0.3.0 — 2026-11-05: revisione del codice e test estesi

- Eliminata la possibilita' di inviare ELF alla porta GoldHEN 9090 aggirando il controllo mediante `--port`.
- Bloccata esplicitamente 9020 nel sender generico e riservate le porte dei servizi diversi.
- Resa obbligatoria la validazione strutturale ELF prima di `--send`; ora include intervalli di segmento ed entry point eseguibile.
- Bloccato l'invio di un ELF rinominato `.bin`.
- Eliminato il TOCTOU file-check/file-send: il sender trasmette la stessa snapshot di byte validata.
- Aggiunta l'opzione `--expected-sha256`; lo script PowerShell verifica hash e dimensione prima del bootstrap.
- Protetto il buffer di `sceKernelGetSystemSwVersion` (0x30 allocati, lunghezza API 0x28 secondo OpenOrbis).
- Sistemato lo script per rieseguire `setup_elfldr.sh` dopo una build con file generati non tracciati.
- Validazione `NaN`/`infinity` per i timeout; aggiunti test C con mock delle API PS4.
- Aggiunta CI multipiattaforma con analisi di sintassi Bash e PowerShell e test Python/C.
- **Nessun test su PS4 reale, nessuna garanzia runtime.** Vedi `docs/VERIFICA-CODICE.md`.

## 2026-11-05 — variante BD-JB / Poops
- Presa in carico la conferma utente: BD-JB su FW12.52.
- Documentato percorso sperimentale GoldHEN 9090 BIN -> elfldr 9021 ELF con guardrail.
- Aggiunto stage del `elfldr.bin` upstream e PowerShell DRY RUN / invio opt-in.
- Bloccato invio `.elf` sul profilo GoldHEN dal sender CLI.
- Nessuna affermazione di compatibilita hardware non verificata.

# Changelog

## 0.2.0 — 2026-11-05

- Ripristinato progetto completo dall’archivio `fwSpoofer_firmware_info_fase4.zip`.
- Impostato SDK predefinito di WSL per PS4 FW 12.52.
- Implementati build/verifica riproducibili e controllo della struttura ELF.
- Implementato sender raw TCP con `elfldr:9021` predefinito e `goldhen:9090` opzionale.
- Implementati diagnostica porte (9020 esclusa), acquisizione Klog e test host.
- Integrati script opt-in per clone/build elfldr e remote_lua_loader, invio Lua e bootstrap.
- Documentati vincoli di compatibilita, Klog, crash pregressi, safe testing.
- Nessun binario PS4 precompilato nello ZIP; nessuno spoof firmware/PSN.

## 0.4.0 — 2026-11-05 — audit offline aggiuntivo

- Corretto il protocollo su `elfldr` 9021: mantiene aperta la lettura TCP per l'output e gli errori del payload, con half-close di scrittura, timeout configurabile e limite 256 KiB.
- Il codice CLI segnala esplicitamente errori di spawn/lettura restituiti dal loader.
- Il dry-run ora valida **sempre** l'ELF, non solo la sua estensione.
- Aggiunti controlli dei section header e sezioni `SHT_RELA` al validatore ELF.
- Aggiunto script opzionale `scripts/fetch_official_elfldr.py --download` con SHA-256 e dimensione ufficiali fissati.
- **64 test**: più test TCP reali, simulazione errore remoto, verifica di ELF PIE autentico e 1.500 input mutati.
- Rapporto di audit e limiti documentati in `docs/VERIFICA-AGGIUNTIVA-v4.md`.
