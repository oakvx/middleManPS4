# Troubleshooting: FW 12.52 / GoldHEN 2.4b18.7 / elfldr

| Sintomo | Significato piu' probabile | Verifica/azione |
|---|---|---|
| `Missing .../toolchain/orbis.mk` | SDK non trovato in WSL | Verifica `~/ps4-payload-sdk-1252/toolchain/orbis.mk`; passa `PS4_PAYLOAD_SDK=...` |
| `orbis-clang: command not found` | SDK non installato o incompleto | Verifica `~/ps4-payload-sdk-1252/bin/orbis-clang`; ricostruisci SDK dalla repo ufficiale |
| `make: Nothing to be done` | ELF preesistente | `bash scripts/build.sh` usa `make -B`; confronta SHA-256 |
| `ERROR file not found` Windows | `dist/*.elf` non generato o cwd sbagliato | `Get-Location`, `Test-Path .\dist\hello_world.elf`; WSL `bash scripts/build.sh` |
| `ELF CHECK FAILED` | Header/segmenti ELF non validi | `python -m host.ps4_sender.elfcheck --file ...`; ricompila |
| `tcp connect timeout` su 9021 | `elfldr` non partito o rete/firewall | Verifica IP della console e del PC, LAN, e bootstrap; **mai sondare 9020** |
| 9090 mostra solo `Payload received` | Ricezione del file, non esecuzione verificata | Questo e' gia' successo anche col sample ufficiale. Non ripetere; usa bootstrap adeguato e 9021 |
| 9026 CLOSED | Remote Lua non in esecuzione | Configura titolo Artemis + savedata seguendo guida ufficiale; non inviare Lua |
| 9021 CLOSED dopo bootstrap | Primo stadio o `elfldr` fallito | Esamina Klog e ordine 9026 -> bin_loader.lua -> 9020 (singolo invio) -> 9021 |
| 9021 OPEN ma niente notifica | Possibile fault in runtime/init, linking, symbol resolution o notifica | Verifica sample ufficiale, Klog, `llvm-readelf-18 -d -sW -r`, output loader |
| `undefined symbol` / `SPRX` | Stub mancante, SPRX non disponibile o contesto sbagliato | Analizza `NEEDED` e `UND`; segui `sce_stubs` dello SDK, non sostituire SPRX di sistema |
| `copyin: GoldHENLoader has nonsleeping lock` | Avviso kernel sul loader | Registra Klog e fermati con test instabili; da solo non prova la causa del fault |
| `PARTY DAEMON` / `NPXS21002` exception 11 | Crash del daemon registrato | Correlazione non e' causalita'. Salva timestamp e log, riavvio pulito, niente test ripetuti |

## Tre livelli di verifica (non confonderli)

1. **Host:** test Python passano e ELF e' ET_DYN x86-64 con segmenti coerenti.
2. **Trasporto:** la connessione TCP invia tutti i byte; una notifica `Payload received` e' compatibile con un fallimento prima di `_start()`.
3. **Esecuzione:** output Klog/stdio o notifica **propria del sample** prova che il codice e' stato raggiunto; eventuale risultato `sceKernelSendNotificationRequest` verifica l'API.

## Debug runtime

Se il sample ufficiale fallisce su `elfldr`, non modificare il codice applicativo: indagare il loader, il kernel exploit e le patch FW. Se il sample funziona e il payload custom no, controllare dipendenze `NEEDED`, simboli `UND`, relocazioni e funzioni usate in `main()`.

```bash
llvm-readelf-18 -d dist/hello_world.elf
llvm-readelf-18 -r dist/hello_world.elf
llvm-readelf-18 -sW dist/hello_world.elf | grep UND || true
```

Un problema di `crt` puo' interrompere il flusso prima del `main()`. Il runtime dell'SDK configura, in ordine variabile per versione, inizializzazione Klog/kernel/RTLD/patch; vedi `docs/runtime-init.md`. Non e' possibile discriminare lo stadio con la sola notifica di GoldHEN.
