# Revisione v7 — verifiche riproducibili (05/11/2026)

## Materiale analizzato

L'archivio della precedente release v6 e il suo contenuto effettivo sono stati ispezionati; gli 85 test preesistenti sono stati eseguiti, tutti con risultato OK. La verifica del flusso di invio ha trovato due comportamenti riproducibili, non intercettati dai test.

## Difetto 1: invio BIN rischioso con bypass del wrapper

Nella v6 i controlli di consenso e provenienza erano presenti in `scripts/bdjb_send_elfldr.ps1`, ma non in `host/ps4_sender/cli.py`. Chi eseguiva direttamente la CLI Python con `--loader goldhen --send` poteva trasmettere qualsiasi `.bin` senza avere controllato hash né consenso di rischio. Test con `unittest.mock` dimostra che `send_payload` veniva chiamata e l'exit code era 0.

Nella v7 l'invio **GoldHEN** tramite CLI richiede tutti i seguenti flag: `--send`, `--accept-bootstrap-risk` e `--expected-sha256 HASH`. Se il file BIN non è identico al `elfldr.bin` v0.7 ufficiale (SHA-256 `9525dc95393ab943758db69a1f49fea6e82f36f2821bf5f41bc00bfc4d6f75df`), richiede anche `--allow-custom-bin`. I dry-run restano eseguibili senza consenso e senza rete. Il wrapper PowerShell viene aggiornato per trasmettere automaticamente questi flag soltanto in presenza dei consensi espliciti.

**Questa protezione limita errori operativi, non certifica che un BIN ufficiale sia compatibile con la PS4.** Il checksum ufficiale si riferisce alla release GitHub `ps4-payload-dev/elfldr` v0.7.

## Difetto 2: exit code fuorviante dopo errore del socket di risposta

Nella v6 una `TransferReport.response_error` (es. `connection reset by peer`) mostrava una sola avvertenza e lasciava `exit 0`. Un chiamante automatizzato interpretava il risultato come operazione completata benché il feedback remoto fosse inaffidabile. Nella v7: errori di risposta => `exit 3`; messaggi espliciti `[elfldr.elf] Error...` => `exit 2`; invio TCP senza messaggio remoto e senza errori => `exit 0` ma **nessuna prova di esecuzione**. Un timeout di cattura normale non significa da solo che il payload abbia fallito.

## Prove eseguite localmente

- 96 test Python (inclusi 11 regressioni v7) superati.
- Test end-to-end TCP su `127.0.0.1` con un server mock, senza accesso alla PS4.
- Parsing Python e `bash -n` per gli script shell.
- Sorgenti C compilati con Clang + ASan/UBSan, con API PS4 simulate; nessuna segnalazione negli scenari verificati.
- Archivio estratto ex novo e SHA256SUMS validati, seguiti dalla procedura `python scripts/preflight_offline.py`.

## Verifiche impossibili qui, da non dare per fatte

- Esecuzione di `scripts/build.ps1` nella tua PowerShell e della toolchain `/home/gabri/ps4-payload-sdk-1252` nel tuo WSL.
- Esecuzione dell'ELF o del bootstrap BIN su firmware 12.52.
- Conferma che GoldHEN 2.4b18.7 esegua `elfldr.bin` via 9090 e che il server 9021 parta.
- Spoofing del firmware: **non implementato** nel progetto (esiste solo lettura della versione).

## Fonti

- `elfldr` v0.7: https://github.com/ps4-payload-dev/elfldr/tree/v0.7
- Sorgente reader ELF: https://github.com/ps4-payload-dev/elfldr/blob/v0.7/elfldr.c
- GoldHEN, BinLoader sperimentale: https://github.com/GoldHEN/GoldHEN
- PS4 Payload SDK: https://github.com/ps4-payload-dev/sdk

**Conclusione operativa:** usare questa v7 come base per il preflight in WSL. Nessun invio alla PS4 finché il bootstrap della specifica configurazione non è convalidato.
