# Audit indipendente v0.4.0 (5 novembre 2026)

## Risultati verificati localmente, senza PS4

- **64 test Python/C**, includendo: mock API PS4, trasporto con server TCP locale, output ed errori di `elfldr`, protocollo half-close, timeout, output massimo 256 KiB, SHA-256, download ufficiale simulato, struttura ELF, un vero PIE ELF compilato con GCC, 1.500 mutazioni deterministiche di un header ELF.
- `python scripts/preflight_offline.py` esegue in un solo passaggio controlli offline e checksum dell'archivio.
- `python -m compileall` per Python e `bash -n` per script Bash; l'intero archivio ZIP viene verificato all'atto della creazione.
- Un vero ELF PIE Linux prodotto da GCC passa `elfcheck`. **Non** e' una compilazione per PS4 o una simulazione dell'ABI PlayStation.
- Script `fetch_official_elfldr.py` non contatta Internet senza `--download`; per la release ufficiale 0.7 verifica SHA-256 e dimensione **prima di creare o sostituire** `dist/elfldr.bin`.

## Errori della v3 corretti nella v4

### 1. Feedback runtime scartato

La v3 usava `socket.sendall` e chiudeva immediatamente la connessione. Il sorgente `ps4-payload-dev/elfldr` tag `v0.7` (`socksrv.c`, `on_connection`) usa lo **stesso socket** per inviare errori di parsing/spawn e per l'output standard del processo avviato. Per questo il sender v3 non poteva distinguere un errore dichiarato da un invio apparentemente riuscito.

Nella v4 l'invio di ELF su `elfldr`:

1. trasmette gli stessi byte validati e pinnati via SHA-256;
2. esegue `shutdown(SHUT_WR)` mantenendo aperta la lettura;
3. legge risposte fino a chiusura o limite `--response-timeout` (5 s default, 0 per disattivare);
4. limita la risposta a 256 KiB;
5. segnala errore se riceve il testo `[elfldr.elf] Error ...` o `Unknown payload`.

**Attenzione:** anche una risposta positiva non prova necessariamente che tutte le operazioni del payload siano terminate correttamente; se il server non invia alcun output, il report non prova successo ne' fallimento.

### 2. Sezioni ELF non controllate

La v3 controllava soprattutto i segmenti PT_LOAD. La v4 verifica la tabella SHT e i bounds delle sezioni sul file, e rifiuta SHT_RELA con estensione oltre il file o entry size errato. Questi controlli riducono i rischi di inviare file malformati al parser upstream, **non sostituiscono** una revisione completa del loader nativo.

### 3. Binario upstream non attestato

La v3 usava esclusivamente un build locale dell'SDK per produrre `elfldr.bin`. Il nuovo script `scripts/fetch_official_elfldr.py` consente di scaricare la release ufficiale v0.7 e applicare la verifica SHA-256 fornita da GitHub: `9525dc95393ab943758db69a1f49fea6e82f36f2821bf5f41bc00bfc4d6f75df`, lunghezza 261.012 byte. Non e' necessario ricompilare il loader a mano per avere un asset identico alla release ufficiale.

## Ricerca: importanti limitazioni upstream

- `ps4-payload-dev/sdk` README: firmware 12.50 e 12.52 ancora indicati come **non testati** (checklist aperta). Sorgenti con offset 12.52 non equivalgono a supporto pratico dimostrato.
- `ps4-payload-dev/sdk` issues #11 e #12: precedenti incompatibilita' su BD-JB 12.50/12.52, con report discordanti tra SDK e pacbrew. Si riferiscono a BinLoader.java/aiofix, **non** dimostrano che il nuovo sender o `elfldr.bin` falliscano o funzionino.
- `GoldHEN/GoldHEN` README: BinLoader 9090 e' esplicitamente **sperimentale**.
- `ps4-payload-dev/elfldr` README v0.7: deployment documentato con **remote_lua_loader** e bootstrap su 9020, server ELF poi su 9021. Il nostro percorso **BD-JB → GoldHEN 9090 → elfldr.bin** non e' una procedura di compatibilita' ufficialmente garantita.
- `GoldHEN/henloader_lp`: Poops per 12.50/12.52. Le diverse ISO/fork BD-JB non sono intercambiabili a priori.

## Non verificati e non certificabili offline

1. PowerShell: non esiste `pwsh` nel container di audit; l'AST parser e' predisposto in CI Windows, ma non e' stato eseguito qui.
2. Build PS4: SDK/WSL privati dell'utente non accessibili nel container.
3. `elfldr.bin` caricato da GoldHEN sulla porta 9090 in quel particolare firmware.
4. Avvio del server 9021, esecuzione `_start()` e `main()` sulla console, notifica effettiva.
5. Firmware spoofing: **non implementato** (solo lettura del firmware e notifica).

### Fonti

- https://github.com/ps4-payload-dev/sdk/blob/main/README.md
- https://github.com/ps4-payload-dev/sdk/issues/11
- https://github.com/ps4-payload-dev/sdk/issues/12
- https://github.com/ps4-payload-dev/elfldr/blob/v0.7/socksrv.c
- https://github.com/ps4-payload-dev/elfldr/releases/tag/v0.7
- https://github.com/GoldHEN/GoldHEN/blob/master/README.md
- https://github.com/GoldHEN/henloader_lp/releases/tag/1.0
