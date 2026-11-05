# Procedura operativa per il tuo BD-JB / Poops (FW 12.52)

**Inizia qui:** `docs/BDJB-1252.md` contiene prerequisiti, rischi, riferimenti e tabella errori. Non seguire il vecchio percorso `remote_lua_loader` se usi soltanto BD-JB.

## A — Preparazione OFFLINE senza PS4

Per prima cosa, su Windows oppure in WSL, nella cartella estratta:

```powershell
python scripts/preflight_offline.py
```

Da WSL (compila i payload e il sample, senza contattare la console):

```bash
cd /mnt/c/Users/gabri/Desktop/projects/fwSpoofer || exit 1
bash scripts/build.sh
bash scripts/compare_sample.sh
```

**Per preparare `dist/elfldr.bin` scegli UNA SOLA strada**:

- **Strada A — binario ufficiale (consigliata per avere esattamente l'asset upstream):** da PowerShell, `python scripts/fetch_official_elfldr.py --download`. Usa HTTPS per scaricare il file, ne controlla la dimensione e lo SHA-256 ufficiale; non si collega alla PS4.
- **Strada B — build dal sorgente:** in WSL esegui `bash scripts/setup_elfldr.sh` e poi `bash scripts/stage_elfldr_bin.sh` (richiede SDK e dipendenze). La compilazione locale puo' dare un hash diverso dalla release ufficiale.

Controlla che esistano `dist/elfldr.bin`, `dist/hello_world_official.elf` e `dist/hello_world.elf`. **Non rinominare ELF in BIN.**

## B — PowerShell: verifica soltanto i file

```powershell
cd C:\Users\gabri\Desktop\projects\fwSpoofer
.\scripts\bdjb_send_elfldr.ps1
```

Senza `-Send` non si connette alla console. Annota checksum SHA256 e dimensione.

## C — Solo dopo che BD-JB / Poops ha caricato GoldHEN ed e' stabile

Opzionale: apri GoldHEN Klog 3232 in un secondo terminale.

```powershell
python -m host.ps4_sender.klog --host 192.168.1.5 --seconds 60
```

Se e solo se scegli consapevolmente di provare il bootstrap flat BIN via GoldHEN 9090:

```powershell
.\scripts\bdjb_send_elfldr.ps1 -Send -AcceptRisk
```

**Non** spedire l'`elfldr.elf` sulla 9090, ne' utilizzare la porta 9020 in assenza di una guida specifica alla tua ISO. Questo percorso non richiede il gioco Artemis o il server Lua 9026.

## D — Verifica 9021

```powershell
python -m host.ps4_sender.diagnostics --host 192.168.1.5 --port 9021 --require-open
```

Se CLOSED, fermati e raccogli Klog. Se OPEN, procedi con **una sola** prova con il sample ufficiale:

```powershell
python -m host.ps4_sender.cli --host 192.168.1.5 --loader elfldr --file dist/hello_world_official.elf --check-elf --send
```

Solo con un comportamento osservabile e corretto prosegui con `hello_world.elf`, e poi `firmware_info.elf`. Il messaggio `TCP transfer completed` non dimostra che `main()` sia partito.

## Note v0.4.0: cattura output del processo su 9021

Il sender ora usa lo stesso socket per leggere stdout/stderr di elfldr e riportare errori espliciti. Per attendere fino a 10 secondi di output dopo il trasferimento usa `--response-timeout 10` solo con il profilo `elfldr`. **Questo non modifica il meccanismo di bootstrap 9090**.
