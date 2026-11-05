# Rapporto di revisione del codice — fwSpoofer 0.3.0

Data: 5 novembre 2026. Ambito: sorgenti e script **contenuti nel pacchetto**, non il funzionamento degli exploit né i sorgenti upstream di GoldHEN/BD-JB/elfldr.

## Risultati della verifica locale

- **48 test** Python `unittest` superati. Due di questi compilano e **eseguono realmente i sorgenti C del progetto** usando stub/mock delle API PlayStation, quando esiste `cc`/`gcc`/`clang` su host.
- Verificati `python -m compileall` e `bash -n scripts/*.sh` sul container Linux.
- Trasporto TCP verificato con un listener locale: byte trasmessi identici all'origine, senza header extra.
- Convalida di profilo/porta, file ELF/PIC, file BIN, checksum e input invalidi verificata con test di regressione.
- **PowerShell non eseguito né analizzato con un parser locale** (non presente nel container): la CI GitHub include un controllo dell'AST PowerShell su Windows, da eseguire dopo aver pubblicato il repository. Non attribuire alla CI esiti non eseguiti.
- **Build cross-compiler PS4 non rieseguita qui:** SDK installato nel WSL dell'utente, non presente nel container di revisione. L'utente aveva compilato i due ELF con il proprio SDK in questa conversazione.
- **Test su hardware PS4 non eseguiti.** Le patch del loader upstream non sono verificate rispetto alla specifica console.

## Problemi nel precedente archivio v2 e relative correzioni

1. **Bypass del tipo file tramite `--port`:** `--loader elfldr --port 9090 --file x.elf` poteva inviare byte ELF a GoldHEN; ora viene rifiutato, insieme a porte di altri servizi.
2. **Validator ELF superficiale:** poteva accettare header con segmenti inesistenti o entry point non eseguibile; ora controlla offset/dimensione PT_LOAD, `p_filesz <= p_memsz`, segmento eseguibile dell'entry point e dimensioni tabella.
3. **TOCTOU:** il vecchio sender controllava un file e lo rileggeva per l'invio; ora trasferisce esattamente i byte gia' controllati. Un test sostituisce il file tra lettura e trasmissione e verifica la snapshot ricevuta.
4. **Rinomina ingannevole:** un ELF rinominato `.bin` viene ora rifiutato sia dalla CLI sia dal PowerShell dedicato.
5. **Integrita' del bootstrap:** lo script PowerShell richiede `dist/elfldr.bin.sha256` e impedisce l'invio se il file differisce; la CLI accetta `--expected-sha256` e ricontrolla la snapshot.
6. **Timeout:** `nan` e infinito ora rifiutati in CLI, diagnostica e Klog.
7. **Riavvio della build upstream:** `setup_elfldr.sh` tollera file non tracciati prodotti dalla compilazione, continuando a impedire la sovrascrittura di file sorgente tracciati modificati.
8. **API firmware:** la documentazione OpenOrbis definisce una struttura da 0x28 byte; altre implementazioni includono un campo finale. Il buffer reale ora e' 0x30 byte, e il campo `size` resta 0x28. Questo limita il rischio di overflow da rappresentazioni diverse, ma **non prova il comportamento di tutte le versioni firmware**.

## Riproduzione dei controlli locali

In PowerShell nella cartella estratta:

```powershell
python -m unittest discover -s tests -v
python -m compileall -q host tests
```

In Ubuntu/WSL (test script e C):

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q host tests
for script in scripts/*.sh; do bash -n "$script" || exit 1; done
sha256sum -c SHA256SUMS.txt
```

La build dei payload PS4 richiede lo SDK disponibile sul tuo WSL:

```bash
bash scripts/build.sh
```

**Non** usare questi risultati come conferma della sicurezza di `elfldr.bin`, della riuscita dell'exploit o di un runtime non eseguito sulla console.

## Fonti del layout firmware

- OpenOrbis, dichiarazione e layout `OrbisKernelSwVersion`: https://github.com/OpenOrbis/OpenOrbis-PS4-Toolchain/blob/master/include/orbis/_types/kernel.h
- Esempio PS4 `sceKernelGetSystemSwVersion` di John Törnblom: https://github.com/john-tornblom/tiny-ps4-shell/blob/master/commands/uname.c
- SDK: https://github.com/ps4-payload-dev/sdk (FW 12.50/12.52 ancora senza conferma pratica nel README alla data di verifica)
