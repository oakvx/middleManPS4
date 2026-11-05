# Porte, protocolli e feedback remoto — versione 0.6.0

- **9021, elfldr:** invio file **ELF raw** su una connessione TCP. Il sorgente `elfldr` v0.7 (`socksrv.c`) invia sul medesimo socket messaggi d'errore e stdout/stderr del processo avviato. Il sender v0.5 effettua `sendall`, `shutdown(SHUT_WR)` e attende la risposta per un massimo di 5 secondi (configurabile `--response-timeout`, `0` disabilita). La cattura e' limitata a 256 KiB. Nessun byte ulteriore viene anteposto all'ELF.
- **9020:** bootstrap Lua remoto, potenzialmente monouso. Non effettuare probe su questa porta. Alcuni exploit BD-JB espongono listener propri; non sono automaticamente compatibili.
- **9026, Remote Lua Loader:** protocollo Lua, non inviare ELF raw.
- **9090, GoldHEN:** BinLoader sperimentale per codice BIN flat. Per il bootstrap BD-JB e' proposto `elfldr.bin`, ma questa catena non e' stata verificata sulla console dell'utente. Questo profilo NON esegue cattura dell'output come elfldr.
- **3232, GoldHEN Klog:** log di sistema, non necessariamente associato al payload.

**Nuovo vincolo statico:** il parser `elfldr.c` v0.7 riceve inizialmente
`e_shoff + e_shnum * 64` byte e usa le sezioni per stabilire quanti altri
byte leggere. ELF privi di section table, con segmenti non interamente
trasmessi o con target di relocazione fuori immagine ora sono rifiutati
prima di aprire una connessione. Questo non garantisce la compatibilita'
di runtime/SDK.

**Sonde ammesse:** `diagnostics` apre soltanto 9021 o 3232; `klog` soltanto
3232. Le porte 9020, 9026, 9090 non sono mai sondabili da questi script.

Il sender e' in **dry run** di default: senza `--send` nessuna connessione di rete. In dry run valida comunque l'intero ELF; il checksum opzionale `--expected-sha256` e' confrontato prima dell'invio con la stessa snapshot in memoria che viene spedita.

Esempio **offline**:

```powershell
python -m host.ps4_sender.cli --host 192.168.1.5 --loader elfldr --file dist/hello_world_official.elf --check-elf
```

Esempio **solo dopo aver verificato che il server elfldr sia effettivamente attivo**:

```powershell
python -m host.ps4_sender.cli --host 192.168.1.5 --loader elfldr --file dist/hello_world_official.elf --response-timeout 8 --send
```

Una risposta del loader che riporti errore comporta exit code 2. Un trasferimento senza risposta non dimostra esecuzione. Se il programma rimane in esecuzione oltre il timeout, il sender interrompe solo la cattura, non il programma remoto.

### Vincoli aggiuntivi v0.6.0

Un ELF con byte dopo l'ultimo byte richiesto dal reader v0.7 viene rifiutato dal validatore: il loader potrebbe lasciarli in coda sul socket che passa poi al processo figlio come input standard. Le relocazioni relative con addend fuori dai segmenti PT_LOAD vengono respinte dal profilo statico restrittivo. Una porta diversa da 9021 richiede `--allow-custom-elfldr-port`; i porti del bootstrap e di GoldHEN restano comunque proibiti. I controlli sono preventivi e non garantiscono che il loader non fallisca.

### Protezioni aggiuntive v0.7.0

Un invio **GoldHEN 9090** non può essere attivato dalla sola `--send` sulla CLI Python: richiede `--accept-bootstrap-risk` e `--expected-sha256 HASH`; per un BIN diverso dalla release ufficiale `elfldr` v0.7 richiede anche `--allow-custom-bin`. Lo script `bdjb_send_elfldr.ps1` inoltra queste opzioni solo dopo i controlli locali e le conferme richieste.

Con `elfldr` 9021, un fallimento nel ricevere la risposta restituisce **exit code 3**; un errore esplicito del loader restituisce **exit code 2**; un invio senza risposta non prova l'esecuzione. I messaggi visualizzati restano fondamentali per capire lo stato del test.
