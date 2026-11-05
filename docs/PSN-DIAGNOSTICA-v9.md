# Diagnostica PSN v9 — PS4 12.52 + GoldHEN

## Stato sperimentale

Sulla console dell'utente sono stati verificati l'avvio di `elfldr` 9021 e l'esecuzione reale di `firmware_info.elf`, con lettura `12.520.001` (`0x12520001`), messaggio a schermo e output remoto. L'accesso PSN viene però deviato alla richiesta di aggiornamento del software di sistema. Questo comportamento **non** dimostra che il controllo sia esclusivamente locale.

Questa prima diagnostica serve a **raccogliere indizi senza patchare** il kernel e senza inviare payload sulla porta 9021. **Non consente l'accesso PSN e non ne elude i controlli.**

## Prerequisiti

- La PS4 con GoldHEN è già in esecuzione e raggiungibile via LAN all'indirizzo IP attuale `192.168.31.11`.
- GoldHEN **Klog Server** è abilitato sulla porta TCP `3232`, se disponibile nel proprio menu. Non va confuso con il BinLoader `9090` o `elfldr` `9021`.
- Il programma Python sul PC non richiede WSL né recompilazione, poiché usa soltanto la libreria standard.

Da PowerShell nella cartella `C:\Users\gabri\Desktop\projects\fwSpoofer`:

```powershell
python -m host.ps4_sender.psn_diag --host 192.168.31.11 --seconds 45
```

1. Attendere la riga `IN ASCOLTO`.
2. Sulla PS4 tentare **una sola volta** l'accesso a PlayStation Network e osservare la richiesta di aggiornamento, senza confermare l'aggiornamento.
3. Attendere la scadenza dei 45 secondi, poi conservare il riepilogo dei contatori e gli eventuali codici di errore.
4. Annotare separatamente il testo preciso della richiesta di aggiornamento e se si è arrivati alla schermata delle credenziali.

Se compare `ERRORE KLOG` o la connessione viene chiusa subito, controllare l'opzione **Klog Server** di GoldHEN. **Non** provare porte differenti a caso e **non** inviare di nuovo `elfldr.bin`.

## Sicurezza e interpretazione

- Lo strumento si connette **esclusivamente in lettura** al Klog TCP 3232; non trasmette payload e non modifica la PS4.
- I log integrali **non vengono mostrati, salvati o richiesti**. Contengono potenzialmente email, token o identificativi: non condividerli.
- Vengono emessi soltanto contatori delle righe con riferimenti a PSN/NP, aggiornamenti, rete e codici di errore `NP-/WS-/CE-...` (senza testo originale). I codici possono provenire da eventi estranei al PSN.
- Un Klog vuoto è un risultato **inconcludente**: i log del kernel non garantiscono visibilità sui controlli applicativi o sul traffico cifrato.
- Anche in presenza di messaggi update/PSN, la sola correlazione temporale non prova che il controllo sia locale o server-side.
- Senza credenziali, senza intercettazione HTTPS, senza alterazione del traffico e senza accesso ai server Sony.

## Dati da riportare nel prossimo controllo

Riepilogo prodotto dal comando, comportamento sullo schermo della PS4, eventuale codice di errore. Se non vengono registrate righe, lo dichiariamo esplicitamente: non si deduce nulla sull'origine del blocco.
