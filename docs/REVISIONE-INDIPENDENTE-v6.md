# Revisione indipendente v0.6.0 — 5 novembre 2026

## Perimetro e metodo

Sorgente: ZIP v0.5.0 estratto realmente dal container, non una sua descrizione.
Riferimenti: sorgenti `ps4-payload-dev/elfldr` tag `v0.7` (`elfldr.c`, `socksrv.c`, `bootstrap-bin.c`), SDK PS4, repository GoldHEN e HENloader LP. In questa revisione NON si e' acceduto alla console e NON si e' provato il firmware 12.52.

## Difetti dimostrati e corretti

1. **False success `hello_world`:** con mock PS4 che ritornava -1 dalla API di notifica il vecchio main restituiva 0. Ora restituisce 1 e il test C controlla entrambi i casi.
2. **Byte in coda sull'ELF:** il reader v0.7 usa le sezioni ELF per determinare il numero di byte da ricevere. Il validator della v5 accettava un ELF di 261 byte che il reader avrebbe terminato di leggere al byte 240; gli ulteriori 21 byte potevano contaminare stdin del processo. Ora rifiutati prima della connessione.
3. **Porte personalizzate non intenzionali:** `--port 12345` permetteva di inviare raw ELF a qualunque servizio TCP della LAN privata. Il profilo ELF ora richiede una scelta esplicita `--allow-custom-elfldr-port`. Le porte di altri servizi PS4 restano vietate.
4. **Addend di rilocazione:** i `R_X86_64_RELATIVE` dell'ELF SDK-style che puntano al di fuori del segmento caricato non sono accettati nel profilo statico. La restrizione e' conservativa.
5. **SHA-256 di staging non autentica la sorgente:** la v5 poteva inviare un BIN qualsiasi con uno SHA sidecar creato localmente, perche' l'hash confermava solo che non fosse cambiato. Ora PowerShell riconosce la release v0.7 verificata dal digest ufficiale e chiede `-AllowCustomLoader` per altri BIN all'atto dell'invio. La modalita' dry-run e' mantenuta.

## Verifiche eseguite

- `python3 -m unittest discover -s tests -q`: 85/85 superati, tra cui server TCP simulato e C mock.
- `gcc -fanalyzer -Wall -Wextra -Werror -pedantic` sui tre sorgenti C: superato.
- `clang -fsanitize=address,undefined` sui payload con mock host: superato.
- `bash -n` su tutti gli script `.sh`: superato.
- Calcolo SHA-256, verifica manifest e roundtrip ZIP: effettuati alla creazione.

## Rischi residui, da NON confondere con test superati

- **PowerShell:** verifica AST tramite CI predisposta, ma il motore PowerShell non era disponibile nell'ambiente di audit; controllo manuale non equivale a parsing completo.
- **Toolchain WSL:** non e' accessibile l'installazione dell'utente `/home/gabri/ps4-payload-sdk-1252` da questo ambiente, quindi non e' stato rigenerato qui l'ELF PS4.
- **Upstream loader nativo:** `elfldr` v0.7 e' la release piu' recente pubblicata alla data della ricerca; la PR #13 (ottobre 2026) indica problemi di gestione memoria, robustezza del parser e tracciamento errori, ma e' chiusa senza merge. Il validatore locale evita alcune condizioni, non garantisce l'esecuzione della libreria nativa.
- **GoldHEN BinLoader 9090:** esplicitamente sperimentale; esiste un rischio di crash con bootstrap BIN.
- **FW 12.52:** offset presenti nel progetto upstream ma supporto di SDK non marcato come testato nell'upstream README.
- **Spoofing:** non implementato. Il progetto attuale legge il firmware e testa il caricamento ELF; non modifica la versione visibile del sistema.

## Fonti

- https://github.com/ps4-payload-dev/elfldr/blob/v0.7/elfldr.c
- https://github.com/ps4-payload-dev/elfldr/blob/v0.7/socksrv.c
- https://github.com/ps4-payload-dev/elfldr/pull/13
- https://github.com/ps4-payload-dev/sdk
- https://github.com/GoldHEN/GoldHEN
- https://github.com/GoldHEN/henloader_lp
