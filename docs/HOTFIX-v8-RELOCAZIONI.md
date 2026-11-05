# Hotfix v8: controllo rilocazioni R_X86_64_RELATIVE

## Evidenza reale

Dopo il trasferimento del BIN compilato localmente a GoldHEN 9090, l'utente ha verificato `192.168.31.11:9021 OPEN` (connessione TCP, non prova di esecuzione). Il `hello_world_official.elf` prodotto con l'SDK PS4 e' stato **bloccato prima dell'invio**, con `SHT_RELA[9] relative relocation addend outside PT_LOAD`.

## Difetto v7 confermato nel sorgente

La specifica ELF x86-64 definisce R_X86_64_RELATIVE come `B + A` (base di caricamento + addend). Il loader PS4 upstream `elfldr.c` usa `loc = base_mirror + r_offset`, `val = base_addr + r_addend`, poi `*loc = val`. Il campo `r_offset` e' la destinazione scritta e deve essere contenuto nel mapping; l'addend e' l'operando che determina il **valore** del puntatore. Non e' corretto rifiutare *automaticamente* l'ELF se l'addend non e' incluso in un intervallo PT_LOAD: un puntatore non interno o un valore sentinella puo' essere legittimo.

La v8 conserva il controllo dell'intera scrittura a 8 byte `r_offset..r_offset+8` dentro PT_LOAD, ma non impedisce a priori addend negativi o esterni. Il report include `relative_addends_outside_load` per segnalare che tali valori non possono essere validati staticamente.

## Test e procedura

1. Aggiornare **solo i sorgenti del progetto**, mantenendo una copia del vecchio codice. Conservare `dist/elfldr.bin` e gli ELF compilati dall'utente; il nuovo archivio non contiene binari.
2. `python -m host.ps4_sender.cli --host 192.168.31.11 --loader elfldr --file dist/hello_world_official.elf --check-elf` (dry run senza rete).
3. Se il controllo conclude con `DRY RUN`, allora valutare l'invio esplicito `--send`; non ripetere se la PS4 si blocca.
4. Se appare un *altro* errore di struttura, fermarsi e ispezionare **l'ELF reale**, senza disabilitare la validazione.

Note: il test statico non garantisce la corretta esecuzione sul firmware PS4 12.52 e non implementa firmware spoofing. Una porta 9021 aperta dimostra solo un listener TCP.

Riferimenti: https://github.com/ps4-payload-dev/elfldr/blob/v0.7/elfldr.c ; https://github.com/ps4-payload-dev/elfldr/releases/tag/v0.7
