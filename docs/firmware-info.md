# firmware_info: lettura read-only della versione PS4

Il file `payloads/common/src/fw_info.c` usa `sceKernelGetSystemSwVersion` per riempire una struttura API 0x28 byte, allocando un buffer di 0x30 byte per proteggersi da eventuali campi finali riservati in altre definizioni, poi produce un messaggio su schermo con la stringa/versione raw. Controlla `fw_info_status` e gestisce buffer e errori.

Questo payload **non modifica la versione** e non aggiunge bypass PSN. La compilazione gia' riuscita e' un risultato lato toolchain; l'esecuzione con `elfldr` resta da verificare sulla console **dopo il sample ufficiale e il payload hello_world**.
