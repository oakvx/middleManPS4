# Sviluppo payload e priorita' test

Sono preservati dal progetto originale i sorgenti `hello_world` e `firmware_info` e la struttura SDK/Makefile. La compilazione sul PC dell'utente con SDK in `~/ps4-payload-sdk-1252` e' gia' riuscita; la **nuova integrazione con elfldr non e' ancora stata provata sul dispositivo**.

1. Verificare localmente `bash scripts/build.sh` e `python3 -m unittest discover -s tests -v`.
2. Compilare il loader ufficiale `bash scripts/setup_elfldr.sh`.
3. Usare un percorso di bootstrap **supportato dal jailbreak e dal gioco/savedata disponibili**; non assumere che 9090 o 9026 siano intercambiabili.
4. Avviare `elfldr`, verificare che 9021 ascolti, acquisire Klog.
5. Inviare **una sola volta** il sample ufficiale dell'SDK, poi il payload `hello_world`, infine `firmware_info`.
6. Se il sample funziona e i payload custom no, comparare `llvm-readelf-18 -d -sW -r` e simboli importati.

L'header `notify_request_t` viene mantenuto coerente con il sample gia' usato; non e' una certificazione autonoma dell'ABI. `firmware_info` interroga un'API SCE senza patchare kernel o memoria. Il progetto attualmente non implementa alcun firmware spoofing.
