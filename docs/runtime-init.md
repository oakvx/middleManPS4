# Analisi del percorso di inizializzazione del runtime

L'ELF viene compilato con il CRT dello SDK. `_start` puo' richiamare routine equivalenti a `__klog_init`, `__kernel_init`, `__rtld_init` e `__patch_init` **prima di `main()`**. Di conseguenza una mancata notifica custom non implica che `main` sia errato; il processo puo' interrompersi gia' nel loader, nelle relocazioni o nel CRT.

## Analisi non invasiva

```bash
PS4_PAYLOAD_SDK="$HOME/ps4-payload-sdk-1252" bash scripts/build.sh
llvm-readelf-18 -h -l -d dist/hello_world.elf
llvm-readelf-18 -sW dist/hello_world.elf | grep -E 'UND|_start|main' || true
llvm-objdump-18 -d dist/hello_world.elf | grep -A45 '<_start>:' || true
```

Per controllare il sorgente del CRT associato al SDK installato, confronta il checkout di origine:

```bash
find "$HOME/ps4-payload-sdk-src/crt" -maxdepth 1 -type f -print
rg '0x1252|0x12520000|__klog_init|__kernel_init|__rtld_init|__patch_init' "$HOME/ps4-payload-sdk-src/crt" || true
```

Questi controlli rilevano riferimenti e simboli, ma **non** forniscono telemetria su esecuzione nella console. Strumentare il CRT con log di ciascuna fase richiede una build separata dell'SDK e un canale di log funzionante; non introdurremo patch alla console basate su offset ipotetici. Se `elfldr` e sample ufficiale si avviano, eventualmente introdurre instrumentation nel codice applicativo **dopo** aver confermato il baseline.
