# Revisione indipendente v5 — 5 novembre 2026

## Perché questa revisione era necessaria

Le suite v3/v4 erano troppo concentrate su input sintetici e su successi del
trasporto TCP. In particolare i test v4 generavano file ELF64 con `e_shnum=0`
e `e_shoff=0` e li classificavano validi. Il sorgente **ufficiale** del reader
`elfldr.c` tag **v0.7**, invece, alloca il buffer con
`size = e_shoff + e_shnum * sizeof(Elf64_Ehdr)`; con entrambi i campi a zero,
questo porta a un'allocazione di dimensione zero e poi a una copia di 64 byte.
Un test che accettava questi file NON rappresentava un invio sicuro al loader.

## Problemi trovati e correzioni

1. **Tabella delle sezioni assente:** ora rifiutata prima di aprire il socket;
   per questo loader servono `e_shoff`, `e_shentsize=64`, `e_shnum>=1` e limiti corretti.
2. **Lettura parziale:** l'upstream riceve prima la tabella delle sezioni e poi
   eventualmente altro contenuto delle sezioni. Il validatore calcola il
   numero di byte realmente letti e impedisce che un segmento PT_LOAD o
   PT_DYNAMIC finisca oltre quel limite, anche se e' fisicamente presente nel file.
3. **Mapping native:** l'upstream alloca in base a indirizzi virtuali e dimensioni
   dei program header, ma indicizza sempre a partire da `base+p_vaddr`.
   Ora vengono rifiutati indirizzi minimi non zero, overflow e immagini
   virtuali troppo grandi, compresi gli header non-PT_LOAD.
4. **Rilocazioni relative:** la v4 controllava solo che la sezione SHT_RELA
   fosse nel file. Ora controlliamo anche che ogni write di 8 byte per
   `R_X86_64_RELATIVE` cada entro un PT_LOAD in memoria.
5. **Sonde di rete:** prima Klog consentiva `--port 9020`, e la diagnostica
   predefinita sondava 9026/9090. Klog accetta **solo 3232**; diagnostica
   **solo 9021/3232**; le porte loader non vengono testate con connessioni vuote.
6. **Prove inaffidabili:** gli ELF fittizi dei test sono stati corretti con
   tabella delle sezioni; introdotto anche un server TCP che legge esattamente
   i byte attesi dal reader nativo e quindi non si limita a `recv` fino a EOF.

## Prove locali effettivamente svolte

- 80 test automatici con `python -m unittest discover -s tests -q`.
- Python `compileall` e Bash `bash -n` su tutti gli script .sh.
- Compilazione dei sorgenti C con clang `-Wall -Wextra -Werror -pedantic`
  e test mock eseguiti con `-fsanitize=address,undefined`.
- ELF Linux PIE reale compilato con GCC come prova del parser **generico**,
  non come sostituto di un binario PS4.
- Simulazione locale del contratto di lettura TCP di `elfldr` v0.7.
- 1.500 input ELF mutati nel test di regressione: nessun errore non gestito.

## Cosa i risultati NON certificano

- Nessun binario PS4 e' stato compilato con il tuo SDK WSL in questo ambiente.
- Nessun test e' stato eseguito sulla tua PS4 o su GoldHEN 2.4b18.7.
- `elfldr.bin` via 9090 resta un bootstrap sperimentale **non documentato come
  funzionante su questa combinazione esatta**.
- Non e' stato eseguito un interprete PowerShell nel container: lo script PS1
  dispone di una regola AST in CI Windows, non di una prova locale.
- **Lo spoofing non e' implementato:** `firmware_info` legge la versione e
  restituisce una notifica, senza modificare il firmware riportato.
- L'upstream `ps4-payload-dev/sdk` continua a segnare FW 12.52 come non
  esplicitamente testato. Non si puo' garantire il 100% su hardware solo con
  test host, e non sarebbe serio dichiararlo.

## Riferimenti sorgente verificati

- ELF reader/loader nativo: https://github.com/ps4-payload-dev/elfldr/blob/v0.7/elfldr.c
- Socket server ELF: https://github.com/ps4-payload-dev/elfldr/blob/v0.7/socksrv.c
- Bootstrap flat bin: https://github.com/ps4-payload-dev/elfldr/blob/v0.7/bootstrap-bin.c
- Build ufficiale: https://github.com/ps4-payload-dev/elfldr/blob/v0.7/Makefile
- Firmware support checklist: https://github.com/ps4-payload-dev/sdk/blob/main/README.md
- Prec. issue firmware 12.52: https://github.com/ps4-payload-dev/sdk/issues/11

## Impatto operativo

Questa v5 rimpiazza v4. Evitare di mischiare gli script di versioni diverse.
Finche' non si possiede la console, il punto di arresto ragionevole e' la build
con la toolchain WSL e il preflight offline; la riuscita di GoldHEN + elfldr
richiede invece una prova di integrazione PS4 e non e' dimostrabile da remoto.
