# fwSpoofer

Strumenti di laboratorio per lo sviluppo e la verifica locale di payload PS4 e
per l'analisi diagnostica della rete. Il nome del progetto è storico: **questo
repository non implementa lo spoofing del firmware né un bypass PSN**.

## Funzionalità

- Payload di esempio per una notifica e per la lettura in sola lettura della
  versione del firmware.
- Sender e controlli statici per file ELF, con test automatizzati eseguibili
  senza una console.
- Strumenti diagnostici per log e metadati di rete; il NetLab non decifra o
  modifica il traffico TLS.

La compatibilità con modelli, firmware, loader e configurazioni specifiche non
è garantita. I test locali non dimostrano il funzionamento su hardware reale.
Usa gli strumenti solo su dispositivi e reti che possiedi o sei autorizzato a
testare; payload e loader possono causare crash o perdita di dati.

## Requisiti

- Python 3.11 o successivo per i test e gli strumenti host.
- Per compilare i payload: Linux o WSL Ubuntu e PS4 Payload SDK configurato.
  La compilazione non è necessaria per eseguire i test host.
- TShark è necessario solo per le funzioni di cattura che lo richiedono.

## Test locali

Dalla directory principale del progetto:

```bash
python -m unittest discover -s tests -v
```

In alternativa, con GNU Make installato:

```bash
make test
```

Per i requisiti e la procedura di compilazione dei payload, consulta
[`docs/payload-development.md`](docs/payload-development.md). Le verifiche
automatizzate usano simulazioni dove necessario e non sostituiscono test su
hardware.

## Documentazione

- [Architettura](docs/architecture.md)
- [Sviluppo dei payload](docs/payload-development.md)
- [Informazioni sul firmware](docs/firmware-info.md)
- [Diagnostica e analisi di rete](docs/PSN-NETLAB-v10.md)
- [Changelog](CHANGELOG.md)

Le note di ricerca possono descrivere esperimenti specifici e non costituiscono
una dichiarazione di compatibilità o una garanzia di sicurezza.

## Privacy e pubblicazione

I risultati diagnostici possono contenere indirizzi IP e altri metadati della
rete locale. Non pubblicare catture, log o riepiloghi reali senza averli
controllati e anonimizzati. Gli output di compilazione e i risultati locali
sono esclusi dal controllo versione tramite `.gitignore`.

## Licenza

Non è ancora presente una licenza. Finché non ne viene scelta e aggiunta una,
non si concede un'autorizzazione generale a riutilizzare o ridistribuire il
codice.
