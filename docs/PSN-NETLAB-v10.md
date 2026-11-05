# fwSpoofer 1.0.0 — PSN NetLab: cosa è implementato e cosa NON lo è

Il codice *non* risolve l'accesso PSN su PS4 12.52 e *non* modifica richieste di autenticazione. Implementa due esperimenti diversi, entrambi **senza decrittare TLS**:

1. **Cattura passiva** con Wireshark/TShark: osserva IP, DNS, SNI quando visibile, SYN/RST e TLS alert. Salva soltanto riepiloghi JSON. I PCAP grezzi temporanei vengono eliminati alla fine dell'analisi.
2. **Proxy HTTPS CONNECT opzionale**: inoltra byte TLS cifrati senza alterazioni, registrando soltanto nome della destinazione e conteggio byte. Non intercetta il plaintext, non cattura token e non può falsificare i campi di versione. La PS4 potrebbe ignorare le impostazioni del proxy per alcuni servizi di sistema.
3. **Analisi comparativa offline** tra la navigazione normale e il tentativo PSN; **non interpreta l'assenza di eventi come prova di controllo locale**.

## Requisiti e posizionamento della cattura

- PS4 sulla LAN: `192.168.31.11` (ricontrollare l'indirizzo se cambia).
- Su Windows installare **Wireshark** con **TShark** e **Npcap**. Verificare che `tshark.exe` sia accessibile nel PATH o installato nella directory standard.
- Un PC su una LAN Ethernet/Wi-Fi commutata **normalmente non vede il traffico unicast della PS4**: bisogna osservare dal router/AP che instrada il traffico, una porta mirror o una macchina che funge da gateway. Non mettere in mezzo un proxy trasparente casuale, non disattivare verifiche TLS.
- La diagnostica è utile solo se il numero di eventi è maggiore di zero e si sa che il punto di osservazione vede davvero il traffico della console. Anche in tal caso non dimostra il motivo del prompt Sony.

## A. Cattura passiva (consigliata per iniziare)

Esegui da PowerShell nella root `fwSpoofer`:

```powershell
python -m host.ps4_sender.psn_netdiag interfaces
python -m host.ps4_sender.psn_netdiag capture --host 192.168.31.11 --interface 1 --seconds 30 --summary baseline.json
```

`--interface 1` è soltanto un **esempio**: scegli l'ID corretto dalla lista. Il comando sopra è **DRY RUN**. Per avviare la cattura devi aggiungere `--capture`:

```powershell
python -m host.ps4_sender.psn_netdiag capture --host 192.168.31.11 --interface 1 --seconds 30 --summary baseline.json --capture
```

Con la PS4 accesa evita il login per tutta la cattura baseline. Poi ripeti con un **nome diverso** e durante i 30 secondi prova una sola volta «Accedi a PSN», senza accettare aggiornamenti:

```powershell
python -m host.ps4_sender.psn_netdiag capture --host 192.168.31.11 --interface 1 --seconds 30 --summary psn_attempt.json --capture
```

Confronta i due riepiloghi:

```powershell
python -m host.ps4_sender.psn_triage --baseline baseline.json --attempt psn_attempt.json
```

Se entrambi i riepiloghi mostrano zero eventi, **non possiamo dedurre nulla sul controllo firmware**: la causa più banale è che il PC non vede il traffico della PS4. Se `tshark` non è installato, fermati e non inventare risultati.

## B. Proxy CONNECT esplicito — esperimento opzionale

Avvia una prova in dry run (nessuna porta aperta):

```powershell
python -m host.ps4_sender.psn_tunnel --client-ip 192.168.31.11 --bind 0.0.0.0 --port 8888 --allow-lan
```

Per una prova reale, **soltanto sulla propria LAN**, aggiungi `--serve`. Abilita temporaneamente il proxy HTTP sulla PS4 usando l'indirizzo **IP del PC** (non della console) e porta `8888`. Il programma accetta soltanto il client PS4 e CONNECT verso destinazioni pubbliche TCP/443. Puoi fermarlo con Ctrl+C; **ripristina le impostazioni di rete precedenti** sulla PS4 dopo il test.

Avviso: l'impostazione proxy della console non implica che i processi PSN usino il proxy. Non installare CA personalizzate e non intercettare credenziali o token. Il tunnel conserva la cifratura end-to-end; non può modificare una richiesta HTTPS.

## Vincoli tecnici dello spoof PSN

- Il prompt «Per usare le funzioni di rete, aggiorna il software di sistema» non identifica da solo quale componente prende la decisione.
- Anche qualora un campo versione fosse presente nella richiesta HTTPS, modificarlo richiederebbe accesso al plaintext, compatibilità con TLS/certificati, e non escluderebbe integrità/firme/controlli applicativi o attestation lato server.
- Non abbiamo verificato presenza né assenza di certificate pinning, firme di protocollo, attestazione o formato dei messaggi PSN; **non affermarne l'esistenza come fatto**.
- Il NetLab non offre bypass dell'autenticazione, PSN login, patch kernel, spoof di sistema o disabilitazione dei controlli di sicurezza.
- Accessi sperimentali ai servizi Sony con una console modificata possono comportare sospensioni o altri rischi. Non utilizzare account importanti per esperimenti e non diffondere metadati di rete.

## Cosa riportare

Invia solo il riepilogo di `psn_triage` e indica dove è stata eseguita la cattura (router/gateway, mirror, PC ordinario). Non condividere PCAP grezzi, credenziali o session token.
