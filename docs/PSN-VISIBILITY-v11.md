# middleManPS4 v0.11.0 — Verifica visibilità del percorso PS4 → Internet

**Obiettivo:** stabilire se la scheda su cui catturiamo vede davvero pacchetti IPv4 con **origine PS4 e destinazione IP pubblica**. Questo è un prerequisito per qualunque interpretazione del tentativo di accesso PSN. Non è un sistema di spoofing e non cambia credenziali, firmware o richieste HTTPS.

## Risultato precedente (v0.10.0)

Nella LAN originale la PS4 era `192.168.31.11`. Il PC riceveva/mandava ICMP alla PS4, ma `baseline.json`, `baseline1.json` e `psn_attempt.json` contenevano zero eventi DNS/TLS/TCP. Una cattura con zero eventi filtrati **non** significa zero pacchetti né dimostra che il messaggio di aggiornamento sia generato localmente.

Il nuovo parser conta anche tutti i pacchetti IPv4 della PS4, inclusi ICMP, e distingue l'uscita verso indirizzi globali. I vecchi JSON restano leggibili, ma il loro campo `capture_visibility.status` sarà `not_measured` perché quei contatori non esistevano.

## A. Metti il PC nel percorso dei pacchetti

### Metodo A: hotspot mobile Windows (senza cavo, se la scheda Wi-Fi lo supporta)

1. Mantieni il PC Windows connesso a Internet.
2. In **Impostazioni → Rete e Internet → Hotspot mobile**, seleziona la connessione da condividere, configura nome/password e attiva l'hotspot. Microsoft documenta la condivisione Wi-Fi su Wi-Fi in Windows 10/11: https://support.microsoft.com/it-it/windows/experience/connectivity-networking/use-your-windows-device-as-a-mobile-hotspot
3. Collega **la PS4 all'SSID dell'hotspot del PC**, non alla rete Wi-Fi precedente.
4. In **PS4 → Impostazioni → Rete → Visualizza stato connessione** annota il nuovo indirizzo IPv4; *non presumere che rimanga* `192.168.31.11`.
5. In PowerShell esegui `python -m host.ps4_sender.psn_netdiag interfaces`. Scegli l'interfaccia relativa all'hotspot/adapter virtuale che trasporta il traffico della PS4. Se TShark non vede pacchetti Internet su tale interfaccia, non trarre conclusioni: prova il metodo B.

### Metodo B: collegamento Ethernet con condivisione connessione (alternativa più controllabile)

1. Mantieni il **PC connesso a Internet via Wi-Fi**.
2. Collega **PS4 e PC con un cavo Ethernet**.
3. Su Windows premi `Win + R`, digita `ncpa.cpl`. Apri **Proprietà** dell'interfaccia Wi-Fi → **Condivisione**; se disponibile, abilita la condivisione della connessione scegliendo **Ethernet** come rete domestica. Non creare un bridge di rete e non impostare manualmente un gateway arbitrario.
4. Su PS4 imposta la connessione via cavo con configurazione **Facile/Automatica**. Se la condivisione è operativa, annota il nuovo IP della PS4 e il gateway (spesso, *ma non necessariamente*, `192.168.137.1`).
5. In TShark scegli **la scheda Ethernet verso la PS4**, non l'interfaccia Wi-Fi collegata al router.

Se Internet non funziona sulla PS4, risolvi prima la configurazione di condivisione. Non puoi interpretare un login PSN senza una connessione Internet funzionante.

## B. Nuova acquisizione (solo metadati)

Sostituisci `IP_PS4` con il **nuovo IP reale** e `N` con l'indice corretto dell'interfaccia restituito da `interfaces`.

```powershell
cd C:\Users\gabri\Desktop\projects\fwSpoofer
python -m host.ps4_sender.psn_netdiag interfaces
python -m host.ps4_sender.psn_netdiag capture --host IP_PS4 --interface N --seconds 45 --summary gw_baseline.json --capture
```

Durante questa prima cattura apri sulla PS4 il normale test **Verifica connessione Internet** (oppure un'altra operazione ordinaria di rete), senza tentare il login PSN. Lo scopo è verificare la visibilità di **traffico effettivamente diretto a Internet**.

Dopo che il file `gw_baseline.json` è stato creato, esegui:

```powershell
python -m host.ps4_sender.psn_netdiag capture --host IP_PS4 --interface N --seconds 45 --summary gw_psn_attempt.json --capture
```

Durante questa seconda cattura tenta **una sola volta** l'accesso PSN; annota se compare la richiesta di aggiornamento, senza accettare alcun aggiornamento. Poi:

```powershell
python -m host.ps4_sender.psn_triage --baseline gw_baseline.json --attempt gw_psn_attempt.json
```

I file di riepilogo devono avere **nomi nuovi** perché il tool non sovrascrive acquisizioni precedenti.

## C. Come leggere l'esito

- `capture_visibility.status = public_destination_observed`: almeno un pacchetto IPv4 con sorgente PS4 e destinatario IP pubblico è stato visto su questa interfaccia. **Il percorso è osservabile per quei pacchetti**, ma non prova successo PSN, presenza di uno specifico controllo o visibilità di *tutti* i flussi.
- `only_nonpublic_or_inbound_observed`: almeno un pacchetto della PS4 è visibile, ma **nessun pacchetto in uscita verso un IP pubblico**. Il solo ping LAN non risolve il problema. Controlla interfaccia, IP e modalità di condivisione; può anche darsi che la PS4 non abbia emesso traffico verso Internet durante quella finestra.
- `no_ipv4_packets_observed`: nessun pacchetto IPv4 della PS4 osservato nell'intervallo. Verifica IP, scheda e connettività, senza concludere nulla sul firmware.
- `not_measured`: riepilogo generato prima della v0.11.0. Serve una nuova acquisizione per ottenere la classificazione.
- `proxy_only`: sono disponibili solo log CONNECT espliciti, non una prova di visibilità della rete fisica.

**La scelta corretta del punto di cattura è cruciale.** Se si osserva soltanto traffico LAN, non è possibile stabilire se il prompt di aggiornamento sia conseguenza di una verifica locale o della risposta di un server. La diagnostica non intercetta contenuti TLS, credenziali, token e non modifica il traffico.

## D. Cosa condividere

Riporta il riepilogo di `psn_triage` e *solo* la topologia usata: hotspot, cavo Ethernet con condivisione, router con port mirroring o PC sulla stessa Wi-Fi. Evita PCAP grezzi, password, token, informazioni di account e indirizzi IP pubblici in chiaro.
