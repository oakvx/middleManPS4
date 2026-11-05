# **AGGIORNAMENTO BD-JB / Poops su firmware 12.52**

La tua console usa BD-JB. **Segui `docs/BDJB-1252.md` e `docs/RUNBOOK.md`** per un possibile primo stadio `elfldr.bin` tramite GoldHEN 9090. La procedura remota Lua/Artemis descritta in seguito e' una **alternativa per un exploit diverso**, NON un prerequisito per BD-JB. Non usare i comandi 9020/9026 della sezione Lua sul tuo BD-JB senza averne verificato ISO e protocollo.

---

# Loader ELF: ricerca, installazione e bootstrap

## Quale componente manca?

**Non una semplice libreria C da linkare.** Gli ELF costruiti con il PS4 Payload SDK importano librerie SPRX (ad esempio `libkernel_web.sprx`, `libSceLibcInternal.sprx`, `libSceNet.sprx`). Il [loader `elfldr`](https://github.com/ps4-payload-dev/elfldr) implementa dynamic linking, symbol resolution e lancio in processo separato. Lo SDK lo indica tra i loader compatibili.

**Compatibilita' specifica non ancora dimostrata:** presenza degli offset FW 12.52 nell'SDK e release di `elfldr` con patch per firmware piu' recenti non dimostrano automaticamente il funzionamento sulla tua PS4 GoldHEN 2.4b18.7.

## Fase A: ambiente WSL (offline rispetto alla console)

```bash
cd /mnt/c/Users/gabri/Desktop/projects/fwSpoofer
bash scripts/build.sh
python3 -m unittest discover -s tests -v
bash scripts/setup_elfldr.sh
```

Se non trovi `git`, `xxd`, `clang-18`, `lld-18`, esegui manualmente `bash scripts/install_deps.sh` e riprova.

`setup_elfldr.sh` usa `ELFLDR_REF=v0.7` per riproducibilita' (override possibile, ma documenta il commit con `git -C ~/ps4-payload-elfldr rev-parse HEAD`). Il SDK installato e' `~/ps4-payload-sdk-1252`.

Non sono inclusi SDK, firmware proprietario, binari precompilati o il sorgente GPL di `elfldr`; lo script preleva direttamente la sorgente ufficiale con Git.

## Fase B: scegli il bootstrap corretto

Per poter usare `elfldr`, serve **un primo stadio che consenta di eseguirlo**. Il percorso documentato da `elfldr` usa `remote_lua_loader` con un gioco Artemis idoneo e i savedata predisposti, quindi il payload `bin_loader.lua`.

L'utente ha confermato **BD-JB**: non sappiamo pero' quale ISO/fork Blu-ray venga utilizzato. Non e' lecito inferire la disponibilita' del gioco Artemis, del savedata, del servizio Lua 9026 o del bootstrap 9020. L'invio a 9090 con GoldHEN ha gia' fallito con il sample ufficiale, quindi non e' una soluzione affidabile da usare automaticamente.

Se usi `remote_lua_loader`, leggi la [guida SETUP](https://github.com/n0llptr/remote_lua_loader/blob/main/SETUP.md). Solo dopo che gioco/save sono configurati e il servizio Lua e' attivo:

```bash
bash scripts/setup_remote_lua.sh
PS4_HOST=192.168.1.5 bash scripts/send_bin_loader_lua.sh --send
```

Lo script di invio Lua usa `payloads/send_lua.py` e `payloads/bin_loader.lua` del clone upstream. **Non esegue `lapse.lua`**: il metodo di exploit specifico per FW 12.52 e' una precondizione esterna e non e' intercambiabile con un percorso dimostrato per altri firmware.

Con un altro jailbreak, usa soltanto il suo meccanismo documentato per lanciare un loader ELF compatibile. Non confondere GoldHEN 9090 con il bootstrap Lua 9020.

## Fase C: inviare elfldr al primo stadio UNA sola volta

**Attenzione: 9020 puo' essere monouso.** Nessun `nc -z`, `Test-NetConnection`, scansione porte o `diagnostics` su 9020. Una connessione vuota potrebbe consumare il listener e invalidare il bootstrap.

Solo se `bin_loader.lua` e' partito e aspetta il payload sulla 9020:

```bash
PS4_HOST=192.168.1.5 bash scripts/deploy_elfldr.sh --send --bootstrap-ready
```

Questo esegue l'upstream `make test` di `elfldr` con `PS4_PORT=9020`; non e' garantito che l'upload equivalga a un avvio riuscito. Se non sai che la 9020 e' pronta, **non lanciare il comando**.

A bootstrap concluso, puoi interrogare **9021**, che e' la porta del loader ELF persistente:

```bash
python3 -m host.ps4_sender.diagnostics --host 192.168.1.5 --port 9021 --require-open
```

Se CLOSED, ferma la procedura: non inviare payload sperimentali alla 9090 a ripetizione.

## Fase D: test graduati

```bash
bash scripts/compare_sample.sh
python3 -m host.ps4_sender.elfcheck --file dist/hello_world_official.elf
python3 -m host.ps4_sender.cli --host 192.168.1.5 --file dist/hello_world_official.elf --check-elf --send
```

Solo dopo che il sample **mostra effettivamente** il proprio comportamento atteso, invia `hello_world.elf` e, infine, `firmware_info.elf`:

```bash
python3 -m host.ps4_sender.cli --host 192.168.1.5 --file dist/hello_world.elf --check-elf --send
```

Per Klog usa il secondo terminale:

```bash
python3 -m host.ps4_sender.klog --host 192.168.1.5 --seconds 60
```

Se la console si blocca o crasha, interrompi i test, salva il log e riavvia pulito. Il crash `NPXS21002` visto in passato non puo' essere attribuito al payload senza nuove prove.

## Protocolli

`elfldr` sulla 9021 riceve **byte ELF raw su TCP**, senza header aggiuntivi. Il sender incluso usa `socket.sendall(data)` e non aggiunge framing; il risultato certifica la consegna al socket locale, non l'esecuzione. `nc -q0 HOST 9021 < file.elf` e' l'equivalente di riferimento upstream (su Linux WSL).

`remote_lua_loader` su 9026 usa invece il proprio protocollo per inviare Lua, non ELF raw. La 9020 accetta il bootstrap dalla procedura `make test` upstream. Non confondere le tre interfacce.
