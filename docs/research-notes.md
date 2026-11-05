# Evidenze e ipotesi della sessione 05-11-2026

## Osservato su macchina utente

- SDK `/home/gabri/ps4-payload-sdk-1252` installato, `orbis-clang` invocato in ricompilazione con `make -B`.
- ELF `hello_world.elf`: ET_DYN, entry 0x90, hash b63c1bd84172b67d1f4aec7e0201f90ac9bdb8dfb9da0c6381bc79cedd0f78b0.
- ELF sample SDK: ET_DYN, entry 0x70, hash 5de41c28493192906cad855d948ac46ede09e406ecc5b96aee70454e1f1c9ef1.
- PS4 12.52 + GoldHEN 2.4b18.7: solo `Payload received` per entrambi sulla 9090.
- Klog: warning `copyin: GoldHENLoader has nonsleeping lock`, crash separato di `PARTY DAEMON` NPXS21002 exception 11. Non vi sono prove sufficienti per attribuire causa al payload.

## Documentato upstream

- `ps4-payload-dev/sdk`: SDK e loader ELF noti funzionanti.
- `ps4-payload-dev/elfldr`: dynamic SPRX linking, automatic symbol resolution, processo separato, 9021, bootstrap con Lua/9020.
- `n0llptr/remote_lua_loader`: richiede uno dei giochi Artemis supportati e savedata.
- GoldHEN: 9090 sperimentale, non equivalenza a elfldr.

## Non verificato

Compatibilita' dell'intera catena `FW 12.52 + GoldHEN 2.4b18.7 + metodo di jailbreak ignoto + elfldr v0.7 + payload`. Non invocare funzioni di alterazione della console per forzare compatibilita'.

## Aggiornamento: l'utente usa BD-JB

L'utente ha confermato il jailbreak BD-JB. Su firmware 12.52 l'exploit documentato e' Poops, non Lapse. GoldHEN 9090 e' specificato come BinLoader per `.bin`; l'invio di `.elf` non era un test valido del loader ELF completo. Il sorgente `elfldr v0.7` contiene `bootstrap-bin.c` che produce `elfldr.bin` e gestisce FW `0x12520000`; la compatibilita effettiva via GoldHEN 9090 deve essere verificata hardware. **Non e' noto quale ISO BD-JB sia utilizzata**: non inviare alla 9020 senza confermare il protocollo di quella ISO.

Vedi `docs/BDJB-1252.md` per fonti e sequenza di verifica.
