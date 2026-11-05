# Architettura effettiva: BD-JB / GoldHEN / elfldr

```mermaid
flowchart TD
  A[Windows o WSL: fwSpoofer] --> B[PS4 SDK]
  B --> C[dist/hello_world.elf + firmware_info.elf]
  D[PS4 FW 12.52] --> E[BD-JB Poops + GoldHEN]
  E --> F[GoldHEN BinLoader 9090]
  G[elfldr v0.7: elfldr.bin flat] -->|bootstrap non collaudato| F
  F -.->|se riesce| H[elfldr TCP 9021]
  C --> I[Sender Python, ELF raw]
  I --> H
  H --> J[Processo payload / linker SPRX]
  J --> K[Notifica e stdout su socket / Klog 3232]
```

Le frecce tratteggiate indicano un **passaggio non ancora verificato in hardware**.
La porta 9090 e' il BinLoader sperimentale di GoldHEN; il sender non invia
ELF direttamente su tale porta. Il percorso Lua/Artemis 9026 -> 9020 e'
un'alternativa documentata upstream, ma NON e' un prerequisito del jailbreak
BD-JB dell'utente e non va avviata alla cieca.

`fw_info_read` interroga un'API di sistema in sola lettura. Il progetto non
modifica il firmware, la memoria kernel per lo spoofing, ne' i servizi PSN.
