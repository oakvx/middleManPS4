# Setup rapido Windows / WSL

Requisiti: Windows con WSL Ubuntu e Python 3.11+; SDK in `/home/gabri/ps4-payload-sdk-1252`; rete LAN verso PS4 `192.168.1.5` (modifica IP se cambia).

PowerShell (cartella estratta):

```powershell
python -m unittest discover -s tests -v
.\scripts\build.ps1 -SdkPath "/home/gabri/ps4-payload-sdk-1252"
```

WSL:

```bash
cd /mnt/c/Users/gabri/Desktop/projects/fwSpoofer
bash scripts/build.sh
bash scripts/setup_elfldr.sh
```

Se vuoi installare i pacchetti mancanti su Ubuntu, esegui separatamente `bash scripts/install_deps.sh` (sudo). Non sono necessari servizi cloud o account esterni per la comunicazione TCP del sender; il clone iniziale dei repository richiede GitHub.

Prima di eseguire payload consulta `docs/loader-install.md`. Non inviare automaticamente alla 9090. Non usare `nc -vz`/`Test-NetConnection` sulla 9020.
