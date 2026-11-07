# Experimental live_agent.elf — self-process telemetry only

This optional userspace ELF connects to a paired Windows/Linux receiver, authenticates with HMAC-SHA256 and sends bounded metadata about **its own process** (PID, elapsed heartbeat, firmware-read status). **It does not monitor other processes, trace global syscalls, inspect PSN or intercept TLS.**

The build requires a private `live_agent_config.h` generated from `python -m host.ps4_sender.live_agent config`. It embeds a private pairing key in the local ELF: do not distribute or upload that binary. Neither this ELF nor a PS4 PKG has been compiled on the actual user's SDK or executed on firmware 12.52; the host C mock is not proof of compatibility.
