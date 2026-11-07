# fwSpoofer: wrapper. Build must run in Linux/WSL with ps4-payload-dev/sdk.
.DEFAULT_GOAL := all
PS4_PAYLOAD_SDK ?= $(HOME)/ps4-payload-sdk-1252
export PS4_PAYLOAD_SDK
.PHONY: all clean test check verify doctor loader-build observer
all:
	$(MAKE) -C payloads all
clean:
	$(MAKE) -C payloads clean

test:
	python3 -m unittest discover -s tests -v

check: test
	python3 -m host.ps4_sender.elfcheck --file dist/hello_world.elf
	python3 -m host.ps4_sender.elfcheck --file dist/firmware_info.elf

verify:
	bash scripts/verify-build.sh

doctor:
	python3 -m host.ps4_sender.diagnostics --host $${PS4_HOST:-192.168.1.5}

loader-build:
	bash scripts/setup_elfldr.sh

observer:
	$(MAKE) -C payloads observer
