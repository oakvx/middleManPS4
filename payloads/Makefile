# Cross compilation: the user's installed SDK; no proprietary libraries bundled.
PS4_PAYLOAD_SDK ?= $(HOME)/ps4-payload-sdk-1252
SDK_MAKEFILE := $(PS4_PAYLOAD_SDK)/toolchain/orbis.mk
ifneq ($(MAKECMDGOALS),clean)
ifeq ($(wildcard $(SDK_MAKEFILE)),)
$(error Missing $(SDK_MAKEFILE). Set PS4_PAYLOAD_SDK to an installed PS4 payload SDK)
endif
include $(SDK_MAKEFILE)
endif

HELLO_ELF := ../dist/hello_world.elf
FIRMWARE_ELF := ../dist/firmware_info.elf
CFLAGS += -Wall -Wextra -O2 -g
.PHONY: all clean hello_world firmware_info
all: $(HELLO_ELF) $(FIRMWARE_ELF)
hello_world: $(HELLO_ELF)
firmware_info: $(FIRMWARE_ELF)
$(HELLO_ELF): hello_world/src/main.c
	@mkdir -p ../dist
	$(CC) $(CFLAGS) -o $@ $<
$(FIRMWARE_ELF): firmware_info/src/main.c common/src/fw_info.c common/include/fw_info.h
	@mkdir -p ../dist
	$(CC) $(CFLAGS) -Icommon/include -o $@ firmware_info/src/main.c common/src/fw_info.c
clean:
	rm -f $(HELLO_ELF) $(FIRMWARE_ELF)
