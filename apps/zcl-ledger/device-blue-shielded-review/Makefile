# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
ifndef BOLOS_SDK
$(error BOLOS_SDK is required)
endif
ifndef ARM_INCLUDE_DIR
$(error ARM_INCLUDE_DIR is required)
endif
SDK_REVISION := $(shell git -C "$(BOLOS_SDK)" rev-parse HEAD 2>/dev/null)
ifneq ($(SDK_REVISION),3c710b4c62ad847599a2deb0932a50dd1ae4bdff)
$(error The Blue SDK revision differs from the reviewed source)
endif

SDK_PATCH_SHA256 := $(word 1,$(shell git -C "$(BOLOS_SDK)" diff --no-ext-diff --binary | sha256sum))
ifneq ($(SDK_PATCH_SHA256),4919fd81ba7a3a80880065aaf7898c2edd603b2586f6086a88570c73996019f6)
$(error The Blue SDK patch differs from the reviewed C23 patch)
endif
SDK_STAGED := $(shell git -C "$(BOLOS_SDK)" diff --cached --name-only)
ifneq ($(strip $(SDK_STAGED)),)
$(error The Blue SDK contains staged changes)
endif
SDK_UNTRACKED := $(shell git -C "$(BOLOS_SDK)" ls-files --others)
ifneq ($(strip $(SDK_UNTRACKED)),)
$(error The Blue SDK contains untracked files)
endif

include $(BOLOS_SDK)/Makefile.defines

ifneq ($(TARGET_ID),0x31000004)
$(error The SDK must target Ledger Blue firmware 2.1.x)
endif

APPNAME = "ZCL Shielded Review"
APPVERSION = 0.5.11
APP_FLAGS = 0x00
APP_SOURCE_PATH += src
SDK_SOURCE_PATH += lib_stusb lib_stusb_impl

DEFINES += OS_IO_SEPROXYHAL IO_SEPROXYHAL_BUFFER_SIZE_B=128
DEFINES += HAVE_BAGL HAVE_IO_USB HAVE_L4_USBLIB
DEFINES += IO_USB_MAX_ENDPOINTS=7 IO_HID_EP_LENGTH=64 HAVE_USB_APDU
DEFINES += CX_COMPLIANCE_141 ZCL_BLUE_SHIELDED_REVIEW

CC := $(CLANGPATH)clang
AS := $(GCCPATH)arm-none-eabi-gcc
LD := $(GCCPATH)arm-none-eabi-gcc
CFLAGS += -std=c23 -O2 -Wall -Wextra -Werror -pedantic -fstack-usage
CFLAGS += -I../include -I../../../contexts/commons/packages/zsha256/include
LDFLAGS += -O2 -Wl,-z,noexecstack
LDLIBS += -lgcc -lc

all: default check-image check-stack

include $(BOLOS_SDK)/Makefile.rules

check-image: default
	@data_size=$$($(GCCPATH)arm-none-eabi-size -A bin/app.elf | awk '$$1 == ".data" { print $$2 }'); \
	  bss_size=$$($(GCCPATH)arm-none-eabi-size -A bin/app.elf | awk '$$1 == ".bss" { print $$2 }'); \
	  test "$$data_size" = 0 || { echo "Initialized .data requires loader allocation; refusing image" >&2; exit 1; }; \
	  test -n "$$bss_size" && test "$$bss_size" -le 5120 || \
	    { echo "Shielded image leaves less than 1024 bytes of Blue SRAM after .bss (which includes the 2048-byte stack reservation); refusing image" >&2; exit 1; }

obj/blue_shielded_stack_check: ../tools/blue_shielded_stack_check.c
	@mkdir -p obj
	$(HOST_CC) -std=c23 -O2 -Wall -Wextra -Werror -pedantic $< -o $@

HOST_CC ?= clang

check-stack: default obj/blue_shielded_stack_check
	@obj/blue_shielded_stack_check $(BOLOS_SDK)/script.ld obj/*.su
