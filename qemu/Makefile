.PHONY: all start-buildroot start-plainramfs dmx kernel benchmark

PWD = $(shell pwd)/

MINT_DIR = $(PWD)../c/code/dm-x/
MINT_KO = $(MINT_DIR)dm-x.ko
MKMINT_DIR = $(PWD)../c/code/mkmint/
MKMINT_RST = $(PWD)../rust/mkdmx_ref/

BENCH_DIR = $(PWD)../c/code/benchmarks/
LINUX_SRC = $(PWD)../linux

SRC_BUSYBOX = ../3rdparty/busybox/
SRC_BUILDROOT = ../3rdparty/buildroot/

MAX = 1500000000

all: kernel dmx rust_mods plainramfs benchmark buildroot

start-buildroot: all
	make -C buildroot start


start-plainramfs: all
	make -C plainramfs start


dmx: $(MKMINT_DIR)/mkmint.c
	make -C $(MINT_DIR) KDIR_RUST=$(LINUX_SRC) PWD=$(MINT_DIR) rust --always-make
	make -C $(MKMINT_DIR)

	# -cargo build --manifest-path=$(MKMINT_RST)Cargo.toml --release
	cp $(MINT_KO) $(MKMINT_DIR)mkmint $(MINT_DIR)Module.symvers $(MINT_DIR)modules.order ./overlay/modules/


./overlay/rand.bin:
	dd if=/dev/random of=./overlay/rand.bin bs=512 count=$$((${MAX} / 512)) conv=fsync


benchmark: $(BENCH_DIR)run.sh ./overlay/rand.bin
ifeq (, $(shell which shellcheck))
	$(error "No shellcheck in $(PATH), skipping verification")
else
	shellcheck ../c/code/benchmarks/run.sh -S warning
endif
	cp $(BENCH_DIR) -r  ./overlay/

#	RIP=$(shell grep 'COUNT=' ../c/code/benchmarks/run.sh | head -n 1 | cut -d $$'\040' -f 2 | tr -d $$'\040' | sort | rev | cut -d ' ' -f1 | rev))


rust_mods: $(LINUX_SRC)/samples/rustfromc/rustfromc.c $(LINUX_SRC)/samples/rustfromc/rustfromc.ko
	cp $(LINUX_SRC)/samples/rustfromc/rustfromc.ko ./overlay/modules
	cp $(LINUX_SRC)/samples/rust/rust_hash.ko ./overlay/modules


kernel:
	make -C $(LINUX_SRC) \
		LLVM=1 \
		-j `nproc` \
		ARCH=x86_64


buildroot: overlay/modules/dm-x.ko
	make -C buildroot


busybox:
	cp ../config/busybox.config ../3rdparty/busybox/.config -v
	make -C $(SRC_BUSYBOX)
	cp $(SRC_BUSYBOX)busybox plainramfs/ -v


clean:
	-make -C buildroot clean
	-make -C plainramfs clean
	-make -C $(MINT_DIR) clean
