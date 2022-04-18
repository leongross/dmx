.PHONY: all c rust clean

KDIR ?= /lib/modules/$(shell uname -r)/build
KDIR_RUST ?= ../../../linux/
PWD ?= $(shell pwd)

all: rust

c: dm-x.c $(KDIR)
	make -C $(KDIR) M=$(PWD)

rust: dm-x.c $(RUST_DIR)
	make -C $(KDIR_RUST) M=$(PWD) LLVM=1 modules

clean:
	-rm -f *.a *.order *.symvers *.cmd *.ko *.mod* *.o 2>/dev/null
