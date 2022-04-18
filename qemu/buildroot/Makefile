SRC_BUILDROOT ?= ../../3rdparty/buildroot/
PWD = $(shell pwd)
SHELL := /bin/bash

all: test-dev-small ../overlay/modules/dm-x.ko
	cp ../../config/buildroot.config $(SRC_BUILDROOT).config
	make -C $(SRC_BUILDROOT) -j `nproc`
	cp $(SRC_BUILDROOT)output/images/rootfs.* $(PWD)


start:
	./start-qemu.sh


start-debug:
	DEBUG=1 ./start-qemu.sh


menuconfig:
	make -C $(SRC_BUILDROOT) menuconfig
	cp $(SRC_BUILDROOT).config ../../config/buildroot.config


busybox:
	make -C $(SRC_BUILDROOT) busybox-menuconfig


test-dev:
	-qemu-img create -f qcow2 mint-data.qcow2 10G
	-qemu-img create -f qcow2 mint-meta.qcow2 2G


test-dev-small:
	-qemu-img create -f qcow2 mint-data.qcow2 2G
	-qemu-img create -f qcow2 mint-meta.qcow2 500M


clean:
	make -C $(SRC_BUILDROOT) clean
