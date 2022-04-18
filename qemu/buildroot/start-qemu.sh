#!/usr/bin/env bash

if [[ $DEBUG ]];then
    qemu-system-x86_64 \
        -kernel ../../linux/arch/x86_64/boot/bzImage \
        -hda rootfs.ext4 \
        -hdb mint-data.qcow2 \
        -hdc mint-meta.qcow2 \
        -m 8G \
        -nographic \
        -s \
        -S \
        -smp 8 \
        -append "\
            root=/dev/sda rw \
            console=ttyS0 \
            nokaslr \
            raid=noautodetect"
else
    qemu-system-x86_64 \
    -kernel ../../linux/arch/x86_64/boot/bzImage \
    -hda rootfs.ext4 \
    -hdb mint-data.qcow2 \
    -hdc mint-meta.qcow2 \
    -m 8G \
    -nographic \
    -smp 8 \
    -append "\
        root=/dev/sda rw \
        console=ttyS0 \
        nokaslr \
        raid=noautodetect"
fi

# rootwait \
#-drive file=rootfs.ext2,if=virtio,format=raw \
