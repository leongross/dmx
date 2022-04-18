 qemu-system-x86_64 \
        -kernel ../../linux/arch/x86_64/boot/bzImage \
        -initrd qemu-initramfs.img \
        -nographic \
        -no-reboot \
	    -m 512 \
	    --append "console=ttyS0"
        
