#!/usr/bin/env bash
# https://gitlab.com/cryptsetup/cryptsetup/-/wikis/DMVerity

insmod /modules/dm-x.ko

if [[ -b /dev/sdb && -b /dev/sdc ]];then
    echo "using 2 devices"
    command=$(/modules/mkmint /dev/sdc /dev/sdb 4096 512 sha256 00 sha256 00 lazy full | tail -n 1)
elif [[ -b /dev/sdb && ! -b /dev/sdc ]];then 
    echo "using one device, may be buggy"
    command=$(/modules/mkmint /dev/sdb /dev/sdb 4096 512 sha256 00 sha256 00 lazy full | tail -n 1)
else
    echo "error finding devices"
fi

echo "$command"
read -r;
eval "$command"

# create ext4 filesystem
mkfs.ext4 /dev/mapper/dmx -F -E lazy_itable_init=0
mount /dev/mapper/dmx /mnt/
