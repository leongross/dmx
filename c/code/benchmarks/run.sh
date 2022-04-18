#!/usr/bin/env bash

# CONFIG
BASEDIR=/
DEV=/dev/sdb
MOUNTPOINT=/mnt
MKMINT=${BASEDIR}/modules/mkmint
DEBUG=false
OUT_DIR=/reports/
DROP_CACHES=true

# CONST
ALGORITHM_HASH=sha256
ALGORITHM_HMAC=sha256
JOURNAL_BLOCKS=16384 # 64 MiB
BLOCK_SIZE=4096
SALT=0011223344556677
SECRET=012345abcd

drop_cache() {
    sync
    echo 3 | tee /proc/sys/vm/drop_caches &>/dev/null
    # sleep 2
}

DMX=true
DD=TRUE

MAPPED_DEVICE=/dev/mapper/dmx

TIME_FORMAT_DD_HUMAN="FS_INPUT=%I,FS_OUTPUT=%O,ELAPSED=%E,CPU_SEC_KERNEL=%S,CPU_SEC_USER=%U,GOT_CPU_USAGE=%P,PAGE_FAULT_MINOR=%R,PAGE_FAUL_MAJOR=%F"
TIME_FORMAT_DD_CSV="%I,%O,%E,%S,%U,%P,%R,%F"

TIME_OUT_DD_HUMAN=dd_$(date +%Y%m%d-%H%M%S)
TIME_OUT_DD_CSV=dd_$(date +%Y%m%d-%H%M%S).csv

DATA=(/dev/zero /rand.bin)

if [ ! -d "$OUT_DIR" ]; then
    mkdir "$OUT_DIR"
fi

# Block sizes
BS=(512 4096)

# assume that the values are sorted by value up
COUNT=(1024 4096 10000 100000 100000000 1500000000)

# echo "Mkmint formatting disk..."
# COMMAND=$(eval ${MKMINT} ${DEV} ${DEV} ${BLOCK_SIZE} ${JOURNAL_BLOCKS} ${ALGORITHM_HASH} ${SALT} ${ALGORITHM_HMAC} ${SECRET} lazy full | tail -1)
# if [ $? -ne 0 ]; then
#     echo "Failed to run mkmint"
#     exit 1
# fi
# echo "Mounting deivce mapper..." "$COMMAND"
# eval "${COMMAND}"
# eval "dmsetup mknodes"
# if [ $? -ne 0 ]; then
#     echo "Failed to run dmsetup create"
#     exit 1
# fi
#

# if dmx is enabled
if [[ "$DMX" == true ]];then
    insmod "$BASEDIR"/modules/dm-x.ko
    echo "[*] Mkmint formatting disk..."

    COMMAND=$(eval ${MKMINT} ${DEV} ${DEV} ${BLOCK_SIZE} ${JOURNAL_BLOCKS} ${ALGORITHM_HASH} ${SALT} ${ALGORITHM_HMAC} ${SECRET} lazy full | tail -1)
    if [ $? -ne 0 ]; then
        echo "Failed to run mkmint"
        exit 1
    fi

    echo "[*] Mounting device mapper..." "$COMMAND"
    eval "${COMMAND}"
    eval "dmsetup mknodes"
    if [ $? -ne 0 ]; then
        echo "[-] Failed to run dmsetup create"
        exit 1
    fi

    if [ -b "$MAPPED_DEVICE" ];then
        mkfs.ext4 "$MAPPED_DEVICE" || exit
        mount "$MAPPED_DEVICE" "$MOUNTPOINT" || exit
    else
        echo "[-] Cannot create fs on mapped device - it does not exist"
        ls -lah "$MAPPED_DEVICE"
        exit
    fi

    echo "[*] Benchamrking DMX"
else
    # make sure that the device $DEV is set correctly and is partioned
    mount "$DEV"1 "$MOUNTPOINT" || exit
    echo "[*] Benchmarking non-dmx"
fi

if [ "$DD" == "TRUE" ]; then
    FORMAT=$TIME_FORMAT_DD_CSV
    OUT=$TIME_OUT_DD_CSV
    BIN="$MOUNTPOINT"/bench.bin

    if [[ "$DEBUG" == true ]];then
        FORMAT=$TIME_FORMAT_DD_HUMAN
        OUT=$TIME_OUT_DD_HUMAN
        set -x
    fi

    # read /write random data initially to other disk to so that the reading from /dev/urandom does not bottleneck the process of writing to the device
    # set up random block of data so that the read overhead neglected.
    # assume that the values are sorted by value up
    if [[ ! -f /rand.bin ]];then
        dd if=/dev/ranom of=/rand.bin bs=512 count=$(( ${COUNT[-1]} / 512 ))
    fi

    # Uncached benchmarks
    start_uncached=$(date +%s)
    for size in "${BS[@]}"; do
        echo "[*] Benchmarking for block bs=$size (not cached)"
        for count in "${COUNT[@]}"; do
            for data in "${DATA[@]}";do
                [[ -f "$BIN" ]] && rm "$BIN"
                /usr/bin/time -f "$FORMAT" dd if="$data" of="$BIN" bs="$size" count=$(("$count" / "$size")) conv=fsync &>> write_"$OUT"
                echo ",$size,$count,$data,false" >> write_"$OUT"
                echo -e "\t[+] Benchmarking write: BS=$size DATA=$data COUNT=$count - done"
                [[ "$DROP_CACHES" == true ]] && drop_cache

                /usr/bin/time -f "$FORMAT" dd if="$BIN" of=/dev/null bs="$size" count=$(("$count" / "$size")) &>> read_"$OUT"
                echo ",$size,$count,$data,false" >> read_"$OUT"
                echo -e "\t[+] Benchmarking read:  BS=$size DATA=$data COUNT=$count - done"
                [[ "$DROP_CACHES" == true ]] && drop_cache
            done
        done
    done
    stop_uncached=$(date +%s)

    echo ""

    # Cached benchmarks
    start_cached=$(date +%s)
    for size in "${BS[@]}"; do
        echo "[*] Benchmarking for block bs=$size (cached)"
        for count in "${COUNT[@]}"; do
            for data in "${DATA[@]}";do
                [[ -f "$BIN" ]] && rm "$BIN"
                /usr/bin/time -f "$FORMAT" dd if="$data" of="$BIN" bs="$size" count=$(("$count" / "$size")) conv=fsync &>> write_"$OUT"
                echo ",$size,$count,$data,true" >> write_"$OUT"
                echo -e "\t[+] Benchmarking write: BS=$size DATA=$data COUNT=$count - done"

                /usr/bin/time -f "$FORMAT" dd if="$BIN" of=/dev/null bs="$size" count=$(("$count" / "$size")) &>> read_"$OUT"
                echo ",$size,$count,$data,true" >> read_"$OUT"
                echo -e "\t[+] Benchmarking read:  BS=$size DATA=$data COUNT=$count - done"
            done
        done
    done
    stop_cached=$(date +%s)
fi

runtime=$((stop_uncached - start_uncached))
echo "[*] Benchmark uncached took $runtime seconds"

runtime=$((stop_cached - start_cached))
echo "[*] Benchmark cached took $runtime seconds"

[[ "$DMX" == true ]] && echo "[*] Benchmarked DMX" || echo "[*] Benchmarked standard volume"

if [[ "$DEBUG" != true ]];then
    echo "[*] Formatting logs to readable csv ..."
    sed -i '/record/d' ./*.csv
    awk 'ORS=NR%2?" ":"\n"' write_"$OUT" | tr -d ' ' > tmp_write.csv
    awk 'ORS=NR%2?" ":"\n"' read_"$OUT" | tr -d ' ' > tmp_read.csv
    echo 'FS_INPUT,FS_OUTPUT,ELAPSED,CPU_SEC_KERNEL,CPU_SEC_USER,CPU_USAGE,PAGE_FAULT_MINOR,PAGE_FAULT_MAJOR,SIZE,COUNT,DATA_TYPE,CACHED' > header.csv
    cat header.csv tmp_write.csv > write_"$OUT"
    cat header.csv tmp_read.csv > read_"$OUT"
    rm tmp_*.csv header.csv
fi

echo "[+] Log files:"
echo -e "\twrite_$OUT"
echo -e "\tread_$OUT"

exit
