#!/usr/bin/env bash

tmux new-session \; \
  send-keys 'cd buildroot && make start-debug' C-m \; \
  split-window -h \; \
  send-keys 'gdb ../linux/vmlinux' C-m \; \
  select-pane -t 1 \; \
  send-keys 'target remote :1234' C-m\; \
  send-keys 'add-symbol-file ./overlay/modules/dm-mintegrity.ko 0xffffffffc0000000' C-m\; \
  send-keys 'add-symbol-file ./overlay/modules/rustfromc.ko 0xffffffffc0005000' C-m\; \
  send-keys 'set logging file dumps/gdb/gdb.log' C-m\; \
  send-keys 'set logging on' C-m\; \
  send-keys 'c' C-m\; \
  select-pane -t 0 \; \

#send-keys 'hbreak dm-mintegrity.c:3551' C-m\; \
#send-keys 'hbreak mintegrity_verify_read_io' C-m\; \
#send-keys 'hbreak mintegrity_read_work' C-m\; \
#send-keys 'hbreak dm-mintegrity.c:2803' C-m\; \
#send-keys 'hbreak mintegrity_verify_level' C-m\; \
#send-keys 'hbreak dm-mintegrity.c:393 if $rcx == 0' C-m\; \
#send-keys 'hbreak dm-mintegrity.c:393' C-m\; \

# https://stackoverflow.com/questions/5941158/gdb-print-to-file-instead-of-stdout
