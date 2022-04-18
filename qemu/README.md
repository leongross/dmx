# QEMU - Run Virtualized Environment

Before running the setup process make sure the submodules are fetched and initialized.
```sh
git submodule update --recursive --remote
git submodule update --recursive
```

## Setup
Compile the kernel with the kernel config `config/kernel.config`.
```sh
$ make kernel
```

Build the kernel module `dm-mintegrity.ko` and the user land utility `mkmint`.
If you boot the rust kernel make sure to add the `rust` flag to the mkmint target in the [`Makefile`](./Makefile)`
```sh
$ make mkmint
```

Or build everything in one step (recommended)
```sh
$ make all
```

Set up benchmark files
```sh
$ make benchmark
```

Build the buildroot environment or the plain ramfs only.
Buildroot will create a filesystem containing all necessary functions and tools.
Using the buildroot root file system is strongly recommended.
```sh
$ make buildroot
```

```sh
$ make plainramfs
```

## Run
The tmux script in the root directory launches qemu with the buildroot rootfs and the rust [kernel](../linux).
The GNU debugger `gdb` is automatically attached to the booted kernel.
Breakpoints for debugging can be set in the script as well.
```sh
$ ./tmux.sh
```

Log into the booted system with the username `root` and launch the script [`/start.sh`](./overlay/start.sh).
Alternatively, configure and run the benchmark script located in `/benchmarks/run.sh`.

Or start the raw qemu virtual machine without gdb attached.
```sh
$ buildroot/start-qemu.sh
```

## Important Note
If files are written to the root file systems, a kernel panic will occur in the next boot.
Rebuild the project at the next run with `make`.
