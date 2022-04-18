# dmx

See [qemu](qemu/README.md) for fast setup.
`dm-x` is the new implementation of `dm-mintegrity`.

This repository accumulates all source files created for the bachelors thesis "Secure Disk Encryption For Modern Cloud Settings".

## C
The directory C includes all source code written in C.
This incorporates the kernel module `dm-mintegrity` and the user land CLI `mkmint`.
Furthermore the [benchmarking](c/code/benchmarks/README.md) utility [run.sh](c/code/benchmarks/run.sh) resides in this folder.

## Config
Configuration files for `BusyBox`, `buildroot` and the Linux `kernel`.

## Linux
Fork of the `Rust-for-Linux` kernel, including the crypto crate `crypto.rs`.

## QEMU
Building and testing infrastructure of the repository.
Start there to get an overview of the tech stack.

## Rust
The folder Rust includes all tools written in Rust.
This includes the `mkdmx` CLI, a rewrite of the original `mkmint` tool.
