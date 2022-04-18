#![feature(io_error_more)]

pub mod utils;
use nix::unistd::Uid;
use std::fs::{File, OpenOptions};
use utils::mkdmx;
use utils::mkdmx_cli;
use uuid::Uuid;

#[cfg(not(debug_assertions))]
use clap::Parser;

fn main() {
    #[cfg(not(debug_assertions))]
    if !Uid::effective().is_root() {
        use std::process::exit;
        eprintln!("[-] Permission denied, run as root");
        exit(1);
    }

    #[cfg(not(debug_assertions))]
    let mut args: mkdmx_cli::Args = mkdmx_cli::Args::parse();

    #[cfg(debug_assertions)]
    let mut args = mkdmx_cli::Args {
        debug: true,
        mint_dev: "/dev/loop0".to_string(),
        data_dev: "/dev/loop0".to_string(),
        block_size: 4096,
        journal_blocks: 4096,
        hash_type: "sha256".to_string(),
        hmac_type: "sha256".to_string(),
        salt: "00".to_string(),
        secret: "0xdeadbeef".to_string(),
        lazy: false,
        full: true,
    };
    args.verify();

    let two_disks: bool = args.mint_dev == args.data_dev;
    if !two_disks {
        unimplemented!("Support for two separate disks is currently not available");
    }

    let mut dev: File = OpenOptions::new()
        .read(true)
        .write(true)
        .create(false)
        .append(true)
        .open(&args.mint_dev)
        .unwrap();

    let mut salt: [u8; 128] = [0u8; 128];
    salt[..args.salt.len()].clone_from_slice(&args.salt.as_bytes());

    // if the disks are not the same, calculate data block for the data_dev, since it will store the data
    // let blocks: u64 = match two_disks {
    //     true => {
    //         mkdmx::check_device_sanity(&args.mint_dev)
    //             .unwrap_or_else(|err| {
    //                 panic!("could not read information for device {}", &err);
    //             })
    //             .capacity
    //             / args.block_size as u64
    //     }
    //     false => {
    //         mkdmx::check_device_sanity(&args.data_dev)
    //             .unwrap_or_else(|err| {
    //                 panic!("could not read information for device {}", &err);
    //             })
    //             .capacity
    //             / args.block_size as u64
    //     }
    // };

    let mut sb = mkdmx::superblock::dmx_superblock::new(
        mkdmx::check_device_sanity(&args.mint_dev)
            .unwrap_or_else(|err| {
                panic!("could not read information for device {}", &err);
            })
            .capacity
            / args.block_size as u64,
        args.block_size,
        Uuid::new_v4().as_bytes().clone(),
        &args.hash_type,
        &args.hmac_type,
        (&args.salt.len() / 2) as u32,
        salt,
        [0u8; 128],
        args.journal_blocks,
    );

    #[cfg(debug_assertions)]
    dbg!(&sb);

    let mut hashes = mkdmx::generate_hashes(&sb);
    sb.hash_root[..32].clone_from_slice(&hashes.pop().unwrap());

    mkdmx::superblock::superblock_to_dev(&sb, &mut dev);
    mkdmx::merkle_tree_to_dev(&mut dev, &sb, &mut hashes);
    mkdmx::journal_block::create_journal(&sb, &mut dev);

    if !args.lazy {
        if two_disks {}
        mkdmx::zero_device(&sb, &mut dev).unwrap();
    }
}
