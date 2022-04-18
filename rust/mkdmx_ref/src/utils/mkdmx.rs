use block_utils::{self, BlockResult, BlockUtilsError, Device};
use std::fs;
// use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::{fs::File, io::Write};

/// Magic byte value marking the Super Block, taken from original source code
pub static DMX_MS_MAGIC: u32 = 0x796c694c;

/// Magic byte value marking journal entries, taken from original source code
pub static DMX_MJ_MAGIC: u32 = 0x594c494c;

#[allow(non_camel_case_types)]
pub mod superblock {
    use openssl::sha;
    use std::str::FromStr;
    use std::{fs::File, io::Write};

    pub enum Hashes {
        Sha1,
        Sha224,
        Sha256,
        Sha384,
        Sha512,
    }

    impl FromStr for Hashes {
        type Err = ();
        fn from_str(input: &str) -> Result<Hashes, Self::Err> {
            match input {
                "sha1" => Ok(Hashes::Sha1),
                "sha224" => Ok(Hashes::Sha224),
                "sha256" => Ok(Hashes::Sha256),
                "sha384" => Ok(Hashes::Sha384),
                "sha512" => Ok(Hashes::Sha512),
                _ => Err(()),
            }
        }
    }

    impl From<&Hashes> for String {
        fn from(hash: &Hashes) -> Self {
            match *hash {
                Hashes::Sha1 => String::from("sha1"),
                Hashes::Sha224 => String::from("sha224"),
                Hashes::Sha256 => String::from("sha256"),
                Hashes::Sha384 => String::from("sha384"),
                Hashes::Sha512 => String::from("sha512"),
            }
        }
    }

    impl From<&[u8; 32]> for Hashes {
        fn from(arr: &[u8; 32]) -> Self {
            Hashes::from_str(
                std::str::from_utf8(arr)
                    .unwrap()
                    .trim_matches(char::from(0)),
            )
            .unwrap()
        }
    }

    impl From<&Hashes> for usize {
        fn from(hash: &Hashes) -> usize {
            match *hash {
                Hashes::Sha1 => 160 / 8,
                Hashes::Sha224 => 224 / 8,
                Hashes::Sha256 => 256 / 8,
                Hashes::Sha384 => 384 / 8,
                Hashes::Sha512 => 521 / 8,
            }
        }
    }

    pub fn wrapper_hash(hash: &Hashes, salt: &[u8], salt_len: usize, input: &[u8]) -> Vec<u8> {
        match *hash {
            Hashes::Sha1 => {
                let mut hasher = sha::Sha1::new();
                hasher.update(&salt[..salt_len]);
                hasher.update(input);
                Vec::<u8>::from(hasher.finish())
            }
            Hashes::Sha224 => {
                let mut hasher = sha::Sha224::new();
                hasher.update(&salt[..salt_len]);
                hasher.update(input);
                Vec::<u8>::from(hasher.finish())
            }
            Hashes::Sha256 => {
                let mut hasher = sha::Sha256::new();
                hasher.update(&salt[..salt_len]);
                hasher.update(input);
                Vec::<u8>::from(hasher.finish())
            }
            Hashes::Sha384 => {
                let mut hasher = sha::Sha384::new();
                hasher.update(&salt[..salt_len]);
                hasher.update(input);
                Vec::<u8>::from(hasher.finish())
            }
            Hashes::Sha512 => {
                let mut hasher = sha::Sha512::new();
                hasher.update(&salt[..salt_len]);
                hasher.update(input);
                Vec::<u8>::from(hasher.finish())
            }
        }
    }

    #[repr(C)]
    #[derive(Debug)]
    pub struct dmx_superblock {
        /// DMX_MS_MAGIC bytes.
        pub magic: u32,

        /// Superblock version.
        pub version: u32,

        /// UUID of the device in bytes representation instead of `u128`.
        pub uuid: [u8; 16],

        /// Hash algorithm name as bytes.
        pub hash_algorithm: [u8; 32],

        /// Hash algorithm name as bytes.
        pub hmac_algorithm: [u8; 32],

        /// Number of data blocks on the device with size `block_size`. Calculated at runtime.
        pub data_blocks_n: u64,

        /// Number of hash blocks on the device. Calculated at runtime.
        pub hash_blocks_n: u32,

        /// Number of journal blocks. Provided by the CLI.
        pub jb_blocks_n: u32,

        // Block size of device in bytes. Provided by the CLI.
        pub block_size: u32,

        /// Size of a salt for hashing. Derived from salt passed to CLI.
        pub salt_size: u16,

        /// Salt used for hashing the blocks. Provided by CLI.
        pub salt: [u8; 128],

        /// Root hash of the Merkle tree. Calculated at runtime.
        pub hash_root: [u8; 128],

        /// Just helper, will not be dumped
        /// Holds the amount of levels as `blocks_per_level.len()` and the block per level at index level
        pub blocks_per_level: Vec<u32>,
    }

    impl dmx_superblock {
        pub fn new(
            blocks: u64,
            block_size: u32,
            uuid: [u8; 16],
            hash_algorithm: &str,
            hmac_algorithm: &str,
            salt_size: u32,
            salt: [u8; 128],
            hash_root: [u8; 128],
            journal_blocks: u32,
        ) -> dmx_superblock {
            let hash_size = match Hashes::from_str(hash_algorithm).unwrap() {
                Hashes::Sha1 => 160 / 8,
                Hashes::Sha224 => 224 / 8,
                Hashes::Sha256 => 256 / 8,
                Hashes::Sha384 => 384 / 8,
                Hashes::Sha512 => 521 / 8,
            };

            let mut blocks_per_level: Vec<u32> = Vec::new();

            // pre compute values for compute_block_numbers
            let (_, levels, hash_blocks): (bool, u32, u32) = crate::mkdmx::compute_hash_blocks(
                blocks,
                crate::utils::mkdmx::fanout(block_size, hash_size),
                &mut blocks_per_level,
            );
            if levels == 0 || hash_blocks == 0 {
                panic!("cannot create dmx_superblock, levels or hash_blocks = 0");
            }

            let (data_blocks, hash_blocks, _) = crate::mkdmx::compute_block_numbers(
                blocks,
                crate::mkdmx::fanout(block_size, hash_size),
                256,
                &mut blocks_per_level,
                journal_blocks,
            )
            .unwrap();

            let mut _hash_algorithm = [0u8; 32];
            _hash_algorithm[..hash_algorithm.chars().count()]
                .clone_from_slice(hash_algorithm.as_bytes());

            let mut _hmac_algorithm = [0u8; 32];
            _hmac_algorithm[..hmac_algorithm.chars().count()]
                .clone_from_slice(hmac_algorithm.as_bytes());

            dmx_superblock {
                magic: crate::mkdmx::DMX_MS_MAGIC,
                version: 1,
                uuid,
                hash_algorithm: _hash_algorithm,
                hmac_algorithm: _hmac_algorithm,
                data_blocks_n: data_blocks as u64,
                hash_blocks_n: hash_blocks,
                jb_blocks_n: journal_blocks,
                block_size,
                salt_size: salt_size as u16,
                salt: salt,
                hash_root: hash_root,
                blocks_per_level,
            }
        }

        /// Dummy constructor used for testing.
        ///
        pub fn new_dummy(hash_blocks: u32, journal_blocks: u32, block_size: u32) -> dmx_superblock {
            let hash_root: [u8; 128] = [8; 128];
            let algorithm = "sha256";

            let mut hash_algorithm = [0u8; 32];
            hash_algorithm[..algorithm.chars().count()].clone_from_slice(algorithm.as_bytes());

            let mut hmac_algorithm = [0u8; 32];
            hmac_algorithm[..algorithm.chars().count()].clone_from_slice(algorithm.as_bytes());

            dmx_superblock {
                magic: crate::mkdmx::DMX_MS_MAGIC,
                version: 1,
                uuid: [
                    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
                ],
                hash_algorithm,
                hmac_algorithm,
                data_blocks_n: 1_000_000 * 8,
                hash_blocks_n: hash_blocks,
                jb_blocks_n: journal_blocks,
                block_size: block_size,
                salt_size: 128 as u16,
                salt: [0xffu8; 128],
                hash_root,
                blocks_per_level: vec![1, 4, 32],
            }
        }

        pub fn size(&self) -> usize {
            std::mem::size_of::<Self>()
        }
    }

    pub fn superblock_to_dev(sb: &dmx_superblock, dev: &mut File) {
        dev.write(&sb.magic.to_le_bytes()).unwrap();
        dev.write(&sb.version.to_le_bytes()).unwrap();
        dev.write(&sb.uuid).unwrap();
        dev.write(&sb.hash_algorithm).unwrap();
        dev.write(&sb.hmac_algorithm).unwrap();
        dev.write(&sb.data_blocks_n.to_le_bytes()).unwrap();
        dev.write(&sb.hash_blocks_n.to_le_bytes()).unwrap();
        dev.write(&sb.jb_blocks_n.to_le_bytes()).unwrap();
        dev.write(&sb.block_size.to_le_bytes()).unwrap();
        dev.write(&sb.salt_size.to_le_bytes()).unwrap();
        dev.write(&sb.salt).unwrap();
        dev.write(&sb.hash_root).unwrap();

        let padding: usize =
            sb.block_size as usize - sb.size() + std::mem::size_of::<Vec<u8>>() + 2;
        dev.write(&vec![0u8; padding]).unwrap();
    }
}

pub mod journal_block {
    use core::panic;
    use std::{fs::File, io::Write};

    use crate::mkdmx::superblock;
    use crate::mkdmx::DMX_MJ_MAGIC;
    /// Journal superblock containing all information regarding the journal.
    /// It is copied into the device before the journal data itself starts.
    ///
    /// Currently not sure why superblock is 3623 bytes long, not 4096
    #[derive(Debug)]
    #[allow(non_camel_case_types)]
    #[repr(C)]
    pub struct dmx_journal_superblock {
        /// Type of journal
        pub header: dmx_journal_header,

        /// Number of block in this journal (including superblock)
        pub blocks_n: u64,

        /// Circular buffer head position for kernel module
        pub head: u32,

        /// Circular buffer tail position
        pub tail: u32,

        /// Number of used blocks in journal.
        pub fill: u32,

        /// Current sequence number
        pub sequence: u32,

        /// State of the journal.
        /// `1`: dirty
        /// `0`: clean / not dirty
        pub state: u32,
    }

    impl dmx_journal_superblock {
        pub fn new(jb_block: u64) -> Self {
            Self {
                header: dmx_journal_header {
                    magic: DMX_MJ_MAGIC,
                    journal_type: dmx_journal_type::TYPE_MJSB,
                    sequence: 0,
                    options: 0,
                },
                blocks_n: jb_block,
                head: 0,
                tail: 0,
                fill: 0,
                sequence: 0,
                state: 0,
            }
        }

        pub fn size(&self) -> usize {
            std::mem::size_of::<Self>()
        }

        pub fn to_u8(&self) -> Box<[u8]> {
            let mut mem = [0u8; 13 + 8 + 4 + 4 + 4 + 4 + 4];
            mem[..13].clone_from_slice(&*self.header.to_u8());
            mem[13..21].clone_from_slice(&self.blocks_n.to_le_bytes());
            mem[21..25].clone_from_slice(&self.head.to_le_bytes());
            mem[25..29].clone_from_slice(&self.tail.to_le_bytes());
            mem[29..33].clone_from_slice(&self.fill.to_le_bytes());
            mem[33..37].clone_from_slice(&self.sequence.to_le_bytes());
            mem[37..41].clone_from_slice(&self.state.to_le_bytes());
            return Box::new(mem);
        }
    }

    #[derive(Debug)]
    #[allow(non_camel_case_types)]
    #[repr(C)]
    /// Every journal block has this as the first n bytes
    /// One journal block is of one block size, i.e. 4096
    pub struct dmx_journal_header {
        /// DMX_MJ_MAGIC
        pub magic: u32,

        /// Journal type \in {super,descriptor,commit,nothing}
        pub journal_type: dmx_journal_type,

        /// Sequence number
        pub sequence: u32,

        /// Bitwise options
        pub options: u32,
    }

    impl dmx_journal_header {
        pub fn new() -> Self {
            Self {
                magic: DMX_MJ_MAGIC,
                journal_type: dmx_journal_type::TYPE_MJNB,
                options: 0,
                sequence: 0,
            }
        }

        pub fn size(&self) -> usize {
            std::mem::size_of::<Self>()
        }

        pub fn to_u8(&self) -> Box<[u8]> {
            let mut mem = [0u8; 13];
            mem[..4].clone_from_slice(&self.magic.to_le_bytes());
            mem[4] = self.journal_type as u8;
            mem[5..9].clone_from_slice(&self.sequence.to_le_bytes());
            mem[9..].clone_from_slice(&self.options.to_le_bytes());
            Box::new(mem)
        }
    }

    #[derive(Debug)]
    #[allow(non_camel_case_types)]
    #[repr(C)]
    pub struct dmx_journal_block_tag {
        /// Destination sector low
        pub low: u32,

        /// Destination sector high
        pub high: u32,

        /// Last or bits for escaped blocks
        pub options: u32,
    }

    #[allow(non_camel_case_types)]
    #[derive(PartialEq, Debug, Copy, Clone)]
    #[repr(u8)]
    pub enum dmx_journal_type {
        /// Mint Journal Nothing Block
        TYPE_MJNB = 1,

        /// Mint Journal Super Block
        TYPE_MJSB = 2,

        /// Mint Journal Descriptor Block
        TYPE_MJDB = 3,

        /// Mint Journal Commit Block
        TYPE_MJCB = 4,
    }

    pub fn create_journal(sb: &superblock::dmx_superblock, dev: &mut File) {
        let js = dmx_journal_superblock::new(sb.jb_blocks_n.into());
        let jsb: &mut [u8] = &mut vec![0u8; sb.block_size as usize];
        jsb[..41].clone_from_slice(&*js.to_u8());

        let jh = dmx_journal_header::new();
        let jhb: &mut [u8] = &mut vec![0; sb.block_size as usize];
        jhb[..13].clone_from_slice(&*jh.to_u8());

        // first, write block with dmx_superblock to disk
        if dev.write(jsb).unwrap() != sb.block_size as usize {
            panic!("cannot write journal super block")
        }

        // write out all n super block headers
        for _i in 0..sb.jb_blocks_n as usize {
            if dev.write(jhb).unwrap() != sb.block_size as usize {
                panic!("cannot write journal header blocks");
            }
        }
    }
}

pub fn fanout(block_size: u32, hash_size: u32) -> u32 {
    let mut fanout: u32 = block_size / hash_size;
    let mut fls: u8 = 0;
    let mut pls: u8 = 0;

    while fanout > 0 {
        if (fanout & 1) == 1 {
            fls = pls;
        }
        pls += 1;
        fanout >>= 1;
    }
    fanout = 1 << fls;
    return fanout;
}

fn div(x: u32, y: u32) -> u32 {
    if x == 0 {
        x
    } else {
        1 + ((x - 1) / y)
    }
}

pub fn compute_hash_blocks(
    data_blocks: u64,
    fanout: u32,
    blocks_per_level: &mut Vec<u32>,
) -> (bool, u32, u32) {
    let mut levels: u32 = 0;
    let mut hash_blocks: u32 = 0;
    let mut layer: u32 = crate::utils::mkdmx::div(data_blocks as u32, fanout);

    while layer != 1 {
        blocks_per_level.push(layer);
        hash_blocks += layer;
        levels += 1;
        layer = crate::utils::mkdmx::div(layer, fanout);
    }

    blocks_per_level.push(1);
    levels += 1;
    hash_blocks += 1;

    if layer == 0 {
        (true, levels, hash_blocks)
    } else {
        (false, levels, hash_blocks)
    }
}

pub fn compute_block_numbers(
    mut blocks: u64,
    fanout: u32,
    padding_blocks: u64,
    blocks_per_level: &mut Vec<u32>,
    journal_blocks: u32,
) -> Result<(u32, u32, u32), &'static str> {
    if blocks < 6 {
        return Err("Not enough space! Need at least 6 blocks");
    } else {
        blocks -= 1;
        let mut low: u64 = 0;
        let mut high: u64 = blocks;
        let mut bpl: Vec<u32> = Vec::new();

        let mut db: u64 = 0;
        let mut pb: u64 = 0;
        let mut hb: u32 = 0;
        let mut levels;

        let mut used: u64;

        while high >= low && high != 0 {
            let mid: u64 = low.wrapping_add(div((high - low) as u32, 2) as u64);
            bpl.clear();

            // db = data_blocks
            db = mid;

            // hb = hash_block, jb = journal_blocks, pb = padding_blocks
            let crash: bool;
            (crash, levels, hb) = compute_hash_blocks(db, fanout, &mut bpl);
            if crash {
                break;
            }

            used = db
                .wrapping_add(journal_blocks as u64)
                .wrapping_add(hb as u64);

            pb = blocks.wrapping_sub(used);

            for i in 0..levels {
                if i >= blocks_per_level.len() as u32 {
                    blocks_per_level.push(bpl[i as usize])
                } else {
                    blocks_per_level[i as usize] = bpl[i as usize];
                }
            }

            if used > blocks {
                high = mid - 1;
            } else if used < blocks {
                low = mid + 1;
            } else {
                break;
            }
        }

        if blocks == padding_blocks {
            return Err("error in `compute_block_numbers`!");
        } else {
            return Ok((db as u32, hb, pb as u32));
        }
    }
}

pub fn generate_hashes(super_block: &superblock::dmx_superblock) -> Vec<Vec<u8>> {
    let mut hash_levels: Vec<Vec<u8>> = Vec::new();
    let mut hash_block: Vec<u8> = Vec::new();
    let hash_size: usize = (&superblock::Hashes::from(&super_block.hash_algorithm)).into();

    // h_0: zero block hash for leafs
    hash_levels.push(superblock::wrapper_hash(
        &superblock::Hashes::from(&super_block.hash_algorithm),
        &super_block.salt[..super_block.salt_size as usize],
        super_block.salt_size as usize,
        &vec![0; super_block.block_size as usize][..],
    ));

    for _ in 0..super_block.blocks_per_level.len() {
        for _ in 0..(super_block.block_size as usize / hash_size) {
            hash_block.append(&mut hash_levels.last().unwrap().clone());
        }

        hash_levels.push(superblock::wrapper_hash(
            &superblock::Hashes::from(&super_block.hash_algorithm),
            &super_block.salt[..super_block.salt_size as usize],
            super_block.salt_size as usize,
            &hash_block,
        ));
        hash_block.clear();
    }

    hash_levels
}

pub fn merkle_tree_to_dev(
    dev: &mut File,
    super_block: &superblock::dmx_superblock,
    hash_levels: &mut Vec<Vec<u8>>,
) {
    let hash_size: usize = (&superblock::Hashes::from(&super_block.hash_algorithm)).into();
    for blocks in super_block.blocks_per_level.iter().rev() {
        let hash = &hash_levels.pop().unwrap();

        for _ in 0..*blocks {
            for _ in 0..(super_block.block_size as usize / hash_size) {
                dev.write(&hash).unwrap();
            }
        }
    }
}

pub fn check_device_sanity(dev: &str) -> BlockResult<Device> {
    let dev_path = &PathBuf::from(dev);
    let d = block_utils::get_device_info(dev_path);

    let d = match d {
        Ok(d) => d.to_owned(),
        Err(error) => {
            return Err(error);
        }
    };

    // 1. The device can be a block device
    // 2. The device can be a file
    // 3. The file may not contain a file system

    if block_utils::is_block_device(dev_path).unwrap()
        || fs::metadata(dev).unwrap().is_file()
        || d.fs_type != block_utils::FilesystemType::Unknown
    {
        match d.device_type {
            block_utils::DeviceType::Disk => {
                return Ok(d);
            }
            _ => {
                return Err(BlockUtilsError::Error(
                    "Device is neither a disk nor a file".to_string(),
                ));
            }
        }
    } else {
        return Err(block_utils::BlockUtilsError::Error(
            "Invalid Device".to_string(),
        ));
    }
}

pub fn zero_device(
    super_block: &superblock::dmx_superblock,
    dev: &mut File,
) -> std::io::Result<usize> {
    let mut written: usize = 0;
    for _ in 0..(super_block.data_blocks_n) as usize {
        let res = dev.write(&vec![0u8; super_block.block_size as usize][..]);
        written += match res {
            Ok(written) => written,
            Err(err) => match err.kind() {
                std::io::ErrorKind::StorageFull => {
                    eprint!("[*] Reached end of disk. Finishing");
                    return Ok(written);
                }
                _ => return Err(err),
            },
        };
    }
    Ok(written)
}

#[cfg(test)]
pub mod tests {
    use std::fs::OpenOptions;
    use std::io::Seek;
    use std::os::unix::prelude::FileExt;

    use crate::utils::mkdmx::{self, check_device_sanity};

    use super::journal_block::create_journal;
    use super::{fanout, superblock};

    #[test]
    fn test_create_journal() {
        let sb = superblock::dmx_superblock::new_dummy(1024, 1024, 4096);
        let mut dev = OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .open("tests/loop_0.img")
            .unwrap();

        create_journal(&sb, &mut dev);
    }

    #[test]
    fn test_superblock_to_dev() {
        let sb = superblock::dmx_superblock::new_dummy(1024, 1024, 4096);
        let mut dev = OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .open("tests/loop_0.img")
            .unwrap();

        crate::mkdmx::superblock::superblock_to_dev(&sb, &mut dev);
    }

    #[test]
    fn test_compute_block_numbers() {
        let mut blocks_per_level = Vec::<u32>::new();
        let block_size = 512;
        let blocks = check_device_sanity("/dev/loop1").unwrap().capacity / block_size;
        assert_eq!(blocks, 1953125);

        let journal_blocks: u32 = 512;
        let fanout = fanout(512, 32);
        assert_eq!(fanout, 16);

        // values taken from original application written in C and debugged (see work.md)
        let (data_blocks, hash_blocks, pad_blocks) = crate::mkdmx::compute_block_numbers(
            blocks,
            16,
            0,
            &mut blocks_per_level,
            journal_blocks,
        )
        .unwrap();

        assert_eq!(data_blocks, 1830572);
        assert_eq!(hash_blocks, 122040);
        assert_eq!(pad_blocks, 0);
        assert_eq!(journal_blocks, 512);
        assert_eq!(blocks_per_level.len(), 6);
        assert_eq!(blocks_per_level, vec![114411, 7151, 447, 28, 2, 1]);
    }

    // For this test to work properly, the `loop_0` and `loop_1` make target has to be executed, since it operates on block sizes of 4096
    #[test]
    fn test_main_real_512() {
        let block_size: u64 = 512;
        let mut dev = OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .open("/dev/loop1")
            .unwrap();

        let blocks = check_device_sanity("/dev/loop1").unwrap().capacity / block_size;
        assert_eq!(blocks, 1953125);

        let mut sb = superblock::dmx_superblock::new(
            check_device_sanity("/dev/loop1").unwrap().capacity / block_size,
            block_size as u32,
            [0xffu8; 16],
            "sha256",
            "sha256",
            0,
            [0u8; 128],
            [0x1a; 128],
            512,
        );

        let mut hashes = crate::mkdmx::generate_hashes(&sb);
        sb.hash_root.clone_from_slice(hashes.get(0).unwrap());

        assert_eq!(sb.data_blocks_n, 1830572);
        assert_eq!(sb.hash_blocks_n, 122040);
        assert_eq!(sb.jb_blocks_n, 512);
        assert_eq!(sb.blocks_per_level.len(), 6);
        assert_eq!(sb.blocks_per_level, vec![114411, 7151, 447, 28, 2, 1]);

        crate::mkdmx::superblock::superblock_to_dev(&sb, &mut dev);
        crate::mkdmx::merkle_tree_to_dev(&mut dev, &sb, &mut hashes);
        create_journal(&sb, &mut dev);
    }

    #[test]
    fn test_superblock() {
        let block_size = 512;
        let super_block_size = std::mem::size_of::<superblock::dmx_superblock>();
        assert_eq!(super_block_size, 392);
        assert_eq!(
            block_size - super_block_size + std::mem::size_of::<Vec<u8>>(),
            1
        );
    }

    /// ../../../c/code/mkmint/mkmint /dev/loop0 /dev/loop0 4096 512 sha256 00 sha256 00 lazy full
    /// Hash_Type: sha256
    /// Hmac_Type: sha256
    /// Block_Size: 4096
    /// Data_Blocks: 238166
    /// Hash_Blocks: 1877
    /// JB_Blocks: 4096
    /// Salt_Size: 1
    /// Salt: 00
    /// Root_Hash: 3fea1b0387c3b064258a915c1e8d9855911a063b7f30b09f94bda33277a7d46e
    ///
    /// For this test to work properly, the `old` make target has to be executed, since it operates on block sizes of 4096
    /// ```
    /// make clean old
    /// ```
    #[test]
    fn test_main_real_4096() {
        let device = "/dev/loop0";
        let block_size: u64 = 4096;
        let mut dev = OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .open(device)
            .unwrap();

        // blockdev --getsz returns 512 sectors, so divide by 8
        let blocks = check_device_sanity(device).unwrap().capacity / block_size;
        assert_eq!(blocks, 1953120 / 8);

        let mut sb = superblock::dmx_superblock::new(
            check_device_sanity(device).unwrap().capacity / block_size,
            block_size as u32,
            [0xffu8; 16],
            "sha256",
            "sha256",
            1,
            [0u8; 128],
            [0u8; 128],
            4096,
        );

        let mut hashes = mkdmx::generate_hashes(&sb);
        sb.hash_root[..32].clone_from_slice(&hashes.pop().unwrap());

        let mut hash: [u8; 128] = [0u8; 128];
        hash[..32].clone_from_slice(
            &hex::decode("3fea1b0387c3b064258a915c1e8d9855911a063b7f30b09f94bda33277a7d46e")
                .unwrap(),
        );

        assert_eq!(&sb.hash_root, &hash);

        assert_eq!(sb.data_blocks_n, 238166);
        assert_eq!(sb.hash_blocks_n, 1877);
        assert_eq!(sb.jb_blocks_n, 4096);
        assert_eq!(sb.blocks_per_level.len(), 3);
        assert_eq!(sb.blocks_per_level, vec![1861, 15, 1]);

        mkdmx::superblock::superblock_to_dev(&sb, &mut dev);
        mkdmx::merkle_tree_to_dev(&mut dev, &sb, &mut hashes);
        create_journal(&sb, &mut dev);

        // reset read pointer
        dev.seek(std::io::SeekFrom::Start(0)).unwrap();

        // super block
        let mut buf = [0u8; 4];
        dev.read_at(&mut buf, 0).unwrap();
        assert_eq!(&buf, &sb.magic.to_le_bytes());

        // hash algo
        let mut buf = [0u8; 32];
        dev.read_at(&mut buf, 24).unwrap();
        assert_eq!(&buf, &sb.hash_algorithm);

        // hmac algo
        let mut buf = [0u8; 32];
        dev.read_at(&mut buf, 56).unwrap();
        assert_eq!(&buf, &sb.hash_algorithm);

        // hmac algo
        let mut buf = [0u8; 32];
        dev.read_at(&mut buf, 56).unwrap();
        assert_eq!(&buf, &sb.hmac_algorithm);

        // data blocks
        let mut buf = [0u8; 8];
        dev.read_at(&mut buf, 88).unwrap();
        assert_eq!(u64::from_le_bytes(buf), sb.data_blocks_n);

        // hash blocks
        let mut buf = [0u8; 4];
        dev.read_at(&mut buf, 96).unwrap();
        assert_eq!(u32::from_le_bytes(buf), sb.hash_blocks_n);

        // journal blocks
        let mut buf = [0u8; 4];
        dev.read_at(&mut buf, 100).unwrap();
        assert_eq!(u32::from_le_bytes(buf), sb.jb_blocks_n);

        // block size
        let mut buf = [0u8; 4];
        dev.read_at(&mut buf, 104).unwrap();
        assert_eq!(u32::from_le_bytes(buf), sb.block_size);

        // block size
        let mut buf = [0u8; 2];
        dev.read_at(&mut buf, 108).unwrap();
        assert_eq!(u16::from_le_bytes(buf), sb.salt_size);

        // salt buffer
        let mut buf = [0u8; 128];
        dev.read_at(&mut buf, 110).unwrap();
        assert_eq!(buf, sb.salt);

        // root hash
        let mut buf = [0u8; 128];
        dev.read_at(&mut buf, 238).unwrap();
        assert_eq!(buf, sb.hash_root);

        // assure the last blocks of padding are zero
        let mut buf = [0u8; 8];
        dev.read_at(&mut buf, 4096 - 8).unwrap();
        assert_eq!(buf, [0u8; 8]);

        // xxd old_0.img | grep -i "42A6 8268 CAEC" | tail -n 1 = 00001fe0
        // 0x1fe0 - 0x1000 = 0x0fe0 = 4064 = 1 4096 bytes block
        let level_0: [u8; 32] = [
            0x42, 0xA6, 0x82, 0x68, 0xCA, 0xEC, 0x60, 0x74, 0x69, 0x6A, 0xD2, 0xCC, 0x2D, 0x47,
            0x87, 0x1A, 0xB9, 0xFC, 0xE7, 0x3F, 0x1A, 0x38, 0x83, 0x0A, 0x83, 0x37, 0xF7, 0xA2,
            0x41, 0x94, 0xD9, 0x4E,
        ];

        let mut buf = [0u8; 32];
        dev.read_at(&mut buf, 0x1000).unwrap();
        assert_eq!(buf, level_0);

        let mut buf = [0u8; 32];
        dev.read_at(&mut buf, 0x1fe0).unwrap();
        assert_eq!(buf, level_0);

        // xxd old_0.img | grep -i "94b8 165a" | tail -n 1 = 00010fe0
        // 0x11000 - 0x2000 = 0xf000 = 641440 bytes = 15.0 4096 bytes bloecke
        let level_1: [u8; 32] = [
            0x94, 0xB8, 0x16, 0x5A, 0x8A, 0xF0, 0x21, 0xF3, 0x2D, 0x0B, 0xEA, 0x9C, 0xC9, 0xFE,
            0x9D, 0x7C, 0xA0, 0x1F, 0x11, 0xF4, 0x00, 0x67, 0xBB, 0xA5, 0x8E, 0x0B, 0xFB, 0x62,
            0xBD, 0x1B, 0xCC, 0x63,
        ];

        let mut buf = [0u8; 32];
        dev.read_at(&mut buf, 0x2000).unwrap();
        assert_eq!(buf, level_1);

        let mut buf = [0u8; 32];
        dev.read_at(&mut buf, 0x10fe0).unwrap();
        assert_eq!(buf, level_1);

        // xxd old_0.img | grep -i "b587 fa29" | tail -n 1 = 0x00755fe0
        // = 1861 4096 bytes hash bloecke
        let level_2: [u8; 32] = [
            0xB5, 0x87, 0xFA, 0x29, 0x72, 0x99, 0xCE, 0x9C, 0x60, 0x2E, 0x58, 0x29, 0x2B, 0x51,
            0x37, 0x94, 0x02, 0xBF, 0x7B, 0x10, 0x74, 0xF6, 0xB1, 0x86, 0x79, 0xC2, 0xFB, 0x87,
            0x1C, 0x91, 0x7C, 0xA8,
        ];

        let mut buf = [0u8; 32];
        dev.read_at(&mut buf, 0x11000).unwrap();
        assert_eq!(buf, level_2);

        let mut buf = [0u8; 32];
        dev.read_at(&mut buf, 0x755fe0).unwrap();
        assert_eq!(buf, level_2);

        // check for journal super block
        let mut buf = [0u8; 4];
        dev.read_at(&mut buf, 0x756000).unwrap();
        assert_eq!(buf, "LILY".as_bytes());
    }
}
