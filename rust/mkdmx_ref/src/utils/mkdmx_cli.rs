use clap::Parser;

use crate::mkdmx;

#[derive(Parser, Debug)]
#[clap(author = "Leon Gross <leon.gross@rub.de> <lg@edgeless.systems>", version = "1.0.0", about, long_about = None)]
pub struct Args {
    /// Device to store merkle tree on
    #[clap(long)]
    pub debug: bool,

    /// Device to protect
    #[clap(short, long)]
    pub mint_dev: String,

    /// Device to check integrity of
    #[clap(short, long)]
    pub data_dev: String,

    /// Size of one block
    #[clap(short, long)]
    pub block_size: u32,

    /// Amount of journal blocks
    #[clap(short, long)]
    pub journal_blocks: u32,

    /// Hash Type
    #[clap(long, default_value = "sha256")]
    pub hash_type: String,

    /// Hmac type
    #[clap(long, default_value = "sha256")]
    pub hmac_type: String,

    /// Hmac Salt in base 16 without leading 0x
    #[clap(long)]
    pub salt: String,

    /// Secret for Hmac base 16 without leading 0x
    #[clap(long)]
    pub secret: String,

    /// Lazy: do not change device contents, Nolazy: wipe
    #[clap(short, long)]
    pub lazy: bool,

    /// Full device
    #[clap(short, long)]
    pub full: bool,
}

// for better cli maybe use https://lib.rs/crates/termion
impl Args {
    pub fn verify(&mut self) {
        let d = mkdmx::check_device_sanity(&self.mint_dev).unwrap();

        if self.block_size < 512 {
            panic!("invalid block size");
        }

        if d.capacity % self.block_size as u64 != 0 {
            eprint!(
                "capacity is not a multiple of device size, {} remaining",
                d.capacity % self.block_size as u64
            );
        }

        if self.salt.len() % 2 != 0 {
            panic!("salt has to be divisible by 2");
        }

        // the salt should not be greater than 256B = 256/4 = 32 chars in base 16
        if self.salt.len() > 32 {
            panic!("salt can only be 256 Bytes long");
        }

        // parse salt and secret
        let reg_hex = regex::Regex::new(r"^([a-fA-F0-9]){0,33}$|^0x([a-fA-F0-9]){0,33}$").unwrap();
        if !reg_hex.is_match(&self.salt) {
            panic!("invalid salt format: {}", self.salt);
        } else {
            self.salt = self.salt.replace("0x", "");
        }

        if self.secret.len() % 2 != 0 {
            panic!("secret has to be divisible by 2");
        }
        if !reg_hex.is_match(&self.secret) {
            panic!("invalid secret format: {}", self.secret);
        } else {
            self.secret = self.salt.replace("0x", "");
        }
    }
}

pub mod tests {
    use crate::mkdmx_cli::Args;

    #[test]
    #[should_panic]
    fn test_arg_parse_wrong_device() {
        let mut args = Args {
            debug: true,
            mint_dev: "/dev/error".to_string(),
            data_dev: "/dev/error".to_string(),
            block_size: 512,
            journal_blocks: 4096,
            hash_type: "Sha256".to_string(),
            hmac_type: "Sha256".to_string(),
            salt: "0x13371337".to_string(),
            secret: "0xdeadbeef".to_string(),
            lazy: false,
            full: true,
        };
        args.verify();
    }

    #[test]
    #[should_panic]
    fn test_arg_parse_block_size() {
        let mut args = Args {
            debug: true,
            mint_dev: "/dev/loop0".to_string(),
            data_dev: "/dev/loop0".to_string(),
            block_size: 511,
            journal_blocks: 4096,
            hash_type: "Sha256".to_string(),
            hmac_type: "Sha256".to_string(),
            salt: "0x13371337".to_string(),
            secret: "0xdeadbeef".to_string(),
            lazy: false,
            full: true,
        };
        args.verify();
    }

    #[test]
    #[should_panic]
    fn test_arg_parse_salt() {
        let mut args = Args {
            debug: true,
            mint_dev: "/dev/loop0".to_string(),
            data_dev: "/dev/loop0".to_string(),
            block_size: 512,
            journal_blocks: 4096,
            hash_type: "Sha256".to_string(),
            hmac_type: "Sha256".to_string(),
            salt: "0x133713371".to_string(),
            secret: "0xdeadbeef".to_string(),
            lazy: false,
            full: true,
        };
        args.verify();
    }

    #[test]
    #[should_panic]
    fn test_arg_parse_secret() {
        let mut args = Args {
            debug: true,
            mint_dev: "/dev/loop0".to_string(),
            data_dev: "/dev/loop0".to_string(),
            block_size: 512,
            journal_blocks: 4096,
            hash_type: "Sha256".to_string(),
            hmac_type: "Sha256".to_string(),
            salt: "0x13371337".to_string(),
            secret: "0x1111111122222222333333334444444455".to_string(),
            lazy: false,
            full: true,
        };
        args.verify();
    }
}
