use std::{
	fs::File,
	io::{BufRead, BufReader},
	path::PathBuf,
	sync::Arc,
};

use anyhow::{Result, bail};
use digest::{Digest, DynDigest};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::metadata::AptMetadataHashAlgm;

pub fn checksum_file(
	algm: AptMetadataHashAlgm,
	path: Arc<PathBuf>,
	expected: Arc<String>,
) -> Result<()> {
	let fd = File::options()
		.read(true)
		.write(false)
		.create(false)
		.open(path.as_path())?;
	let mut reader = BufReader::with_capacity(128 * 1024, fd);
	let hash_value = match algm {
		AptMetadataHashAlgm::MD5 => {
			if expected.len() != 32 {
				bail!("Unexpected length {}, expected 32", expected.len());
			}
			let mut context = md5::Context::new();
			loop {
				let buf = reader.fill_buf()?;
				let len = buf.len();
				if len == 0 {
					break;
				}
				context.consume(&buf[..len]);
				reader.consume(len);
			}
			let digest = context.compute();
			format!("{:x}", digest)
		}
		_ => {
			let mut hasher: Box<dyn DynDigest> = match algm {
				AptMetadataHashAlgm::SHA1 => Box::new(Sha1::new()),
				AptMetadataHashAlgm::SHA256 => Box::new(Sha256::new()),
				AptMetadataHashAlgm::SHA512 => Box::new(Sha512::new()),
				_ => unreachable!(),
			};
			loop {
				let buf = reader.fill_buf()?;
				let len = buf.len();
				if len == 0 {
					break;
				}
				hasher.update(buf);
				reader.consume(len);
			}
			let digest = hasher.finalize();
			let mut str_digest = String::new();
			digest.iter()
				.for_each(|x| str_digest.push_str(&format!("{:02x}", x)));
			str_digest
		}
	};
	if hash_value != *expected {
		bail!(
			"{:?} Checksum verification failed.\nExpected: {}\nActual:   {}",
			algm,
			expected,
			hash_value
		);
	}
	Ok(())
}
