use std::{
	fs::File,
	io::{BufRead, BufReader},
	path::PathBuf,
	sync::Arc,
};

use anyhow::{Result, bail};
use sequoia_openpgp::{fmt::hex, types::HashAlgorithm};

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
	let mut hasher = HashAlgorithm::from(algm).context()?.for_digest();
	loop {
		let buf = reader.fill_buf()?;
		let len = buf.len();
		if len == 0 {
			break;
		}
		hasher.update(buf);
		reader.consume(len);
	}
	let mut digest = vec![0; hasher.digest_size()];
	hasher.digest(&mut digest)?;
	let hash_value = hex::encode(digest).to_ascii_lowercase();
	if hash_value != expected.to_ascii_lowercase() {
		bail!(
			"{:?} Checksum verification failed.\nExpected: {}\nActual:   {}",
			algm,
			expected,
			hash_value
		);
	}
	Ok(())
}
