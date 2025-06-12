use std::{
	collections::HashMap,
	fs::{File, read},
	io::Read,
	path::Path,
	time::SystemTime,
};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, prelude::BASE64_STANDARD};
use ed25519_dalek::{Signature, VerifyingKey};
use log::{debug, info, warn};
use sequoia_openpgp::{
	Cert, KeyHandle, KeyID,
	armor::{self, ReaderMode},
	cert::CertParser,
	packet::UserID,
	parse::{
		PacketParser, Parse,
		stream::{DetachedVerifierBuilder, MessageStructure, VerificationHelper},
	},
	policy::StandardPolicy,
	types::RevocationStatus,
};
use walkdir::WalkDir;

struct Helper<'a> {
	store: &'a PgpKeyringStore,
}

static SP: StandardPolicy = StandardPolicy::new();

impl VerificationHelper for Helper<'_> {
	fn get_certs(&mut self, ids: &[KeyHandle]) -> Result<Vec<Cert>> {
		let mut res = Vec::new();
		for k in ids {
			let k = KeyID::from_bytes(k.as_bytes());
			if let Some(c) = self.store.get(&k) {
				if c.cert.revocation_status(&SP, SystemTime::now())
					== RevocationStatus::NotAsFarAsWeKnow
				{
					debug!("Found certificate in keyring: {} {}", &k, &c.uid);
					res.push(c.cert.clone());
				}
			}
		}
		Ok(res)
	}

	fn check(&mut self, _: MessageStructure) -> Result<()> {
		Ok(())
	}
}

#[derive(PartialEq, Eq, Debug)]
enum KeyringType {
	Binary,
	AsciiArmored,
}

#[derive(Clone, Debug)]
pub struct PgpKeyringStoreEnt {
	// We need this to display the UID to the console
	uid: UserID,
	cert: Cert,
}

pub type PgpKeyringStore = HashMap<KeyID, PgpKeyringStoreEnt>;

pub async fn init_pgp_keyringstore(keystore_dir: &dyn AsRef<Path>) -> Result<PgpKeyringStore> {
	info!("Initializing APT trusted keys ...");
	info!("- Using directory {}", keystore_dir.as_ref().display());
	let walkdir = WalkDir::new(keystore_dir).max_depth(2).follow_links(true);
	let mut keyring_store = PgpKeyringStore::new();
	for ent in walkdir.into_iter() {
		let ent = ent?;
		if !ent.file_type().is_file() {
			continue;
		}
		let path = ent.path();
		let cert_type: KeyringType;
		match ent.file_name().to_string_lossy().split(".").last() {
			Some(ext) => match ext {
				"gpg" | "pgp" => {
					cert_type = KeyringType::Binary;
				}
				"asc" => {
					cert_type = KeyringType::AsciiArmored;
				}
				_ => {
					warn!(
						"Keyring file {} has unknown file extension, skipping",
						path.display()
					);
					continue;
				}
			},
			None => {
				warn!(
					"Keyring file {} has no file extension, skipping",
					path.display()
				);
				continue;
			}
		}
		debug!("Processing {}", path.display());
		let keyfile = File::options().read(true).open(path)?;
		let key_data = if cert_type == KeyringType::AsciiArmored {
			let mut r = armor::Reader::from_reader(
				keyfile,
				ReaderMode::Tolerant(Some(armor::Kind::PublicKey)),
			);
			let mut buf = Vec::new();
			r.read_to_end(&mut buf)?;
			buf
		} else {
			// Keyring in binary format
			read(path)?
		};
		let ppr = PacketParser::from_bytes(&key_data)?;
		for cert in CertParser::from(ppr) {
			if cert.is_err() {
				bail!("Unable to read keyring file {}", path.display());
			}
			let cert = cert?;
			let key_id = cert.keyid().clone();
			let first_uid = cert.userids().next().ok_or(anyhow!(
				"No UIDs found in the certificate {}",
				path.display()
			))?;
			let first_uid = first_uid.userid().clone();
			if keyring_store.contains_key(&key_id) {
				debug!(
					"Duplicate key found: {} ({}), from file {}",
					&first_uid,
					&key_id,
					path.display()
				);
				// Duplicate key found, ignore it
				continue;
			}
			debug!("Registering {} {}", &key_id, &first_uid);
			let ent = PgpKeyringStoreEnt {
				uid: first_uid,
				cert,
			};
			keyring_store.insert(key_id, ent);
		}
	}
	info!("{} keys in the APT trusted keystore.", keyring_store.len());
	Ok(keyring_store)
}

pub fn verify_pgp_signature(
	message: &dyn AsRef<str>,
	sig: &dyn AsRef<str>,
	keyring_store: &PgpKeyringStore,
) -> Result<()> {
	info!("Verifying metadata signatures ...");
	let message = message.as_ref();
	let sig = sig.as_ref();
	let h = Helper {
		store: keyring_store,
	};
	let mut v = DetachedVerifierBuilder::from_bytes(sig)?.with_policy(
		&SP,
		Some(SystemTime::now()),
		h,
	)?;
	v.verify_bytes(message)?;
	info!("PGP signature verified.");
	Ok(())
}

pub fn verify_request_signature(
	msg: &dyn AsRef<str>,
	sig: &dyn AsRef<str>,
	keys: &Vec<VerifyingKey>,
) -> Result<()> {
	let msg = msg.as_ref().as_bytes();
	let sig = BASE64_STANDARD
		.decode(sig.as_ref())
		.context("Unable to decode the signature as base64 encoded text")?;
	let sig = sig
		.try_into()
		.map_err(|_| anyhow!("Unexpected signature length - must be 64 bytes long"))?;
	let sig = Signature::from_bytes(&sig);
	for key in keys {
		if key.verify_strict(msg, &sig).is_ok() {
			return Ok(());
		}
	}
	bail!("Unknown signature - Check your public keys");
}

#[tokio::test]
async fn test_keystore() -> Result<()> {
	env_logger::builder()
		.filter_level(log::LevelFilter::Debug)
		.init();
	init_pgp_keyringstore(&"/etc/apt/trusted.gpg.d").await?;
	Ok(())
}
