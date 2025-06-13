use std::{env, fs::read_to_string, net::SocketAddr, path::{Path, PathBuf}, sync::Arc};

use aosc_mirror::{metadata::split_inrelease, server::Status, sync::do_sync_inner, *};

use anyhow::{Context, Result, anyhow, bail};
use base64::prelude::*;
use chrono::Utc;
use clap::{Parser, Subcommand, command};
use config::AppConfig;
use ed25519_dalek::VerifyingKey;
use log::{error, info};
use metadata::fetch_manifest;
use reqwest::{Client, redirect::Policy};
use server::build_server;
use tokio::{
	fs::{rename, symlink},
	net::TcpListener,
	sync::RwLock,
	task::JoinSet,
};
use verify::{init_pgp_keyringstore, verify_pgp_signature};

use crate::{config::check_config, metadata::AptRepoReleaseInfo};
pub use server::SyncRequestBody;

#[derive(Clone, Subcommand)]
/// The Mirror Sync Client
pub enum AppAction {
	/// Perform the full sync
	Sync,
	/// Start the daemon and listen to the sync requests
	Daemon,
}

#[derive(Parser)]
#[command(version, about)]
pub struct Cmdline {
	#[arg(short = 'c', long = "config")]
	/// Path to the config file
	pub config_file: PathBuf,
	#[command(subcommand)]
	/// Action to execute
	pub action: AppAction,
}

fn check_repo(root: &dyn AsRef<Path>, manifests: Vec<AptRepoReleaseInfo>) -> bool {
	for manifest in manifests {
		let suite_dir = root.as_ref().join("dists").join(manifest.suite);
		let files = manifest.metadata_info.iter().next().unwrap();
		for f in &files.files {
			let full_path = suite_dir.join(&f.path);
			if !full_path.is_file() {
				return false;
			}
		}
	}
	true
}

#[tokio::main]
async fn main() -> Result<()> {
	env_logger::init();
	// console_subscriber::init();
	info!("AOSC OS Mirror Sync Client");
	info!("Please wait, while we perform some checks ...");
	let cmdline = match Cmdline::try_parse() {
		Result::Ok(args) => args,
		Err(e) => {
			// Do not let anyhow to handle this error
			eprintln!("{}", e);
			// let it handle this "error" instead
			bail!("Invalid usage");
		}
	};
	let config_file = &cmdline.config_file;
	let argv0 = env::args().next().unwrap_or("sync-client".into());

	let config: AppConfig = toml::from_str(&read_to_string(config_file)?)
		.context("Unable to read the config file")?;
	let config = Arc::new(config);

	let errors = check_config(&config);
	if !errors.is_empty() {
		let mut error_str = String::from("Error(s) found in config file:\n");
		for e in errors {
			// Build error string
			let mut chain = 1;
			error_str.push_str(&format!("- {}\n", e));
			e.chain().skip(1).for_each(|c| {
				error_str.push_str(&format!("{}> {}\n", "  ".repeat(chain), c));
				chain += 1;
			});
		}
		error!("{}", error_str);
		bail!("Error(s) found in the config file. Refer to the log above for details.")
	}

	// Deserialize server public keys
	let mut server_pubkeys = Vec::new();
	for pubkey in &config.server_pubkeys {
		let bytes = BASE64_STANDARD
			.decode(pubkey)
			.context("Failed to decode server public key as base64 text")?;
		let bytes: [u8; 32] = bytes.try_into().map_err(|_| anyhow!("Unexpected length; Public keys must be 32 bytes long (that is 45 charaters in base64 with padding"))?;
		let pubkey = VerifyingKey::from_bytes(&bytes)?;
		server_pubkeys.push(pubkey);
	}
	let server_pubkeys = Arc::new(server_pubkeys);

	// Initialize the APT trusted keystore.
	let keyring_dir = &config.keyring_dir;
	let keyring_store = init_pgp_keyringstore(keyring_dir).await?;
	let keyring_store = Arc::new(keyring_store);

	let base_url = config.http_url.clone();
	let client = Client::builder()
		.user_agent("Debian APT-HTTP/1.3 (3.0.1)")
		.redirect(Policy::limited(10))
		.build()?;
	// Download the InRelease files before starting, and make sure it can be verified
	// by the keys from the given keystore.
	info!("Checking the validity of the repository metadata ...");
	let mut errors = Vec::<anyhow::Error>::new();
	let mut manifests = Vec::new();
	for suite in &config.suites {
		if let Err(e) = {
			info!(
				"Fetching the InRelease file for suite '{}' from '{}' ...",
				suite, &base_url
			);
			let (inrelease, release) =
				fetch_manifest(base_url.clone(), suite.clone(), &client).await?;
			let info = if let Some(inrelease) = inrelease {
				let (inrelease_body, inrelease_sig) = split_inrelease(&inrelease);
				verify_pgp_signature(
					&inrelease_body,
					&inrelease_sig,
					&keyring_store,
				)?;
				if let Some((release, sig)) = release {
					verify_pgp_signature(&release, &sig, &keyring_store)?;
				}
				AptRepoReleaseInfo::parse_from(&inrelease_body)?
			} else if let Some((release, sig)) = release {
				verify_pgp_signature(&release, &sig, &keyring_store)?;
				AptRepoReleaseInfo::parse_from(&release)?
			} else {
				bail!(
					"No valid InRelease/Release found in the specified repository"
				);
			};
			let diff: Vec<_> = config
				.archs
				.iter()
				.filter(|x| !info.archs.contains(x))
				.collect();
			if !diff.is_empty() {
				bail!(anyhow!(
					"Found architecture(s) not supported by this repo: {:?}",
					diff
				)
				.context(format!(
					"The following architectures are supported:\n{:?}",
					info.archs
				)));
			};
			manifests.push(info);
			Ok(())
		} {
			errors.push(e);
		}
	}
	if !errors.is_empty() {
		let mut error_str = String::from("Error(s) found in config file:\n");
		for e in errors {
			let mut chain = 1;
			error_str.push_str(&format!("- {}\n", e));
			e.chain().skip(1).for_each(|c| {
				error_str.push_str(&format!("{}> {}\n", "  ".repeat(chain), c));
				chain += 1;
			});
		}
		error!("{}", error_str);
		bail!(
			"Your config file does not align with the upstream repository. See the log above for details."
		)
	}

	let now = Utc::now().timestamp();
	// Prepare the dists/ directory
	// If dists/ is a directory, move it to dists-{cur_timestamp} and make a symlink to that.
	let dists = config.mirror_root.join("dists");
	if dists.exists() && !dists.is_symlink() && dists.is_dir() {
		info!("Replacing dists/ with a symlink to dists-{}/ ...", now - 1);
		let new_name = config.mirror_root.join(format!("dists-{}", now - 1));
		rename(&dists, &new_name)
			.await
			.context(format!("Unable to move dists/ to {}/", new_name.display()))?;
		symlink(&new_name, &dists).await.context(format!(
			"Unable to create symlink at {} -> {}",
			dists.display(),
			new_name.display()
		))?;
	}

	// Mutable shared state to share across different async tasks.
	let state = Arc::new(RwLock::new(AppState {
		syncing: false,
		config: config.clone(),
		last_sync_timestamp: now,
		last_sync_status: server::Status::Success,
		last_sync_message: String::new(),
		server_pubkeys,
		keyring_store,
		client,
	}));
	match cmdline.action {
		AppAction::Daemon => {
			info!("Checking the repository ...");
			if !check_repo(&config.mirror_root, manifests) {
				bail!("Looks like you don't have a full copy of the mirrored repository.\n".to_owned() + 
				&"Please run the following command to initialize a full copy:\n\n".to_owned() +
				&format!("{} -c {} sync", argv0, config_file.display()));
			};
			// Start the server
			info!("Starting server ...");
			let s = build_server(state)
				.into_make_service_with_connect_info::<SocketAddr>();
			let mut tasks = JoinSet::new();
			// let mut tasks = Vec::new();
			for addr in &config.listen {
				let listener = TcpListener::bind(addr)
					.await
					.context(format!("Failed to bind to {}", addr))?;
				info!("Listening on {}", addr);
				let s = s.clone();
				tasks.spawn(async move { axum::serve(listener, s).await });
			}
			info!("Sync server started, waiting for requests ...");
			while let Some(r) = tasks.join_next().await {
				r??;
			}
		}
		AppAction::Sync => {
			do_sync_inner(state.clone(), now).await;
			let lock = state.read().await;
			if lock.last_sync_status == Status::Failed {
				let e = anyhow!(lock.last_sync_message.clone())
					.context("Sync job failed");
				bail!(e);
			}
		}
	}
	Ok(())
}
