use std::{
	fs::{self, File, create_dir_all, remove_file},
	net::SocketAddr,
	path::PathBuf,
};

use anyhow::{Context, anyhow};
use log::warn;
use serde::Deserialize;
use url::Url;

#[derive(Copy, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OperationMode {
	#[allow(clippy::upper_case_acronyms)]
	AOSC,
	Debian,
}

#[derive(Deserialize, Clone, Debug)]
pub struct AppConfig {
	/// Hostname for the mirror, for projects/trace generation
	pub hostname: String,
	/// Listening address of the server
	pub listen: Vec<SocketAddr>,
	/// Server token
	pub server_pubkeys: Vec<String>,
	/// Testing mode, skips the signature check.
	pub skip_verification: bool,
	/// Operation Mode
	pub mode: OperationMode,
	/// The URL to mirror
	pub mirror_url: Url,
	/// HTTP URL of the origin server (to fetch the metadata)
	pub http_url: Url,
	/// Root directory of the mirror
	pub mirror_root: PathBuf,
	/// Also mirror the topics (AOSC only)
	pub mirror_topics: bool,
	/// Certificate store
	pub keyring_dir: PathBuf,
	/// Suites to mirror (Debian, Ubuntu, etc.)
	#[serde(default = "default_suites")]
	pub suites: Vec<String>,
	/// Architectures to mirror
	#[serde(default = "default_archs")]
	pub archs: Vec<String>,
	/// Number of parallel jobs
	pub parallel_jobs: u8,
}

fn default_suites() -> Vec<String> {
	vec!["stable".into()]
}

fn default_archs() -> Vec<String> {
	vec![
		"all".into(),
		"amd64".into(),
		"arm64".into(),
		"loongarch64".into(),
		"loongson3".into(),
		"ppc64el".into(),
		"riscv64".into(),
	]
}

pub fn check_config(config: &AppConfig) -> Vec<anyhow::Error> {
	let mut errors = Vec::new();
	// TODO list for Debian mode:
	// - deb-src mirroring
	// - i18n and icons support
	// - Use async_compression for reading gzipped Packages files
	if config.mode == OperationMode::Debian {
		errors.push(anyhow!("Debian mode is currently unfinished"));
	}
	if !config.mirror_url.as_str().ends_with('/') {
		errors.push(anyhow!(
			"Mirror URL must end with a slash, otherwise the path will be overridden"
		));
	}
	if !config.http_url.as_str().ends_with('/') {
		errors.push(anyhow!(
			"Mirror HTTP URL must end with a slash, otherwise the path will be overridden"
		));
	}
	let scheme = config.mirror_url.scheme().to_lowercase();
	if scheme != "rsync" {
		errors.push(anyhow!(
			"Invalid mirror URL scheme: '{}'. Only rsync is supported",
			scheme
		));
	}
	let scheme = config.http_url.scheme().to_lowercase();
	if scheme != "http" && scheme != "https" {
		errors.push(anyhow!(
			"Invalid mirror HTTP URL: '{}', expected http or https",
			scheme
		));
	}
	if config.mirror_root.exists() && !config.mirror_root.is_dir() {
		errors.push(anyhow!(
			"Unable to use {} as mirror root since it is not a directory",
			config.mirror_root.display()
		));
	}
	if config.parallel_jobs > 16 {
		errors.push(anyhow!("Too much concurrency: {}", config.parallel_jobs));
	}
	if config.parallel_jobs < 1 {
		errors.push(anyhow!("Invalid concurrency: {}", config.parallel_jobs));
	}
	if config.mode == OperationMode::Debian && config.suites.is_empty() {
		errors.push(anyhow!("Attempting to mirror a Debian-like APT repository, but no suites specified; Try 'stable', 'stable-updates'"));
	}
	if config.archs.is_empty() {
		warn!(
			"No archictures configured, mirroring all supported architectures on this repository"
		)
	}
	let dir = fs::read_dir(config.keyring_dir.clone()).context(format!(
		"Failed to open '{}' as a directory",
		config.keyring_dir.display()
	));
	if let Err(e) = dir {
		errors.push(e.context(format!(
			"Failed to open {} as keyring directory",
			config.keyring_dir.display()
		)));
	} else {
		let mut dir = dir.unwrap();
		if dir.next().is_none() {
			errors.push(anyhow!("No keyring files are found"));
		}
	}
	if config.server_pubkeys.is_empty() && !config.skip_verification {
		errors.push(anyhow!("Public keys from mirror origin servers required"));
	}
	if config.mirror_root.exists() {
		if !config.mirror_root.is_dir() {
			errors.push(anyhow!(
				"Specified irror root {} is not a directory",
				config.mirror_root.display()
			));
		}
		if let Err(e) = create_dir_all(&config.mirror_root) {
			errors.push(anyhow!(
				"Can't create the mirror root directory {}: {}",
				config.mirror_root.display(),
				e
			));
		}
	}
	let path = config.mirror_root.join(".testfile");
	if let Err(e) = File::create_new(&path) {
		errors.push(anyhow!(
			"Can't write to {}: {} - Check permissions",
			config.mirror_root.display(),
			e
		));
	}
	if let Err(e) = remove_file(&path) {
		errors.push(anyhow!(
			"Can't remove the test file {}: {}",
			config.mirror_root.display(),
			e
		));
	}
	errors
}
