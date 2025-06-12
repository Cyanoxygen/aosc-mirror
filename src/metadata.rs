use std::{
	collections::{HashMap, HashSet},
	io::{BufRead, BufReader},
	path::PathBuf,
	sync::Arc,
};

use anyhow::{Context, Result, anyhow, bail};
use deb822_lossless::Deb822;
use futures_util::StreamExt;
use log::{debug, info, warn};
use reqwest::Client;
use sequoia_openpgp::types::HashAlgorithm;
use tokio::{
	fs::{File, create_dir_all, symlink},
	io::{AsyncWriteExt, BufWriter, copy},
};

use url::Url;

use crate::{config::OperationMode, utils::checksum_file};

const MAGIC: &str = "-----BEGIN PGP SIGNED MESSAGE-----";
const SIG_MAGIC: &str = "-----BEGIN PGP SIGNATURE-----";

// The only thing we are interested in the Packages file is the path of the deb package.
// Integrity are verified by rsync.
pub type PackageFileEntry = String;
pub type PackageFileList = Vec<PackageFileEntry>;

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum AptMetadataHashAlgm {
	// Used by Debian and Ubuntu
	MD5,
	// Used by Debian and Ubuntu (some releases)
	SHA1,
	// Used by AOSC and Debian
	SHA256,
	// Haven't seen one yet
	SHA512,
}

impl AptMetadataHashAlgm {
	fn parse(v: &dyn AsRef<str>) -> Result<AptMetadataHashAlgm> {
		let v = v.as_ref();
		match v {
			"MD5Sum" => Ok(AptMetadataHashAlgm::MD5),
			"SHA1" => Ok(AptMetadataHashAlgm::SHA1),
			"SHA256" => Ok(AptMetadataHashAlgm::SHA256),
			"SHA512" => Ok(AptMetadataHashAlgm::SHA512),
			_ => {
				bail!("Invalid string {}", v);
			}
		}
	}
}

impl From<AptMetadataHashAlgm> for HashAlgorithm {
	fn from(value: AptMetadataHashAlgm) -> Self {
		match value {
			AptMetadataHashAlgm::SHA256 => HashAlgorithm::SHA256,
			AptMetadataHashAlgm::SHA512 => HashAlgorithm::SHA512,
			AptMetadataHashAlgm::SHA1 => HashAlgorithm::SHA1,
			AptMetadataHashAlgm::MD5 => HashAlgorithm::MD5,
		}
	}
}

#[derive(Debug)]
pub struct AptMetadataFileEntry {
	pub hash: String,
	pub size: usize,
	pub path: PathBuf,
}

#[derive(Debug)]
pub struct AptMetadataInfo {
	pub hash_algo: AptMetadataHashAlgm,
	pub files: Vec<AptMetadataFileEntry>,
}

// Well we might only interested in archs, components and file hashes.
#[derive(Debug)]
/// Partially represents a Release/InRelease file.
pub struct AptRepoReleaseInfo {
	// pub origin: String,
	// pub label: String,
	pub suite: String,
	pub codename: String,
	// pub description: String,
	// pub date: DateTime<FixedOffset>,
	pub archs: Vec<String>,
	pub components: Vec<String>,
	pub acquire_by_hash: bool,
	pub metadata_info: Vec<AptMetadataInfo>,
	// We might not interested on this.
	// other_fields: HashMap<String, String>,
}

impl AptRepoReleaseInfo {
	pub fn parse_from(s: &dyn AsRef<str>) -> Result<AptRepoReleaseInfo> {
		let (parsed, _) = Deb822::from_str_relaxed(s.as_ref());
		let p = parsed
			.paragraphs()
			.next()
			.ok_or(anyhow!("Invalid InRelease structure"))?;
		// let origin = p.get("Origin").unwrap();
		// let label = p.get("Label").unwrap();
		let suite = p.get("Suite").context("Expected keys not found")?;
		let codename = p.get("Codename").context("Expected keys not found")?;
		// let description = p.get("Description").unwrap();
		// let date = p.get("Date").unwrap().replace("UTC", "+0000");
		// let date = DateTime::parse_from_rfc2822(&date)?;
		let archs = p
			.get("Architectures")
			.context("Expected keys not found")?
			.split_ascii_whitespace()
			.map(|x| x.into())
			.collect();
		let components = p
			.get("Components")
			.context("Expected keys not found")?
			.split_ascii_whitespace()
			.map(|x| x.into())
			.collect();
		let acquire_by_hash = if p.contains_key("Acquire-By-Hash") {
			let v = p.get("Acquire-By-Hash").unwrap();
			&v == "yes"
		} else {
			false
		};
		let mut metadata_info = Vec::new();
		for hashtype in ["MD5Sum", "SHA1", "SHA256", "SHA512"] {
			if !p.contains_key(hashtype) {
				continue;
			}
			let mut files = Vec::new();
			let unparsed_ent = p.get(hashtype).unwrap();
			for l in unparsed_ent.lines() {
				let mut s = l.split_whitespace();
				let hash = s
					.next()
					.ok_or(anyhow!("Invalid file info entry structure"))?
					.into();
				let size: usize = s.next().unwrap().parse()?;
				let path = s.next().unwrap().into();
				let ent = AptMetadataFileEntry { hash, size, path };
				files.push(ent);
			}
			let hash_info = AptMetadataInfo {
				hash_algo: AptMetadataHashAlgm::parse(&hashtype)?,
				files,
			};
			metadata_info.push(hash_info);
		}
		Ok(AptRepoReleaseInfo {
			// origin,
			// label,
			suite,
			codename,
			// description,
			// date,
			archs,
			components,
			acquire_by_hash,
			metadata_info,
		})
	}
}

#[inline]
async fn fetch_to_string(url: Url, client: &Client) -> Result<String> {
	let req = client.get(url).build()?;
	let res = client.execute(req).await?.error_for_status()?;
	res.text()
		.await
		.context("Failed to decode response body as UTF-8 text")
}

pub async fn fetch_manifest(
	base_url: Url,
	suite: String,
	client: &Client,
) -> Result<(Option<String>, Option<(String, String)>)> {
	info!("Fetching APT repository manifests ...");
	let url_in_release = base_url.join(format!("dists/{}/InRelease", suite).as_str())?;
	let url_release = base_url.join(format!("dists/{}/Release", suite).as_str())?;

	// Check InRelease first
	debug!("Trying {} ...", &url_in_release);
	let req = client.head(url_in_release).build()?;
	let res = client
		.execute(req)
		.await
		.context("Failed to get infromation of the manifest")?;
	let mut inrelease = None;
	if res.status().is_success() {
		inrelease = fetch_InRelease(base_url.clone(), suite.clone(), client)
			.await
			.context("Failed to fetch the repository manifest files")?;
	} else {
		debug!("InRelease file doesn't exist, trying {} ...", &url_release);
	}
	let req = client.head(url_release).build()?;
	let res = client
		.execute(req)
		.await
		.context("Failed to get infromation of the manifest")?;
	let mut release = None;
	if res.status().is_success() {
		release = fetch_Release(base_url.clone(), suite.clone(), client)
			.await
			.context("Failed to fetch the repository manifest files")?;
	} else if inrelease.is_none() {
		bail!(
			"Specified repository at '{}' has neither InRelease or Release file. Can not continue.",
			base_url
		);
	}

	Ok((inrelease, release))
}

#[allow(clippy::too_many_arguments)]
async fn download_metadata_inner(
	base_url: Url,
	queue: HashMap<PathBuf, (u32, String)>,
	algm: AptMetadataHashAlgm,
	timestamp: i64,
	dst: PathBuf,
	suite: String,
	client: Client,
	total_files: u32,
) -> Result<()> {
	let tmp_dst = Arc::new(dst.join(format!("dists-{}/{}", timestamp, &suite)));
	let dst = Arc::new(dst.join(format!("dists/{}/", &suite)));
	for f in queue {
		let rel_path = Arc::new(f.0);
		let hash = Arc::new(f.1.1);
		let http_url = base_url.join(&rel_path.to_string_lossy())?;
		let local_file = Arc::new(dst.join(rel_path.as_path()));
		let tmpdist_local_file = Arc::new(tmp_dst.join(rel_path.as_path()));
		let dir = tmpdist_local_file.parent().context("Invalid path")?;
		create_dir_all(dir).await?;
		if local_file.is_file() {
			let path = local_file.clone();
			let hash = hash.clone();
			if tokio::task::spawn_blocking(move || checksum_file(algm, path, hash))
				.await?
				.is_ok()
			{
				info!(
					"[{}/{}] '{}' is up to date.",
					f.1.0,
					total_files,
					rel_path.display()
				);
				tokio::fs::copy(local_file.as_path(), tmpdist_local_file.as_path())
					.await
					.context(format!(
						"Failed to copy '{}' to '{}'",
						local_file.display(),
						tmpdist_local_file.display()
					))?;
				continue;
			};
		}
		let dst_fd = File::options()
			.create(true)
			.append(false)
			.truncate(true)
			.write(true)
			.open(tmpdist_local_file.clone().as_path())
			.await?;
		let mut writer = BufWriter::with_capacity(1024 * 1024, dst_fd);
		client.head(http_url.clone())
			.send()
			.await?
			.error_for_status()?;
		let res = client.get(http_url).send().await?;
		let mut stream = res.bytes_stream();
		while let Some(c) = stream.next().await {
			let chunk = c?;
			copy(&mut &chunk[..], &mut writer).await?;
		}
		writer.flush().await?;
		let handle = tokio::task::spawn_blocking(move || {
			checksum_file(algm, tmpdist_local_file, hash)
		});
		handle.await??;
		info!(
			"[{}/{}] Downloaded '{}'",
			f.1.0,
			total_files,
			rel_path.display()
		);
	}
	Ok(())
}

pub async fn download_metadata_files(
	base_url: &Url,
	manifest: &AptRepoReleaseInfo,
	dst: PathBuf,
	timestamp: i64,
	mode: OperationMode,
	parallel_jobs: u32,
	client: &Client,
) -> Result<()> {
	let suite = &manifest.suite;
	let codename = &manifest.codename;
	// Create a symbolic link with the name of dists/<suite>, points to dists/<codename>.
	// Align with debmirror(8).
	if mode == OperationMode::Debian && codename != suite {
		let symlink_file = dst.join(format!("dists-{}/{}", timestamp, suite));
		debug!(
			"Creating symbolic link {} -> {}",
			symlink_file.display(),
			codename
		);
		create_dir_all(dst.join(format!("dists-{}/{}/", timestamp, codename))).await?;
		symlink(codename, symlink_file).await?;
	}
	let base_url = base_url.join(&format!("dists/{}/", suite))?;
	let mut queues = (0..parallel_jobs)
		.map(|_| HashMap::<PathBuf, (u32, String)>::new())
		.collect::<Vec<_>>();
	// Prefer SHA256/SHA512 over SHA1 and MD5.
	let f = &manifest.metadata_info.iter().find(|x| {
		x.hash_algo == AptMetadataHashAlgm::SHA256
			|| x.hash_algo == AptMetadataHashAlgm::SHA512
	});
	let info = if let Some(info) = f {
		info
	} else if let Some(info) = manifest.metadata_info.first() {
		info
	} else {
		bail!("No file hash info is found!");
	};

	let mut idx: u32 = 0;
	for f in &info.files {
		if mode == OperationMode::Debian
			&& (!f.path.extension().is_some_and(|x| {
				["gz", "xz", "bz2"].contains(&x.to_str().unwrap())
			}) && f.path.file_name().is_some_and(|x| x != "Release"))
		{
			continue;
		}
		let q_idx = (idx % parallel_jobs) as usize;
		let queue = queues
			.get_mut(q_idx)
			.context("Failed to create download queues")?;
		idx += 1;
		queue.insert(f.path.clone(), (idx, f.hash.clone()));
	}
	info!(
		"Downloading {} files with {} threads ...",
		idx, parallel_jobs
	);
	let mut handles = Vec::new();
	for (i, q) in queues.into_iter().enumerate() {
		let base_url = base_url.clone();
		let dst = dst.clone();
		let client = client.clone();
		let suite = suite.clone();
		let algo = info.hash_algo;
		debug!("Spawning thread {} with {} files", i, q.len());
		handles.push(tokio::spawn(async move {
			download_metadata_inner(
				base_url, q, algo, timestamp, dst, suite, client, idx,
			)
			.await
			.context("Unable to download metadata files")
		}));
	}
	let iter = handles.into_iter();
	for r in iter {
		r.await??;
	}
	Ok(())
}

#[allow(non_snake_case)]
async fn fetch_Release(
	base_url: Url,
	suite: String,
	client: &Client,
) -> Result<Option<(String, String)>> {
	let url_Release = base_url.join(format!("dists/{}/Release", suite).as_str())?;
	let url_Release_sig = base_url.join(format!("dists/{}/Release.gpg", suite).as_str())?;

	let body = fetch_to_string(url_Release, client).await?;
	let sig = fetch_to_string(url_Release_sig, client).await?;
	Ok(Some((body, sig)))
}

#[allow(non_snake_case)]
async fn fetch_InRelease(base_url: Url, suite: String, client: &Client) -> Result<Option<String>> {
	let url = base_url.join(format!("dists/{}/InRelease", suite).as_str())?;

	let buf = fetch_to_string(url.clone(), client).await?;
	let magic = buf
		.lines()
		.next()
		.ok_or(anyhow!("Bad response: {}", &buf))?;
	if magic != MAGIC {
		bail!(
			"Bad magic in the fetched InRelease content from URL {}",
			url
		);
	}

	Ok(Some(buf))
}

pub fn split_inrelease(content: &dyn AsRef<str>) -> (String, String) {
	#[derive(PartialEq)]
	enum State {
		None,
		InHeader,
		InContent,
		InSignature,
	}
	let content = content.as_ref();
	let mut state = State::None;
	let iter = content.lines();
	let mut body = String::new();
	let mut sig = String::new();
	for l in iter {
		if l == MAGIC {
			state = State::InHeader;
			continue;
		}
		if l == SIG_MAGIC {
			sig += &format!("{}\n", l);
			state = State::InSignature;
			continue;
		}
		if l.is_empty() {
			if state == State::InSignature {
				sig += "\n";
			}
			if state == State::InHeader {
				state = State::InContent;
			}
			continue;
		}
		match state {
			State::InContent => {
				body += &format!("{}\n", l);
			}
			State::InSignature => {
				sig += &format!("{}\n", l);
			}
			_ => {}
		}
	}
	(body, sig)
}

/// Collect the files to mirror, for each architecture in each suite.
/// This may take a few seconds. So please use [`tokio::task::spawn_blocking`].
pub fn get_files(
	mirror_root: PathBuf,
	suites: HashMap<String, Vec<String>>,
	archs: Vec<String>,
	timestamp: i64,
	num_queues: u8,
) -> Result<(HashSet<String>, Vec<PackageFileList>)> {
	info!("Collecting files from {} dists ...", suites.len());
	let mut files = Vec::new();
	for suite in &suites {
		for component in suite.1 {
			let temp_dists_dir = mirror_root
				.join(format!("dists-{}/{}/{}/", timestamp, suite.0, component));
			for arch in &archs {
				let packages_path =
					temp_dists_dir.join(format!("binary-{}/Packages", arch));
				if !packages_path.exists() || !packages_path.is_file() {
					warn!(
						"Component {} in suite {} doesn't support architecture {}. Skipping.",
						component, suite.0, arch
					);
					continue;
				}
				let fd = std::fs::File::options()
					.create(false)
					.append(false)
					.read(true)
					.write(false)
					.open(&packages_path)?;
				let reader = BufReader::with_capacity(256 * 1024, fd);
				let mut lines = reader.lines();
				// Not using deb822 to save energy.
				while let Some(Ok(l)) = lines.next() {
					if !l.starts_with("Filename: ") {
						continue;
					}
					let path = l
						.split_whitespace()
						.nth(1)
						.context("Invalid Packages content")?;
					debug!("New file: {}", path);
					files.push(path.into());
				}
			}
		}
	}
	if files.is_empty() {
		bail!("Internal error: No files collected");
	}
	files.sort();
	let hashset: HashSet<String> = files.iter().cloned().collect();
	info!("There are {} files currently known to us.", files.len());
	// Distribute files
	// It's better to split this list into chunks, rather than round-robin them.
	// This is for reducing the server load (rsync treats file lists specially).
	let mut queues = Vec::new();
	let each_size = files.len().div_ceil(num_queues as usize);
	files.chunks(each_size)
		.for_each(|x| queues.push(x.to_vec()));
	Ok((hashset, queues))
}

#[tokio::test]
#[allow(non_snake_case)]
async fn test_fetch_manifest() -> Result<()> {
	use reqwest::redirect::Policy;
	env_logger::builder()
		.filter_level(log::LevelFilter::Debug)
		.init();
	let (inrelease, _) = fetch_manifest(
		"https://repo-hk.aosc.io/anthon/debs/".parse()?,
		"stable".into(),
		&Client::builder()
			.user_agent("Debian APT-HTTP/1.3 (3.0.1)")
			.redirect(Policy::limited(10))
			.build()?,
	)
	.await?;
	let body = inrelease.context("Expected InRelease to exist")?;
	let (body, sig) = split_inrelease(&body);
	assert!(body.lines().next().unwrap() != MAGIC);
	assert!(body.lines().next().unwrap() != SIG_MAGIC);
	assert!(sig.lines().next().unwrap() == SIG_MAGIC);
	assert!(sig.lines().next().unwrap() != MAGIC);
	let repo_info = AptRepoReleaseInfo::parse_from(&body)?;
	info!("Parsed InRelease: ");
	eprintln!("{:#?}", repo_info);
	Ok(())
}
