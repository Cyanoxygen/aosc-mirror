use std::{
	env,
	fs::{File, create_dir_all},
	io::BufWriter,
	path::PathBuf,
	sync::Arc,
	time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use aosc_mirror::server::SyncRequestBody;
use base64::prelude::*;
use chrono::{Local, Utc};
use clap::{Parser, Subcommand, command};
use ed25519_dalek::{SECRET_KEY_LENGTH, SigningKey, ed25519::signature::SignerMut};
use log::{error, info};
use rand::{TryRngCore, rngs::OsRng};
use reqwest::{Client, redirect::Policy};
use serde::Serialize;
use serde_json::json;
use tokio::{
	fs::read_to_string,
	io::{AsyncReadExt, stdin},
	task::JoinSet,
};
use url::Url;

#[derive(Debug, Clone, Subcommand)]
enum Action {
	/// Generate a private key
	Genkey,
	/// Generate a public key from the given private key
	Pubkey,
	/// Trigger the sync process by invoking endpoints
	Invoke {
		/// Path to the private key file
		#[arg(short, long)]
		private_key: PathBuf,
		/// Path to the list of endpoints to invoke
		#[arg(short, long)]
		endpoint_list: Option<PathBuf>,
		/// Timestamp of the generated metadata file
		#[arg(short, long)]
		timestamp: i64,
		#[arg(short, long)]
		/// Directory to generate reports
		report_dir: PathBuf,
		#[arg(short = 'T', long, default_value = "10")]
		/// Max connection time for a timeout
		timeout: u32,
		/// Number of concurrent jobs
		#[arg(short, long, default_value = "4")]
		jobs: u8,
		/// List of endpoints
		endpoints: Option<Vec<Url>>,
	},
}

#[derive(Parser, Debug)]
#[command(version, about)]
/// Program to invoke real-time syncing with signed signature
struct Args {
	#[command(subcommand)]
	action: Action,
}

#[derive(Serialize, PartialEq)]
#[serde(tag = "status", rename_all = "lowercase")]
enum ClientInvocationStatus {
	Succeeded,
	Failed { reason: String },
}

#[derive(Serialize)]
struct ReportEntry {
	endpoint: Url,
	#[serde(flatten)]
	status: ClientInvocationStatus,
}

#[derive(Serialize)]
struct InvocationReport {
	req_timestamp: i64,
	start_timestamp: i64,
	end_timestamp: i64,
	num_clients: u32,
	num_succeeded: u32,
	num_failed: u32,
	endpoints: Vec<ReportEntry>,
}

async fn invoke_queue(queue: Vec<Url>, client: Client, body: Arc<String>) -> Vec<ReportEntry> {
	let mut status_list = Vec::new();
	for endpoint in queue {
		let body = body.as_ref();
		let res = match client
			.post(endpoint.clone())
			.header("Content-Type", "application/json")
			.body(body.clone())
			.send()
			.await
		{
			Ok(r) => r,
			Err(e) => {
				error!("FAILED: {} ({})", endpoint, e);
				let status = ClientInvocationStatus::Failed {
					reason: e.to_string(),
				};
				status_list.push(ReportEntry { endpoint, status });
				continue;
			}
		};
		match res.error_for_status_ref() {
			Ok(_) => {
				info!("SUCCEED: {}", endpoint);
				let status = ClientInvocationStatus::Succeeded;
				status_list.push(ReportEntry { endpoint, status });
			}
			Err(e) => {
				error!("FAILED: {} ({})", endpoint, e);
				let status = ClientInvocationStatus::Failed {
					reason: e.to_string(),
				};
				status_list.push(ReportEntry { endpoint, status });
			}
		}
		tokio::time::sleep(Duration::from_millis(250)).await;
	}
	status_list
}

#[tokio::main]
async fn main() -> Result<()> {
	let args = match Args::try_parse() {
		Ok(args) => args,
		Err(e) => {
			// Do not let anyhow to handle this error
			eprintln!("{}", e);
			// let it handle this "error" instead
			bail!("Invalid usage");
		}
	};
	match args.action {
		Action::Genkey => {
			let mut rng = OsRng;
			let mut buf = [0u8; SECRET_KEY_LENGTH];
			rng.try_fill_bytes(&mut buf)
				.context("Failed to acquire random bytes for keys")?;
			let private_key = SigningKey::from_bytes(&buf);
			println!("{}", BASE64_STANDARD.encode(private_key.as_bytes()));
			Ok(())
		}
		Action::Pubkey => {
			let argv0 = env::args().next().unwrap_or_default();
			let usage =
				format!("Invalid usage\nUsage:\n    cat key | {} pubkey", argv0);
			let mut buf = String::new();
			stdin().read_to_string(&mut buf)
				.await
				.context(usage.clone())?;
			let decoded = BASE64_STANDARD.decode(buf.trim()).context(usage.clone())?;
			let bytes = decoded
				.try_into()
				.map_err(|_| anyhow!("Invalid input"))
				.context(usage)?;
			let private_key = SigningKey::from_bytes(&bytes);
			println!(
				"{}",
				BASE64_STANDARD.encode(private_key.verifying_key().as_bytes())
			);
			eprintln!(
				"{}: Remember to distribute the PUBLIC key to your downstream mirrors!",
				argv0
			);
			eprintln!("{}: Keep your PRIVATE key safe.", argv0);
			Ok(())
		}
		Action::Invoke {
			private_key,
			endpoint_list,
			timestamp,
			report_dir,
			jobs,
			timeout,
			endpoints,
		} => {
			env_logger::init();
			let mut endpoints_vec = Vec::new();
			if let Some(l) = endpoint_list {
				let endpoints_fd = read_to_string(l)
					.await
					.context("Failed to read the endpoints list file")?;
				for endpoint in endpoints_fd.lines() {
					let url = Url::parse(endpoint).context(format!(
						"Failed to parse '{}' as a URL",
						endpoint
					))?;
					endpoints_vec.push(url);
				}
			}
			if let Some(l) = endpoints {
				endpoints_vec.extend(l);
			};
			if endpoints_vec.is_empty() {
				bail!("No endpoints specified");
			}

			let private_key_fd = read_to_string(private_key)
				.await
				.context("Failed to read the private key file")?;
			let key = BASE64_STANDARD.decode(private_key_fd.trim())?;
			let bytes = key.try_into().map_err(|_| {
				anyhow!("Unexpected length; Private keys must be 32 bytes long")
			})?;
			let mut private_key = SigningKey::from_bytes(&bytes);
			let sig = BASE64_STANDARD.encode({
				private_key
					.sign(timestamp.to_string().as_bytes())
					.to_bytes()
			});
			info!("Timestamp: {}", timestamp);
			info!("Signature: {}", sig);
			let req_body = Arc::new(
				json!(SyncRequestBody {
					timestamp,
					signature: sig,
				})
				.to_string(),
			);

			let client = Client::builder()
				.timeout(Duration::from_secs(timeout.into()))
				.redirect(Policy::limited(10))
				.user_agent("aosc-mirror/0.1.0")
				.build()?;

			let actual_num_jobs = endpoints_vec.len().clamp(1, jobs.into());
			let mut queues = Vec::new();
			for _ in 1..=actual_num_jobs {
				let queue = Vec::<Url>::new();
				queues.push(queue);
			}
			let len = endpoints_vec.len();
			for (q_idx, endpoint) in endpoints_vec.into_iter().enumerate() {
				let queue = queues.get_mut(q_idx).unwrap();
				queue.push(endpoint);
			}
			info!(
				"Invoking {} clients with {} parallel jobs",
				len, actual_num_jobs
			);
			let start_timestamp = Utc::now().timestamp();
			let mut tasks = JoinSet::new();
			for queue in queues {
				let client = client.clone();
				let body = req_body.clone();
				tasks.spawn(async move { invoke_queue(queue, client, body).await });
			}
			let mut results = Vec::new();
			while let Some(t) = tasks.join_next().await {
				results.extend(t?);
			}
			let report = InvocationReport {
				req_timestamp: timestamp,
				start_timestamp,
				end_timestamp: Utc::now().timestamp(),
				num_clients: len as u32,
				num_succeeded: results
					.iter()
					.filter(|r| r.status == ClientInvocationStatus::Succeeded)
					.count() as u32,
				num_failed: results
					.iter()
					.filter(|r| r.status != ClientInvocationStatus::Succeeded)
					.count() as u32,
				endpoints: results,
			};
			info!("Done invoking clients. Generating report ...");
			let localdate = Local::now();
			let localdate = localdate.format("%Y%m%d").to_string();
			create_dir_all(&report_dir)
				.context("Failed to create the report directory")?;
			let path =
				report_dir.join(format!("report-{}-{}.json", localdate, timestamp));
			info!("Report file: {}", path.display());
			let fd = File::options()
				.create(true)
				.truncate(true)
				.append(false)
				.write(true)
				.open(path)?;
			let writer = BufWriter::new(fd);
			serde_json::to_writer_pretty(writer, &report)?;
			info!("Generation complete. Program Finished.");
			Ok(())
		}
	}
}
