use std::sync::Arc;

use ed25519_dalek::VerifyingKey;
use reqwest::Client;

use crate::{config::AppConfig, server::Status, verify::PgpKeyringStore};

pub mod aosc;
pub mod config;
pub mod debian;
pub mod metadata;
pub mod server;
pub mod sync;
pub mod utils;
pub mod verify;

#[derive(Clone)]
pub struct AppState {
	// Status flags
	pub syncing: bool,
	pub config: Arc<AppConfig>,
	pub last_sync_timestamp: i64,
	pub last_sync_status: Status,
	pub last_sync_message: String,
	pub keyring_store: Arc<PgpKeyringStore>,
	pub server_pubkeys: Arc<Vec<VerifyingKey>>,
	// reqwest uses Arc internally.
	pub client: Client,
}
