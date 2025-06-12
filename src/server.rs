use std::sync::Arc;

use axum::{
	Router,
	extract::State,
	routing::{get, post},
};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::{AppState, sync::do_sync};

#[derive(Copy, Clone, Deserialize, PartialEq, Serialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Status {
	Success,
	Failed,
}

#[derive(Deserialize, Serialize)]
pub struct SyncRequestBody {
	pub timestamp: i64,
	pub signature: String,
}

#[derive(Deserialize, Serialize)]
pub struct SyncRequestResponse {
	pub status: Status,
	pub message: String,
}

#[derive(Deserialize, Serialize)]
pub struct SyncStatusResponse {
	pub syncing: bool,
	pub last_sync_timestamp: i64,
	pub last_sync_status: Status,
	pub last_sync_message: String,
}

pub async fn status(State(s): State<Arc<RwLock<AppState>>>) -> String {
	let lock = s.read().await;
	serde_json::to_string_pretty(&SyncStatusResponse {
		syncing: lock.syncing,
		last_sync_timestamp: lock.last_sync_timestamp,
		last_sync_status: lock.last_sync_status,
		last_sync_message: lock.last_sync_message.clone(),
	})
	.unwrap()
}

pub fn build_server(s: Arc<RwLock<AppState>>) -> Router {
	// let service = do_sync.with_state(s.clone()).into_make_service_with_connect_info::<SocketAddr>();
	Router::new()
		.route("/do-sync", post(do_sync))
		.route("/status", get(status))
		.with_state(s)
}
