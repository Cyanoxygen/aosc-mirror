use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};

/// Represents a topic. Serializes to /var/lib/atm/state.
#[derive(Deserialize, Serialize, Clone)]
// arch and draft are not used
#[allow(dead_code)]
pub struct Topic {
	/// Topic name.
	pub name: String,
	/// Topic description.
	pub description: Option<String>,
	/// Date of the launch - as time64_t.
	pub date: i64,
	/// Update date of this topic - as time_t.
	pub update_date: i64,
	/// Available archs in this topic.
	pub arch: Vec<String>,
	/// Affected packages in this topic.
	pub packages: Vec<String>,
	/// Whether the corresponding PR is a draft.
	pub draft: bool,
}

// If you want to use downstream mirrors for fetch topic manifests, you
// shouldn't use this program anyway.
const TOPIC_MANIFEST_URL: &str = "https://repo-hk.aosc.io/debs/manifest/topics.json";

pub async fn fetch_topics(client: Client) -> Result<Vec<Topic>> {
	eprintln!("Fetching topics manifest ...");
	let response = client.get(TOPIC_MANIFEST_URL).send().await?;
	response.error_for_status_ref()?;
	let topics: Vec<Topic> = serde_json::from_str(&response.text().await?)?;
	Ok(topics)
}
