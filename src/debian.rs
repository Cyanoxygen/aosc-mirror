#![allow(dead_code)]
#[allow(non_snake_case)]
struct TracingInfo {
	Date: String,
	Date_Started: String,
	Creator: String,
	Running_on_host: String,
	Maintainer: String,
	Suites: String,
	Architectures: String,
	Upstream_Mirror: String,
}

const TRACE_DIR: &str = "project/trace";
