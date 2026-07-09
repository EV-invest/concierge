use std::{fs, path::PathBuf};

/// Compile every `proto/<pkg>/v1/*.proto` into Rust with tonic — BOTH client and
/// server stubs. The runner includes the servers; other service repos that depend
/// on this crate (by git) include the clients. Each package's generated module is
/// pulled into `src/lib.rs` via `tonic::include_proto!("<pkg>.v1")`.
///
/// `concierge.v1` is the whole user/identity + platform plane surface: auth,
/// directory, the deferred notification/log seams, the cross-plane lifecycle
/// events, and health.
fn main() -> Result<(), Box<dyn std::error::Error>> {
	let proto_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("proto");

	let mut protos: Vec<PathBuf> = Vec::new();
	for package in ["concierge/v1"] {
		let dir = proto_root.join(package);
		println!("cargo:rerun-if-changed={}", dir.display());
		for entry in fs::read_dir(&dir)? {
			let path = entry?.path();
			if path.extension().is_some_and(|ext| ext == "proto") {
				println!("cargo:rerun-if-changed={}", path.display());
				protos.push(path);
			}
		}
	}
	protos.sort();

	tonic_prost_build::configure().build_server(true).build_client(true).compile_protos(&protos, &[proto_root])?;

	Ok(())
}
