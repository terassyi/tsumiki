use assert_cmd::Command;
use std::path::PathBuf;

/// Workspace root (parent of the `cli` crate manifest directory).
pub fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Path to a fixture file under `examples/certs`.
pub fn fixture_path(name: &str) -> String {
    project_root()
        .join("examples/certs")
        .join(name)
        .to_string_lossy()
        .to_string()
}

/// A `Command` for the built `tsumiki` binary, run from the workspace root.
pub fn tsumiki() -> Command {
    let bin_path = project_root().join("target/debug/tsumiki");
    let mut cmd = Command::new(bin_path);
    cmd.current_dir(project_root());
    cmd
}
