//! JSON state files: tolerant reads, atomic writes.

use std::io;
use std::path::Path;

use serde::Serialize;
use serde::de::DeserializeOwned;

use super::private;

/// The file's contents; empty if it doesn't exist. A corrupt file is reported and
/// treated as empty (it is replaced on the next save) rather than aborting the run.
pub fn load<T: DeserializeOwned + Default>(path: &Path) -> T {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            eprintln!("⚠  Ignoring unreadable {}: {e}", path.display());
            T::default()
        }),
        Err(_) => T::default(),
    }
}

/// Write via a temp file + rename, so an interrupted run can't truncate the file. Only
/// you can read it: it names your projects and the advisories affecting them.
pub fn save<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("json.tmp");
    private::write(&tmp, &serde_json::to_vec(value)?)?;
    std::fs::rename(&tmp, path)
}
