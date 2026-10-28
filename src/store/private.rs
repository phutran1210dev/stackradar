//! Files only you can read: reports and the state under `~/.stackradar` name your projects
//! and their weaknesses, and the config can hold a webhook URL. On Windows the files
//! inherit the user profile's permissions.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;

/// Create `dir` (and its parents) and make it yours only; an existing one is tightened too.
pub fn create_dir(dir: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Write `path`, replacing it, readable by you only.
pub fn write(path: &Path, content: &[u8]) -> io::Result<()> {
    let mut file = options().create(true).truncate(true).open(path)?;
    // An existing file keeps its mode when opened, so it is tightened here.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(content)
}

/// Create `path` readable by you only; fails if it already exists.
pub fn create_new(path: &Path, content: &[u8]) -> io::Result<()> {
    options().create_new(true).open(path)?.write_all(content)
}

fn options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.write(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn only_you_can_read() {
        let dir = std::env::temp_dir().join(format!("stackradar-private-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        create_dir(&dir).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700, "an existing folder is tightened");

        let file = dir.join("a.json");
        std::fs::write(&file, "old").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        write(&file, b"new").unwrap();
        assert_eq!((mode(&file), std::fs::read_to_string(&file).unwrap().as_str()), (0o600, "new"));

        create_new(&dir.join("b.toml"), b"x").unwrap();
        assert_eq!(mode(&dir.join("b.toml")), 0o600);
        assert!(create_new(&dir.join("b.toml"), b"y").is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
