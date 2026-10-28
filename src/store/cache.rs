//! Results that change slowly (repo health, stargazer samples), kept for a while so
//! re-runs skip the requests.

use std::collections::HashMap;
use std::io;
use std::path::PathBuf;

use chrono::{DateTime, Duration, Utc};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::{json_file, paths};

#[derive(Serialize, Deserialize)]
#[serde(bound = "T: Serialize + DeserializeOwned")]
struct Stamped<T> {
    at: DateTime<Utc>,
    value: T,
}

pub struct Cache<T> {
    path: PathBuf,
    entries: HashMap<String, Stamped<T>>,
}

impl<T: Serialize + DeserializeOwned> Cache<T> {
    /// `~/.stackradar/<file>`, minus entries older than `ttl`.
    pub fn load(file: &str, ttl: Duration, now: DateTime<Utc>) -> Self {
        Self::load_from(paths::data_dir().join(file), ttl, now)
    }

    fn load_from(path: PathBuf, ttl: Duration, now: DateTime<Utc>) -> Self {
        let mut entries: HashMap<String, Stamped<T>> = json_file::load(&path);
        entries.retain(|_, e| now - e.at < ttl);
        Self { path, entries }
    }

    pub fn get(&self, key: &str) -> Option<&T> {
        self.entries.get(key).map(|e| &e.value)
    }

    /// The entry for `key` if it was stored less than `ttl` before `now`.
    pub fn get_within(&self, key: &str, ttl: Duration, now: DateTime<Utc>) -> Option<&T> {
        self.entries.get(key).filter(|e| now - e.at < ttl).map(|e| &e.value)
    }

    pub fn insert(&mut self, key: String, value: T, now: DateTime<Utc>) {
        self.entries.insert(key, Stamped { at: now, value });
    }

    pub fn save(&self) -> io::Result<()> {
        json_file::save(&self.path, &self.entries)
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drops_expired_entries_on_load() {
        let now = Utc::now();
        let path = std::env::temp_dir().join(format!("stackradar-cache-{}.json", std::process::id()));
        let mut c: Cache<u32> = Cache { path: path.clone(), entries: HashMap::new() };
        c.insert("fresh".into(), 1, now - Duration::hours(1));
        c.insert("old".into(), 2, now - Duration::hours(20));
        c.save().unwrap();
        let c: Cache<u32> = Cache::load_from(path.clone(), Duration::hours(12), now);
        std::fs::remove_file(&path).unwrap();
        assert_eq!((c.get("fresh"), c.get("old")), (Some(&1), None));
        assert_eq!(c.get_within("fresh", Duration::minutes(30), now), None);
    }
}
