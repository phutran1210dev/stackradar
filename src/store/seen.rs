//! Which items (e.g. vulnerabilities) earlier runs already reported, so a run can tell
//! what is new.

use std::collections::{BTreeMap, HashSet};
use std::io;
use std::path::PathBuf;

use super::{json_file, paths};

pub struct Seen {
    path: PathBuf,
    /// id → date first reported (YYYY-MM-DD)
    first: BTreeMap<String, String>,
    /// A previous run saved this file (an empty one counts: it saw nothing)
    existed: bool,
}

impl Seen {
    pub fn load(file: &str) -> Self {
        let path = paths::data_dir().join(file);
        Self { first: json_file::load(&path), existed: path.exists(), path }
    }

    /// Record the ids reported `today` and return the ones no earlier run reported.
    /// On the very first run nothing counts as new (there is nothing to compare to).
    /// Ids that are gone (say, a fixed vulnerability) are forgotten, so a return is new again.
    pub fn update(&mut self, ids: impl IntoIterator<Item = String>, today: &str) -> HashSet<String> {
        let first_run = !std::mem::replace(&mut self.existed, true);
        let current: HashSet<String> = ids.into_iter().collect();
        self.first.retain(|id, _| current.contains(id));
        let mut new = HashSet::new();
        for id in current {
            if !self.first.contains_key(&id) {
                self.first.insert(id.clone(), today.to_string());
                if !first_run {
                    new.insert(id);
                }
            }
        }
        new
    }

    pub fn save(&self) -> io::Result<()> {
        json_file::save(&self.path, &self.first)
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_new_ids_after_the_first_run() {
        let mut s = Seen { path: PathBuf::new(), first: BTreeMap::new(), existed: false };
        let ids = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(s.update(ids(&["a", "b"]), "2026-10-24").is_empty());
        assert_eq!(s.update(ids(&["a", "c"]), "2026-10-25"), HashSet::from(["c".to_string()]));
        assert_eq!(s.first["a"], "2026-10-24");
        assert!(!s.first.contains_key("b"));
        assert_eq!(s.update(ids(&["a", "b", "c"]), "2026-10-26"), HashSet::from(["b".to_string()]));
        // An empty earlier run still counts as a run.
        let mut s = Seen { path: PathBuf::new(), first: BTreeMap::new(), existed: true };
        assert_eq!(s.update(ids(&["x"]), "2026-10-26").len(), 1);
    }
}
