//! Per-day star snapshots, so a run can report stars gained since the previous run.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::ops::Bound;
use std::path::PathBuf;

use chrono::NaiveDate;

use super::{json_file, paths};

/// Snapshots older than this many run-days are dropped.
const KEEP_DAYS: usize = 60;

/// date (YYYY-MM-DD, UTC) → repo full_name → stars
type Snapshots = BTreeMap<String, HashMap<String, u64>>;

pub struct History {
    path: PathBuf,
    days: Snapshots,
}

impl History {
    /// `~/.stackradar/history.json`.
    pub fn load() -> Self {
        let path = paths::data_dir().join("history.json");
        Self { days: json_file::load(&path), path }
    }

    /// Latest snapshot taken on a day before `today`.
    pub fn previous(&self, today: &str) -> Option<(&str, &HashMap<String, u64>)> {
        self.days.range::<str, _>((Bound::Unbounded, Bound::Excluded(today))).next_back().map(|(d, s)| (d.as_str(), s))
    }

    /// Star counts per earlier run for any repo, as (days before `today`, stars), oldest
    /// first. Dates are parsed once here, not once per repo.
    pub fn trend(&self, today: NaiveDate) -> impl Fn(&str) -> Vec<(i64, u64)> + '_ {
        let days: Vec<(i64, &HashMap<String, u64>)> = self
            .days
            .iter()
            .filter_map(|(d, s)| Some(((today - NaiveDate::parse_from_str(d, "%Y-%m-%d").ok()?).num_days(), s)))
            .filter(|&(ago, _)| ago > 0)
            .collect();
        move |name| days.iter().filter_map(|&(ago, s)| Some((ago, *s.get(name)?))).collect()
    }

    /// Merge into today's snapshot (re-runs on the same day accumulate), then prune.
    pub fn record(&mut self, today: &str, stars: impl IntoIterator<Item = (String, u64)>) {
        self.days.entry(today.to_string()).or_default().extend(stars);
        while self.days.len() > KEEP_DAYS {
            self.days.pop_first();
        }
    }

    pub fn save(&self) -> io::Result<()> {
        json_file::save(&self.path, &self.days)
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trend_lists_earlier_runs_oldest_first() {
        let mut h = History { path: PathBuf::new(), days: Snapshots::new() };
        h.record("2026-10-20", [("a/b".to_string(), 10)]);
        h.record("2026-10-23", [("a/b".to_string(), 25), ("c/d".to_string(), 1)]);
        h.record("2026-10-25", [("a/b".to_string(), 40)]);
        let trend = h.trend(NaiveDate::from_ymd_opt(2026, 10, 25).unwrap());
        assert_eq!(trend("a/b"), vec![(5, 10), (2, 25)]);
        assert!(trend("x/y").is_empty());
        assert_eq!(h.previous("2026-10-25").map(|(d, _)| d), Some("2026-10-23"));
    }
}
