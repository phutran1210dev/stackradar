//! The report's tabs: one per configured category, plus "For you" and "Watching".

use std::collections::{HashMap, HashSet};

use crate::deps::Project;
use crate::model::{Entry, RepoInfo, Section};
use crate::signals::foryou::Stack;
use crate::store::config::{self, Config};

/// Topic chips shown on the "For you" tab.
const FOR_YOU_CHIPS: usize = 20;

/// One section per category, from its members (repo key → matched topics).
pub(super) fn categories(
    config: &Config,
    by_cat: Vec<HashMap<String, Vec<String>>>,
    infos: &HashMap<String, RepoInfo>,
) -> Vec<Section> {
    config
        .categories
        .iter()
        .zip(by_cat)
        .map(|(cat, members)| Section {
            key: cat.key.clone(),
            title: cat.title.clone(),
            topics: cat.topics.clone(),
            note: cat.note.clone(),
            entries: ranked(members.into_iter().map(|(key, matched)| Entry { info: infos[&key].clone(), matched })),
        })
        .collect()
}

/// Highest buzz first; ties by velocity, then name so the order is stable.
fn ranked(entries: impl Iterator<Item = Entry>) -> Vec<Entry> {
    let mut v: Vec<Entry> = entries.collect();
    v.sort_by(|a, b| {
        b.buzz
            .total_cmp(&a.buzz)
            .then(b.stars_per_day.total_cmp(&a.stars_per_day))
            .then_with(|| a.repo.full_name.cmp(&b.repo.full_name))
    });
    v
}

/// Repos from every tab that match dependencies of your projects.
pub(super) fn for_you(config: &Config, projects: &[Project], infos: &HashMap<String, RepoInfo>) -> Section {
    let topics: HashSet<&str> = config.categories.iter().flat_map(|c| &c.topics).map(String::as_str).collect();
    let stack = Stack::of(projects, &topics);
    let entries = ranked(infos.values().filter_map(|info| {
        let matched = stack.matches(&info.repo);
        (!matched.is_empty()).then(|| Entry { info: info.clone(), matched })
    }));
    let mut hits: HashMap<&str, usize> = HashMap::new();
    for t in entries.iter().flat_map(|e| &e.matched) {
        *hits.entry(t).or_default() += 1;
    }
    let mut chips: Vec<(&str, usize)> = hits.into_iter().collect();
    chips.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    Section {
        key: config::FOR_YOU.into(),
        title: "For you".into(),
        topics: chips.into_iter().take(FOR_YOU_CHIPS).map(|(t, _)| t.to_string()).collect(),
        note: None,
        entries,
    }
}

/// The watched repos (`watched` are keys), ranked like any tab.
pub(super) fn watching(watched: &[String], infos: &HashMap<String, RepoInfo>) -> Section {
    Section {
        key: config::WATCH.into(),
        title: "Watching".into(),
        topics: Vec::new(),
        note: None,
        entries: ranked(
            watched.iter().filter_map(|k| Some(Entry { info: infos.get(k)?.clone(), matched: Vec::new() })),
        ),
    }
}
