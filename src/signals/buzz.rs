//! "Buzz": one ranking score combining independent signals that people really care
//! about a repo, so no single gameable number (raw stars) decides the order.

use crate::sources::github::Repo;

/// Points for a count on a log scale: `k` per order of magnitude, capped.
fn log_points(x: f64, k: f64, cap: f64) -> f64 {
    (k * (1.0 + x.max(0.0)).log10()).min(cap)
}

/// Many stars but almost no forks and no issues — the shape of bought or
/// campaign stars rather than people using the code.
pub fn low_engagement(repo: &Repo) -> bool {
    repo.stargazers_count >= 100 && repo.forks_count * 100 < repo.stargazers_count && repo.open_issues_count == 0
}

pub struct Signals {
    /// Stars today on github.com/trending (GitHub's own trending algorithm)
    pub trending_today: Option<u64>,
    /// Points of the best recent Hacker News story
    pub hn_points: Option<u64>,
    /// Stars gained since the previous run
    pub stars_delta: Option<i64>,
    pub stars_per_day: f64,
    pub low_engagement: bool,
    /// Most recent stargazers are throwaway accounts
    pub suspicious_stars: bool,
}

/// Roughly 0–115. Being on GitHub Trending and discussed on HN weigh most, measured
/// momentum next, launch velocity least. Low engagement halves the score; suspicious
/// stars (measured, so stronger evidence) cut it to 30%.
pub fn score(s: &Signals) -> f64 {
    let trending = s.trending_today.map_or(0.0, |t| 25.0 + log_points(t as f64, 10.0, 25.0));
    let hn = s.hn_points.map_or(0.0, |p| log_points(p as f64, 10.0, 30.0));
    let momentum = s.stars_delta.map_or(0.0, |d| log_points(d as f64, 8.0, 20.0));
    let velocity = log_points(s.stars_per_day, 6.0, 15.0);
    let total = trending + hn + momentum + velocity;
    let mut penalty = 1.0;
    if s.low_engagement {
        penalty *= 0.5;
    }
    if s.suspicious_stars {
        penalty *= 0.3;
    }
    total * penalty
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signals() -> Signals {
        Signals {
            trending_today: None,
            hn_points: None,
            stars_delta: None,
            stars_per_day: 0.0,
            low_engagement: false,
            suspicious_stars: false,
        }
    }

    #[test]
    fn trending_and_hn_outrank_raw_velocity() {
        let fast_only = Signals { stars_per_day: 500.0, ..signals() };
        let trending = Signals { trending_today: Some(300), stars_per_day: 20.0, ..signals() };
        let discussed = Signals { hn_points: Some(200), stars_per_day: 20.0, ..signals() };
        assert!(score(&trending) > score(&fast_only));
        assert!(score(&discussed) > score(&fast_only));
    }

    #[test]
    fn low_engagement_halves_and_negative_delta_scores_zero() {
        let s = Signals { stars_per_day: 99.0, ..signals() };
        let flagged = Signals { low_engagement: true, ..Signals { stars_per_day: 99.0, ..signals() } };
        assert_eq!(score(&flagged), score(&s) / 2.0);
        assert_eq!(score(&Signals { stars_delta: Some(-5), ..signals() }), 0.0);
        let bought = Signals { suspicious_stars: true, trending_today: Some(500), ..signals() };
        assert!(score(&bought) < score(&Signals { trending_today: Some(20), ..signals() }));
    }
}
