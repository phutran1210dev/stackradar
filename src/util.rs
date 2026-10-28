//! Small helpers shared across modules: a thread pool map and text.

use std::sync::atomic::{AtomicUsize, Ordering};

/// Run `f` over `items` on up to `workers` threads, keeping input order. Threads pull
/// the next item when free, so one slow request doesn't hold up a fixed chunk.
pub fn par_map<T: Sync, R: Send>(items: &[T], workers: usize, f: impl Fn(&T) -> R + Sync) -> Vec<R> {
    let next = AtomicUsize::new(0);
    let mut done: Vec<(usize, R)> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..workers.clamp(1, items.len().max(1)))
            .map(|_| {
                s.spawn(|| {
                    let mut out = Vec::new();
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        let Some(item) = items.get(i) else { break };
                        out.push((i, f(item)));
                    }
                    out
                })
            })
            .collect();
        handles.into_iter().flat_map(|h| h.join().expect("worker thread panicked")).collect()
    });
    done.sort_unstable_by_key(|(i, _)| *i);
    done.into_iter().map(|(_, r)| r).collect()
}

pub fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max { s.to_string() } else { format!("{}…", s.chars().take(max - 1).collect::<String>()) }
}

#[cfg(test)]
mod tests {
    use super::par_map;

    #[test]
    fn par_map_keeps_order() {
        let items: Vec<u64> = (0..100).collect();
        let out = par_map(&items, 7, |&x| {
            std::thread::sleep(std::time::Duration::from_micros((100 - x) * 10));
            x * 2
        });
        assert_eq!(out, items.iter().map(|x| x * 2).collect::<Vec<_>>());
        assert!(par_map(&[] as &[u8], 4, |&x| x).is_empty());
    }
}
