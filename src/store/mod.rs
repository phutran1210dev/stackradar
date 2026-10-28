//! Local state under ~/.stackradar: config, star history, caches and seen items.

pub mod cache;
pub mod config;
pub mod history;
pub mod ignore;
mod json_file;
pub mod paths;
pub mod private;
pub mod seen;
