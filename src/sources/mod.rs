//! External services: the GitHub API (repos, trending page, security advisories),
//! Hacker News, package registries, and the HTTP plumbing they share.

pub mod advisories;
pub mod exploits;
pub mod github;
pub mod hn;
pub mod http;
#[cfg(test)]
pub mod mock;
pub mod osv;
pub mod registry;
