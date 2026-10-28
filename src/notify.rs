//! `--notify`: a desktop notification, plus the digest posted to the configured webhook.

use crate::model::Report;
use crate::platform;
use crate::report;
use crate::sources::http;

pub fn send(report: &Report, webhook: Option<&str>) {
    platform::notify("Stack Radar updated", &report::summary(report));
    if let Some(url) = webhook {
        match post(url, &report::digest(report)) {
            Ok(()) => println!("✓ Digest posted to webhook"),
            Err(e) => eprintln!("⚠  Webhook failed: {e}"),
        }
    }
}

/// Discord expects `content`; Slack, Telegram and most others take `text`. On Discord no
/// `@everyone` or other mention in a repo description may ping anyone.
fn payload(url: &str, text: &str) -> serde_json::Value {
    let host = url.trim_start_matches("https://").split(['/', '?']).next().unwrap_or_default();
    if host == "discord.com" || host.ends_with(".discord.com") || host == "discordapp.com" {
        serde_json::json!({ "content": text, "allowed_mentions": { "parse": [] } })
    } else {
        serde_json::json!({ "text": text })
    }
}

fn post(url: &str, text: &str) -> Result<(), String> {
    http::checked(http::send(http::client().post(url).json(&payload(url, text)))?).map(drop)
}

#[cfg(test)]
mod tests {
    use super::payload;

    #[test]
    fn payload_matches_the_service() {
        let discord = payload("https://discord.com/api/webhooks/1/x", "hi");
        assert_eq!(
            (&discord["content"], &discord["allowed_mentions"]["parse"]),
            (&"hi".into(), &serde_json::json!([]))
        );
        assert_eq!(payload("https://hooks.slack.com/services/x", "hi")["text"], "hi");
        assert_eq!(payload("https://api.telegram.org/botX/sendMessage?chat_id=1", "hi")["text"], "hi");
        assert!(payload("https://evil.example/discord.com", "hi").get("content").is_none());
    }
}
