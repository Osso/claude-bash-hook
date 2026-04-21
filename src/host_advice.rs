//! LLM-based host safety check for curl fallback.
//!
//! Queries the Codex CLI to determine if a host is a well-known legitimate
//! public service. Decisions are cached forever in
//! `~/.cache/claude-bash-hook/host-decisions.json`.

use log::debug;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

/// Result of the LLM host safety check.
pub enum HostDecision {
    Safe,
    Unsafe,
}

/// Query whether `host` is safe, using a cache-then-LLM strategy.
///
/// Returns `None` on any error (binary missing, timeout, parse failure,
/// cache I/O) so the caller can fall back to `Ask`.
pub fn query_host_safety(host: &str) -> Option<HostDecision> {
    let cache_path = cache_file_path()?;

    if let Some(cached) = read_cache(&cache_path, host) {
        debug!("host_advice: cache hit for {}", host);
        return Some(cached);
    }

    debug!("host_advice: querying LLM for host {}", host);
    let decision = call_llm(host)?;

    write_cache(&cache_path, host, &decision);
    Some(decision)
}

// ── Cache helpers ─────────────────────────────────────────────────────────────

fn cache_file_path() -> Option<PathBuf> {
    let home = std::env::var("HOME").ok()?;
    Some(PathBuf::from(home).join(".cache/claude-bash-hook/host-decisions.json"))
}

fn read_cache(path: &PathBuf, host: &str) -> Option<HostDecision> {
    let content = fs::read_to_string(path).ok()?;
    let map: HashMap<String, String> = serde_json::from_str(&content).ok()?;
    match map.get(host)?.to_lowercase().as_str() {
        "safe" => Some(HostDecision::Safe),
        "unsafe" => Some(HostDecision::Unsafe),
        _ => None,
    }
}

fn write_cache(path: &PathBuf, host: &str, decision: &HostDecision) {
    let label = match decision {
        HostDecision::Safe => "safe",
        HostDecision::Unsafe => "unsafe",
    };

    // Read-modify-write; accept last-write-wins on concurrent access.
    let mut map: HashMap<String, String> = path
        .exists()
        .then(|| {
            fs::read_to_string(path)
                .ok()
                .and_then(|c| serde_json::from_str(&c).ok())
        })
        .flatten()
        .unwrap_or_default();

    map.insert(host.to_string(), label.to_string());

    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(json) = serde_json::to_string_pretty(&map) {
        let _ = fs::write(path, json);
    }
}

// ── LLM call ─────────────────────────────────────────────────────────────────

fn build_prompt(host: &str) -> String {
    format!(
        "Is `{host}` a well-known legitimate public API, website, or service \
         (e.g. OpenAI, Google, GitHub, npmjs, well-known SaaS)?\n\
         Reply with ONLY one word: SAFE or UNSAFE.\n\
         Err on the side of UNSAFE if unsure or if the domain looks like a \
         lookalike/typosquat."
    )
}

fn call_llm(host: &str) -> Option<HostDecision> {
    use llm_sdk::Backend;
    use llm_sdk::codex_cli::CodexCli;

    let backend = CodexCli::new()
        .ok()?
        .model("gpt-5.3-codex-spark")
        .timeout(Duration::from_secs(8));

    let prompt = build_prompt(host);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()?;

    let output = rt.block_on(backend.complete(&prompt)).ok()?;
    parse_decision(&output.text)
}

fn parse_decision(text: &str) -> Option<HostDecision> {
    let upper = text.to_uppercase();
    // First occurrence of SAFE or UNSAFE wins.
    let safe_pos = upper.find("SAFE");
    let unsafe_pos = upper.find("UNSAFE");

    match (safe_pos, unsafe_pos) {
        (None, None) => None,
        (Some(_), None) => Some(HostDecision::Safe),
        (None, Some(_)) => Some(HostDecision::Unsafe),
        (Some(s), Some(u)) => {
            // "UNSAFE" contains "SAFE", so check which comes first as a word.
            // If UNSAFE starts before or at SAFE's position, UNSAFE wins.
            if u <= s {
                Some(HostDecision::Unsafe)
            } else {
                Some(HostDecision::Safe)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_decision ────────────────────────────────────────────────────────

    #[test]
    fn parse_safe_response() {
        assert!(matches!(parse_decision("SAFE"), Some(HostDecision::Safe)));
        assert!(matches!(parse_decision("safe"), Some(HostDecision::Safe)));
        assert!(matches!(
            parse_decision("  safe  "),
            Some(HostDecision::Safe)
        ));
    }

    #[test]
    fn parse_unsafe_response() {
        assert!(matches!(
            parse_decision("UNSAFE"),
            Some(HostDecision::Unsafe)
        ));
        assert!(matches!(
            parse_decision("unsafe"),
            Some(HostDecision::Unsafe)
        ));
    }

    #[test]
    fn parse_unsafe_beats_embedded_safe() {
        // "UNSAFE" contains "SAFE" — must resolve to Unsafe
        assert!(matches!(
            parse_decision("UNSAFE"),
            Some(HostDecision::Unsafe)
        ));
    }

    #[test]
    fn parse_empty_returns_none() {
        assert!(parse_decision("").is_none());
        assert!(parse_decision("   ").is_none());
        assert!(parse_decision("maybe").is_none());
    }

    // ── cache roundtrip ───────────────────────────────────────────────────────

    #[test]
    fn cache_roundtrip_safe() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("host-decisions.json");

        write_cache(&path, "openai.com", &HostDecision::Safe);
        let result = read_cache(&path, "openai.com");
        assert!(matches!(result, Some(HostDecision::Safe)));
    }

    #[test]
    fn cache_roundtrip_unsafe() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("host-decisions.json");

        write_cache(&path, "evil-lookalike.com", &HostDecision::Unsafe);
        let result = read_cache(&path, "evil-lookalike.com");
        assert!(matches!(result, Some(HostDecision::Unsafe)));
    }

    #[test]
    fn cache_miss_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("host-decisions.json");

        write_cache(&path, "openai.com", &HostDecision::Safe);
        let result = read_cache(&path, "github.com");
        assert!(result.is_none());
    }

    #[test]
    fn cache_accumulates_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("host-decisions.json");

        write_cache(&path, "openai.com", &HostDecision::Safe);
        write_cache(&path, "evil.xyz", &HostDecision::Unsafe);

        assert!(matches!(
            read_cache(&path, "openai.com"),
            Some(HostDecision::Safe)
        ));
        assert!(matches!(
            read_cache(&path, "evil.xyz"),
            Some(HostDecision::Unsafe)
        ));
    }

    #[test]
    fn read_cache_returns_none_for_missing_file() {
        let path = PathBuf::from("/nonexistent/host-decisions.json");
        assert!(read_cache(&path, "openai.com").is_none());
    }

    // ── query_host_safety with bogus PATH (no codex binary) ──────────────────

    #[test]
    fn query_returns_none_when_codex_missing() {
        // Override PATH so `which("codex")` fails, making CodexCli::new() → Err.
        // SAFETY: single-threaded test binary; no concurrent env reads.
        let original_path = std::env::var("PATH").unwrap_or_default();
        unsafe { std::env::set_var("PATH", "/nonexistent-path-for-test") };

        // Use a temp cache dir so we don't accidentally hit a real cache entry.
        let dir = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("HOME", dir.path().to_str().unwrap()) };

        let result = query_host_safety("openai.com");

        // Restore environment
        unsafe { std::env::set_var("PATH", original_path) };

        assert!(result.is_none(), "expected None when codex is not found");
    }

    // ── prompt builder ────────────────────────────────────────────────────────

    #[test]
    fn build_prompt_contains_host() {
        let prompt = build_prompt("openai.com");
        assert!(prompt.contains("openai.com"));
        assert!(prompt.contains("SAFE"));
        assert!(prompt.contains("UNSAFE"));
    }
}
