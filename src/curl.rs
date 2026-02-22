//! Curl command special handling - URL host extraction

use crate::analyzer::Command;
use crate::config::{Config, ExecContext, Permission, PermissionResult};

/// Extract host from a URL
fn extract_host(url: &str) -> Option<String> {
    // Strip quotes if present
    let url = url.trim_matches('"').trim_matches('\'');

    // Handle scheme://host/path
    let after_scheme = if let Some(pos) = url.find("://") {
        &url[pos + 3..]
    } else {
        // No scheme - treat as host directly for simple cases
        url
    };

    // Extract host (before first / or end)
    let host_port = if let Some(pos) = after_scheme.find('/') {
        &after_scheme[..pos]
    } else {
        after_scheme
    };

    // Strip user@ prefix if present
    let host_port = if let Some(pos) = host_port.find('@') {
        &host_port[pos + 1..]
    } else {
        host_port
    };

    // Strip :port suffix if present
    let host = if let Some(pos) = host_port.rfind(':') {
        // Make sure this is actually a port (after last colon, all digits)
        let potential_port = &host_port[pos + 1..];
        if potential_port.chars().all(|c| c.is_ascii_digit()) {
            &host_port[..pos]
        } else {
            host_port
        }
    } else {
        host_port
    };

    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// Options that take an argument (skip them when looking for URLs)
const OPTS_WITH_ARGS: &[&str] = &[
    "-A",
    "--user-agent",
    "-b",
    "--cookie",
    "-c",
    "--cookie-jar",
    "-d",
    "--data",
    "--data-raw",
    "--data-binary",
    "--data-urlencode",
    "-D",
    "--dump-header",
    "-e",
    "--referer",
    "-F",
    "--form",
    "-H",
    "--header",
    "-K",
    "--config",
    "-m",
    "--max-time",
    "-o",
    "--output",
    "-O",
    "--remote-name",
    "-T",
    "--upload-file",
    "-u",
    "--user",
    "-w",
    "--write-out",
    "-x",
    "--proxy",
    "-X",
    "--request",
    "--connect-timeout",
    "--retry",
    "--retry-delay",
    "--retry-max-time",
    "-r",
    "--range",
    "--resolve",
    "--interface",
    "-E",
    "--cert",
    "--key",
    "--cacert",
];

/// Extract URL arguments from curl command args, skipping flags and their values
fn extract_urls(args: &[String]) -> Vec<String> {
    let mut urls = Vec::new();
    let mut skip_next = false;

    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }

        if arg.starts_with('-') {
            if arg.contains('=') {
                continue;
            } else if arg.len() > 2 && !arg.starts_with("--") {
                // Combined short opts like -sLA - check if ANY takes an argument
                for c in arg[1..].chars() {
                    let opt = format!("-{}", c);
                    if OPTS_WITH_ARGS.contains(&opt.as_str()) {
                        skip_next = true;
                    }
                }
            } else if OPTS_WITH_ARGS.contains(&arg.as_str()) {
                skip_next = true;
            }
            continue;
        }

        urls.push(arg.clone());
    }

    urls
}

/// Check a curl command and extract URL hosts
/// Returns a permission result based on the URL host
pub fn check_curl(cmd: &Command, config: &Config, ctx: ExecContext) -> Option<PermissionResult> {
    if cmd.name != "curl" {
        return None;
    }

    let urls = extract_urls(&cmd.args);
    if urls.is_empty() {
        return None;
    }

    let hosts: Vec<String> = urls.iter().filter_map(|url| extract_host(url)).collect();
    if hosts.is_empty() {
        return None;
    }

    // Check each host against config rules
    // Return the most restrictive result (or first non-passthrough)
    for host in &hosts {
        let result = config.check_command_with_host("curl", &cmd.args, Some(host), ctx);
        if result.permission != Permission::Passthrough {
            return Some(result);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_host_simple() {
        assert_eq!(
            extract_host("http://localhost:3000/foo"),
            Some("localhost".to_string())
        );
    }

    #[test]
    fn test_extract_host_ip() {
        assert_eq!(
            extract_host("http://127.0.0.1:3000/debug"),
            Some("127.0.0.1".to_string())
        );
    }

    #[test]
    fn test_extract_host_external() {
        assert_eq!(
            extract_host("https://example.com/api"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_extract_host_with_user() {
        assert_eq!(
            extract_host("http://user:pass@host.com/path"),
            Some("host.com".to_string())
        );
    }

    #[test]
    fn test_extract_host_quoted() {
        assert_eq!(
            extract_host("\"http://localhost:8080/test\""),
            Some("localhost".to_string())
        );
    }

    #[test]
    fn test_extract_host_no_port() {
        assert_eq!(
            extract_host("https://api.example.com/v1"),
            Some("api.example.com".to_string())
        );
    }

    fn make_cmd(args: &[&str]) -> Command {
        Command {
            name: "curl".to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            text: format!("curl {}", args.join(" ")),
        }
    }

    fn config_with_curl_rules() -> Config {
        let config_str = r#"
            default = "passthrough"
            [[rules]]
            commands = ["curl"]
            permission = "check_host"
            reason = "curl"
            host_rules = [
                { pattern = "localhost", permission = "allow" },
                { pattern = "*.localhost", permission = "allow" },
                { pattern = "127.0.0.1", permission = "allow" },
                { pattern = "127.*", permission = "allow" },
                { pattern = "gcdev.site", permission = "allow" },
                { pattern = "*", permission = "ask" },
            ]
        "#;
        toml::from_str(config_str).unwrap()
    }

    #[test]
    fn test_curl_localhost_allowed() {
        let config = config_with_curl_rules();
        let cmd = make_cmd(&["-s", "http://127.0.0.1:3000/debug"]);
        let result = check_curl(&cmd, &config, ExecContext::default()).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_curl_localhost_name_allowed() {
        let config = config_with_curl_rules();
        let cmd = make_cmd(&[
            "-H",
            "Content-Type: application/json",
            "http://localhost:8080/api",
        ]);
        let result = check_curl(&cmd, &config, ExecContext::default()).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_curl_allowed_host() {
        let config = config_with_curl_rules();
        let cmd = make_cmd(&["https://gcdev.site/api"]);
        let result = check_curl(&cmd, &config, ExecContext::default()).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_curl_external_asks() {
        let config = config_with_curl_rules();
        let cmd = make_cmd(&["https://example.com/api"]);
        let result = check_curl(&cmd, &config, ExecContext::default()).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_curl_no_rule_passthrough() {
        // With config that has no curl rules, passthrough
        let config_str = r#"
            default = "passthrough"
            [[rules]]
            commands = ["ls"]
            permission = "allow"
            reason = "read-only"
        "#;
        let config: Config = toml::from_str(config_str).unwrap();
        let cmd = make_cmd(&["https://example.com/api"]);
        let result = check_curl(&cmd, &config, ExecContext::default());
        assert!(result.is_none());
    }

    #[test]
    fn test_curl_no_url() {
        let config = config_with_curl_rules();
        let cmd = make_cmd(&["--help"]);
        let result = check_curl(&cmd, &config, ExecContext::default());
        assert!(result.is_none());
    }

    #[test]
    fn test_not_curl() {
        let config = config_with_curl_rules();
        let cmd = Command {
            name: "wget".to_string(),
            args: vec!["http://localhost".to_string()],
            text: "wget http://localhost".to_string(),
        };
        let result = check_curl(&cmd, &config, ExecContext::default());
        assert!(result.is_none());
    }

    #[test]
    fn test_curl_combined_short_opts_with_arg() {
        // -sLA "Mozilla/5.0" - the -A takes an argument, should skip it
        let config = config_with_curl_rules();
        let cmd = make_cmd(&[
            "-sLA",
            "Mozilla/5.0",
            "https://localhost/page",
            "-o",
            "/tmp/out.html",
        ]);
        let result = check_curl(&cmd, &config, ExecContext::default()).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }
}
