use super::{Config, ExecContext, Permission};
use std::path::Path;

#[test]
fn test_npm_prefix_test_allowed() {
    let config = Config::load(Path::new("config.default.toml")).expect("load test config");
    let result = config.check_command_with_cwd(
        "npm",
        &[
            "--prefix".into(),
            "frontend/web-ui".into(),
            "test".into(),
            "--".into(),
            "readerCdnUrls".into(),
            "--run".into(),
        ],
        None,
        ExecContext::default(),
    );
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn test_npm_coding_agent_test_runner_allows_any_test_file() {
    let config = Config::load(Path::new("config.default.toml")).expect("load test config");
    let result = config.check_command_with_cwd(
        "npm",
        &[
            "run".into(),
            "test:coding-agent".into(),
            "--".into(),
            "test/interactive-mode-status.test.ts".into(),
        ],
        None,
        ExecContext::default(),
    );
    assert_eq!(result.permission, Permission::Allow);
}
