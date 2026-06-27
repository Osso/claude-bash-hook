use super::*;

#[test]
fn test_default_config_allows_globalcomix_ci_clean_only_in_gc_worktree() {
    let config = Config::default();

    let allowed = config.check_command_with_cwd(
        "./scripts/ci-clean.sh",
        &[],
        Some("/syncthing/Sync/Projects/globalcomix/gc"),
        ExecContext::default(),
    );
    assert_eq!(allowed.permission, Permission::Allow);

    let outside_worktree = config.check_command_with_cwd(
        "./scripts/ci-clean.sh",
        &[],
        Some("/syncthing/Sync/Projects/claude/claude-bash-hook"),
        ExecContext::default(),
    );
    assert_eq!(outside_worktree.permission, Permission::Passthrough);
}
