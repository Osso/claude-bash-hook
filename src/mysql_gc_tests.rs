use crate::analyze_command;
use crate::config::{Config, ExecContext, Permission};
use std::path::Path;

fn test_config() -> Config {
    Config::load(Path::new("config.default.toml")).expect("Failed to load test config")
}

#[test]
fn local_profile_allowed() {
    let config = test_config();
    let result = analyze_command(
        "mysql-gc globalcomix",
        &config,
        ExecContext::default(),
        None,
    );
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn external_redirect_allowed() {
    let config = test_config();
    let result = analyze_command(
        "mysql-gc -s external < db/etls/2026/migration.sql",
        &config,
        ExecContext::default(),
        Some("/syncthing/Sync/Projects/globalcomix/gc"),
    );
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn prod_readonly_redirect_allowed() {
    let config = test_config();
    let result = analyze_command(
        "mysql-gc --server prod < db/etls/2026/query.sql",
        &config,
        ExecContext::default(),
        Some("/syncthing/Sync/Projects/globalcomix/gc"),
    );
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn prod_rw_redirect_asks() {
    let config = test_config();
    let result = analyze_command(
        "mysql-gc --server prod-rw < db/etls/2026/migration.sql",
        &config,
        ExecContext::default(),
        Some("/syncthing/Sync/Projects/globalcomix/gc"),
    );
    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn prod_rw_select_allowed() {
    let config = test_config();
    let result = analyze_command(
        "mysql-gc -s prod-rw -e 'SELECT 1'",
        &config,
        ExecContext::default(),
        Some("/syncthing/Sync/Projects/globalcomix/gc"),
    );
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn prod_rw_insert_asks() {
    let config = test_config();
    let result = analyze_command(
        "mysql-gc -s prod-rw -e 'INSERT INTO t VALUES (1)'",
        &config,
        ExecContext::default(),
        Some("/syncthing/Sync/Projects/globalcomix/gc"),
    );
    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn prod_rw_piped_select_allowed() {
    let config = test_config();
    let result = analyze_command(
        "echo 'SELECT 1' | mysql-gc -s prod-rw",
        &config,
        ExecContext::default(),
        Some("/syncthing/Sync/Projects/globalcomix/gc"),
    );
    assert_eq!(result.permission, Permission::Allow);
}

#[test]
fn prod_rw_piped_insert_asks() {
    let config = test_config();
    let result = analyze_command(
        "echo 'INSERT INTO t VALUES (1)' | mysql-gc -s prod-rw",
        &config,
        ExecContext::default(),
        Some("/syncthing/Sync/Projects/globalcomix/gc"),
    );
    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn deprecated_prod_root_asks() {
    let config = test_config();
    let result = analyze_command(
        "mysql-gc --server prod-root < db/etls/2026/migration.sql",
        &config,
        ExecContext::default(),
        Some("/syncthing/Sync/Projects/globalcomix/gc"),
    );
    assert_eq!(result.permission, Permission::Ask);
}

#[test]
fn unknown_profile_without_visible_query_asks() {
    let config = test_config();
    let result = analyze_command(
        "mysql-gc -s scratch globalcomix",
        &config,
        ExecContext::default(),
        None,
    );
    assert_eq!(result.permission, Permission::Ask);
}
