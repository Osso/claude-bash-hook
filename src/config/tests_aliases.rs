use super::*;

fn single_alias_config(from: &str, to: &str) -> Config {
    toml::from_str(&format!(
        r#"
        [[aliases]]
        from = "{from}"
        to = "{to}"
    "#
    ))
    .unwrap()
}

#[test]
fn test_apply_aliases_rewrites_command_name() {
    let config = single_alias_config("fdfind", "fd");
    assert_eq!(
        config.apply_aliases("fdfind deploy.sh ."),
        Some("fd deploy.sh .".to_string())
    );
}

#[test]
fn test_apply_aliases_no_match() {
    let config = single_alias_config("fdfind", "fd");
    assert_eq!(config.apply_aliases("ls -la"), None);
}

#[test]
fn test_apply_aliases_word_boundary() {
    let config = single_alias_config("fd", "fdfind");
    // "fdfind" starts with "fd" but "fd" is not at a word boundary end here
    assert_eq!(config.apply_aliases("fdfind foo"), None);
}

#[test]
fn test_apply_aliases_in_pipeline() {
    let config = single_alias_config("fdfind", "fd");
    assert_eq!(
        config.apply_aliases("echo test | fdfind foo"),
        Some("echo test | fd foo".to_string())
    );
}

#[test]
fn test_apply_aliases_after_semicolon() {
    let config = single_alias_config("fdfind", "fd");
    assert_eq!(
        config.apply_aliases("cd /tmp; fdfind foo"),
        Some("cd /tmp; fd foo".to_string())
    );
}

#[test]
fn test_apply_aliases_after_and() {
    let config = single_alias_config("fdfind", "fd");
    assert_eq!(
        config.apply_aliases("true && fdfind foo"),
        Some("true && fd foo".to_string())
    );
}

#[test]
fn test_apply_aliases_multiple() {
    let config: Config = toml::from_str(
        r#"
        [[aliases]]
        from = "fdfind"
        to = "fd"

        [[aliases]]
        from = "batcat"
        to = "bat"
    "#,
    )
    .unwrap();
    assert_eq!(
        config.apply_aliases("fdfind foo | batcat"),
        Some("fd foo | bat".to_string())
    );
}

#[test]
fn test_apply_aliases_command_alone() {
    let config = single_alias_config("fdfind", "fd");
    assert_eq!(config.apply_aliases("fdfind"), Some("fd".to_string()));
}

#[test]
fn test_apply_aliases_no_partial_word() {
    let config = single_alias_config("grep", "rg");
    // "grepping" should not be rewritten — not a word boundary after "grep"
    assert_eq!(config.apply_aliases("grepping files"), None);
}
