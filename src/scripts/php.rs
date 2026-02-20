//! PHP inline script analysis for `php -r` commands

use crate::analyzer::Command;
use crate::config::{Permission, PermissionResult};

/// Read-only PHP functions (case-insensitive)
const READONLY_FUNCTIONS: &[&str] = &[
    // Output
    "echo",
    "print",
    "print_r",
    "var_dump",
    "var_export",
    "printf",
    "sprintf",
    // PHP info
    "phpinfo",
    "phpversion",
    "php_uname",
    "php_sapi_name",
    "zend_version",
    // Configuration
    "ini_get",
    "ini_get_all",
    "get_cfg_var",
    "get_include_path",
    // Extensions
    "extension_loaded",
    "get_loaded_extensions",
    "get_extension_funcs",
    // Definitions
    "get_defined_constants",
    "get_defined_functions",
    "get_defined_vars",
    "get_declared_classes",
    "get_declared_interfaces",
    "get_declared_traits",
    // Class/function info
    "function_exists",
    "class_exists",
    "interface_exists",
    "trait_exists",
    "method_exists",
    "property_exists",
    "get_class",
    "get_parent_class",
    "get_class_methods",
    "get_class_vars",
    "get_object_vars",
    // Type checking
    "gettype",
    "is_array",
    "is_bool",
    "is_callable",
    "is_float",
    "is_int",
    "is_null",
    "is_numeric",
    "is_object",
    "is_string",
    "isset",
    "empty",
    // String functions (read-only)
    "strlen",
    "strpos",
    "substr",
    "strtolower",
    "strtoupper",
    "trim",
    "ltrim",
    "rtrim",
    "str_replace",
    "preg_match",
    "explode",
    "implode",
    "join",
    // Array functions (read-only)
    "count",
    "sizeof",
    "array_keys",
    "array_values",
    "array_key_exists",
    "in_array",
    "array_search",
    "array_merge",
    "array_filter",
    "array_map",
    // JSON
    "json_encode",
    "json_decode",
    // Date/time
    "date",
    "time",
    "strtotime",
    "mktime",
    "gmdate",
    // Environment (read-only)
    "getenv",
    "get_current_user",
    "getmypid",
    "getmyuid",
    "sys_get_temp_dir",
    // Path info
    "basename",
    "dirname",
    "pathinfo",
    "realpath",
    // Streams (read-only)
    "stream_get_contents",
    "fgets",
    "fread",
    "fgetc",
    "feof",
    // Serialization
    "serialize",
    "unserialize",
    // File reading (read-only)
    "file_get_contents",
    "file",
    "readfile",
    // Encoding
    "base64_decode",
    "base64_encode",
    "urlencode",
    "urldecode",
    "rawurlencode",
    "rawurldecode",
    "http_build_query",
    // More array functions
    "array_keys",
    "array_unique",
    "array_reverse",
    "array_flip",
    "array_slice",
    "array_chunk",
    "array_combine",
    "array_diff",
    "array_intersect",
    "sort",
    "rsort",
    "asort",
    "arsort",
    "ksort",
    "krsort",
    "usort",
    "uasort",
    "uksort",
    "array_multisort",
];

/// Extract PHP code from php -r command
fn extract_php_code(cmd: &Command) -> Option<&str> {
    let mut iter = cmd.args.iter();

    while let Some(arg) = iter.next() {
        if arg == "-r" || arg == "--run" {
            // Next arg is the code
            return iter.next().map(|s| s.as_str());
        }
        // Handle -r"code" (no space)
        if let Some(code) = arg.strip_prefix("-r") {
            if !code.is_empty() {
                return Some(code);
            }
        }
    }

    None
}

/// Check if PHP code only uses read-only functions
fn is_readonly_php(code: &str) -> bool {
    // Simple heuristic: extract function calls and check against allowlist
    // This matches patterns like: func_name( or func_name (
    let code_lower = code.to_lowercase();

    // Look for function calls - pattern: word followed by (
    let mut i = 0;
    let bytes = code_lower.as_bytes();

    while i < bytes.len() {
        // Skip to start of potential function name
        while i < bytes.len() && !bytes[i].is_ascii_alphabetic() && bytes[i] != b'_' {
            i += 1;
        }

        if i >= bytes.len() {
            break;
        }

        // Check if preceded by -> (method call) or "new " (constructor)
        let is_method_call = i >= 2 && &code_lower[i - 2..i] == "->";
        let is_constructor = i >= 4 && &code_lower[i - 4..i] == "new ";

        // Extract word
        let start = i;
        while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
            i += 1;
        }

        let word = &code_lower[start..i];

        // Skip whitespace
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }

        // Check if followed by ( - this is a function call
        if i < bytes.len() && bytes[i] == b'(' && !is_method_call && !is_constructor {
            // Check if this function is in our allowlist
            if !READONLY_FUNCTIONS
                .iter()
                .any(|f| f.eq_ignore_ascii_case(word))
            {
                // Also allow PHP language constructs that look like functions
                if !matches!(
                    word,
                    "if" | "else"
                        | "elseif"
                        | "while"
                        | "for"
                        | "foreach"
                        | "switch"
                        | "case"
                        | "array"
                        | "list"
                        | "new"
                        | "require"
                        | "require_once"
                        | "include"
                        | "include_once"
                ) {
                    return false;
                }
            }
        }
    }

    true
}

/// Check if a php command is read-only
pub fn check_php_script(cmd: &Command) -> Option<PermissionResult> {
    if cmd.name != "php" {
        return None;
    }

    // Only handle -r flag
    let code = extract_php_code(cmd)?;

    if is_readonly_php(code) {
        Some(PermissionResult {
            permission: Permission::Allow,
            reason: "read-only PHP script".to_string(),
            suggestion: None,
        })
    } else {
        Some(PermissionResult {
            permission: Permission::Ask,
            reason: "PHP script may have side effects".to_string(),
            suggestion: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cmd(args: &[&str]) -> Command {
        Command {
            name: "php".to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            text: format!("php {}", args.join(" ")),
        }
    }

    #[test]
    fn test_echo_ini_get_allowed() {
        let cmd = make_cmd(&["-r", "echo ini_get('error_log');"]);
        let result = check_php_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_phpinfo_allowed() {
        let cmd = make_cmd(&["-r", "phpinfo();"]);
        let result = check_php_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_print_r_allowed() {
        let cmd = make_cmd(&["-r", "print_r(get_loaded_extensions());"]);
        let result = check_php_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_file_write_asks() {
        let cmd = make_cmd(&["-r", "file_put_contents('/tmp/test', 'data');"]);
        let result = check_php_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_exec_asks() {
        let cmd = make_cmd(&["-r", "exec('rm -rf /');"]);
        let result = check_php_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_unlink_asks() {
        let cmd = make_cmd(&["-r", "unlink('/tmp/test');"]);
        let result = check_php_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Ask);
    }

    #[test]
    fn test_complex_readonly_allowed() {
        let cmd = make_cmd(&[
            "-r",
            "echo json_encode(['version' => phpversion(), 'extensions' => get_loaded_extensions()]);",
        ]);
        let result = check_php_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_not_php_returns_none() {
        let cmd = Command {
            name: "python".to_string(),
            args: vec!["-c".to_string(), "print('hello')".to_string()],
            text: "python -c print('hello')".to_string(),
        };
        let result = check_php_script(&cmd);
        assert!(result.is_none());
    }

    #[test]
    fn test_php_without_r_returns_none() {
        let cmd = make_cmd(&["script.php"]);
        let result = check_php_script(&cmd);
        assert!(result.is_none());
    }

    #[test]
    fn test_require_autoload_allowed() {
        let cmd = make_cmd(&[
            "-r",
            "require 'vendor/autoload.php'; echo get_class_methods('Foo');",
        ]);
        let result = check_php_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_new_reflection_allowed() {
        let cmd = make_cmd(&[
            "-r",
            r#"require 'vendor/autoload.php'; $r = new ReflectionClass('Foo'); echo $r->getMethods()[0]->getReturnType();"#,
        ]);
        let result = check_php_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_method_call_allowed() {
        let cmd = make_cmd(&[
            "-r",
            r#"$obj->dangerousFunction();"#,
        ]);
        let result = check_php_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }
}
