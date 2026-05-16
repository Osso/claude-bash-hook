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
    "defined",
    "constant",
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
    // Network (read-only)
    "gethostbyname",
    "gethostbynamel",
    "gethostbyaddr",
    "checkdnsrr",
    "dns_get_record",
    "dns_check_record",
    "getmxrr",
    "ip2long",
    "long2ip",
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
    let code_lower = code.to_lowercase();
    let mut i = 0;
    let bytes = code_lower.as_bytes();

    while i < bytes.len() {
        let Some(start) = next_identifier_start(bytes, i) else {
            break;
        };
        let (word, next_index) = read_identifier(&code_lower, bytes, start);
        i = skip_whitespace(bytes, next_index);

        if is_php_call(bytes, i)
            && !is_non_function_call(&code_lower, start)
            && !is_allowed_php_call(word)
        {
            return false;
        }

        if is_php_call(bytes, i) {
            i += 1;
        }
    }

    true
}

fn next_identifier_start(bytes: &[u8], mut index: usize) -> Option<usize> {
    while index < bytes.len() && !bytes[index].is_ascii_alphabetic() && bytes[index] != b'_' {
        index += 1;
    }
    (index < bytes.len()).then_some(index)
}

fn read_identifier<'a>(code: &'a str, bytes: &[u8], start: usize) -> (&'a str, usize) {
    let mut end = start;
    while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
        end += 1;
    }
    (&code[start..end], end)
}

fn skip_whitespace(bytes: &[u8], mut index: usize) -> usize {
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    index
}

fn is_php_call(bytes: &[u8], index: usize) -> bool {
    index < bytes.len() && bytes[index] == b'('
}

fn is_non_function_call(code: &str, index: usize) -> bool {
    (index >= 2 && &code[index - 2..index] == "->")
        || (index >= 4 && &code[index - 4..index] == "new ")
}

fn is_allowed_php_call(word: &str) -> bool {
    READONLY_FUNCTIONS
        .iter()
        .any(|function| function.eq_ignore_ascii_case(word))
        || matches!(
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
        )
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
        let cmd = make_cmd(&["-r", r#"$obj->dangerousFunction();"#]);
        let result = check_php_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_gethostbynamel_allowed() {
        let cmd = make_cmd(&[
            "-r",
            r#"var_export(gethostbynamel("93.184.216.34")); echo "\n"; var_export(gethostbynamel("localhost")); echo "\n";"#,
        ]);
        let result = check_php_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }

    #[test]
    fn test_dns_lookup_allowed() {
        let cmd = make_cmd(&[
            "-r",
            r#"var_export(checkdnsrr("example.com", "A")); echo "\n"; var_export(getmxrr("example.com", $hosts)); echo "\n";"#,
        ]);
        let result = check_php_script(&cmd).unwrap();
        assert_eq!(result.permission, Permission::Allow);
    }
}
