//! Source builtin handling
//!
//! `source <file>` and `. <file>` read a script file and execute it.
//! We read the file contents and return them as the inner command for re-analysis.

use crate::analyzer::Command;
use crate::wrappers::UnwrapResult;

const MAX_SOURCE_FILE_SIZE: u64 = 64 * 1024; // 64 KiB

/// Check if this is a source/dot builtin and unwrap it by reading the file
pub fn unwrap(cmd: &Command) -> Option<UnwrapResult> {
    if !matches!(cmd.name.as_str(), "source" | ".") {
        return None;
    }

    let path = find_file_path(&cmd.args)?;
    let path = strip_quotes(path);

    // Only handle absolute paths; relative paths can't be safely resolved here
    if !path.starts_with('/') {
        return None;
    }

    let contents = read_source_file(&path)?;

    Some(UnwrapResult {
        inner_command: Some(contents),
        host: None,
        wrapper: cmd.name.clone(),
    })
}

/// Find the first non-flag argument as the file path
fn find_file_path(args: &[String]) -> Option<&str> {
    args.iter()
        .find(|a| !a.starts_with('-'))
        .map(String::as_str)
}

/// Strip surrounding single or double quotes
fn strip_quotes(s: &str) -> &str {
    let s = s.trim();
    if s.len() >= 2
        && ((s.starts_with('\'') && s.ends_with('\'')) || (s.starts_with('"') && s.ends_with('"')))
    {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

/// Read file contents for analysis, enforcing safety constraints
fn read_source_file(path: &str) -> Option<String> {
    let metadata = std::fs::metadata(path).ok()?;

    // Must be a regular file (not FIFO, device, socket, directory)
    if !metadata.file_type().is_file() {
        return None;
    }

    // Cap at 64 KiB
    if metadata.len() > MAX_SOURCE_FILE_SIZE {
        return None;
    }

    let bytes = std::fs::read(path).ok()?;
    String::from_utf8(bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::make_command;
    use std::io::Write;

    fn make_cmd(name: &str, args: &[&str]) -> Command {
        make_command(name, args)
    }

    #[test]
    fn test_source_reads_allowed_file() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        write!(f, "ls -la\necho hello").unwrap();
        let path = f.path().to_str().unwrap().to_string();

        let cmd = make_cmd("source", &[&path]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("ls -la\necho hello".to_string()));
        assert_eq!(result.wrapper, "source");
    }

    #[test]
    fn test_dot_equivalent_to_source() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        write!(f, "ls -la\necho hello").unwrap();
        let path = f.path().to_str().unwrap().to_string();

        let cmd = make_cmd(".", &[&path]);
        let result = unwrap(&cmd).unwrap();
        assert_eq!(result.inner_command, Some("ls -la\necho hello".to_string()));
    }

    #[test]
    fn test_source_rejects_relative_path() {
        let cmd = make_cmd("source", &["foo.sh"]);
        assert!(unwrap(&cmd).is_none());
    }

    #[test]
    fn test_source_rejects_missing_file() {
        let cmd = make_cmd("source", &["/definitely/not/there/file.sh"]);
        assert!(unwrap(&cmd).is_none());
    }

    #[test]
    fn test_source_rejects_large_file() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        let big = vec![b'a'; 100 * 1024]; // 100 KiB
        f.write_all(&big).unwrap();
        let path = f.path().to_str().unwrap().to_string();

        let cmd = make_cmd("source", &[&path]);
        assert!(unwrap(&cmd).is_none());
    }

    #[test]
    fn test_source_rejects_non_regular_file() {
        // A directory is not a regular file
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().to_str().unwrap().to_string();

        let cmd = make_cmd("source", &[&path]);
        assert!(unwrap(&cmd).is_none());
    }

    #[test]
    fn test_source_rejects_non_utf8() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(&[0xff, 0xfe, 0x00, 0x01]).unwrap();
        let path = f.path().to_str().unwrap().to_string();

        let cmd = make_cmd("source", &[&path]);
        assert!(unwrap(&cmd).is_none());
    }
}
