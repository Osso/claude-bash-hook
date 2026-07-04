use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};

pub trait Backend {
    fn complete<'a>(
        &'a self,
        prompt: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Output>> + Send + 'a>>;
}

#[derive(Debug)]
pub struct Output {
    pub text: String,
}

pub mod codex_cli {
    use super::*;

    #[derive(Clone)]
    pub struct CodexCli {
        binary: PathBuf,
        model: Option<String>,
        timeout: Option<Duration>,
    }

    impl CodexCli {
        pub fn new() -> Result<Self> {
            let binary =
                find_binary("codex").ok_or_else(|| anyhow!("codex binary not found in PATH"))?;
            Ok(Self {
                binary,
                model: None,
                timeout: None,
            })
        }

        pub fn model(mut self, model: impl Into<String>) -> Self {
            self.model = Some(model.into());
            self
        }

        pub fn timeout(mut self, timeout: Duration) -> Self {
            self.timeout = Some(timeout);
            self
        }

        async fn run_completion(&self, prompt: &str) -> Result<Output> {
            let mut child = spawn_codex(self.build_command(), prompt).await?;
            let stdout = take_stdout(&mut child)?;
            let stderr = take_stderr(&mut child)?;
            let completion = wait_for_completion(child, stdout, stderr, self.timeout).await?;
            output_from_completion(completion)
        }

        fn build_command(&self) -> Command {
            let mut command = Command::new(&self.binary);
            command
                .arg("exec")
                .arg("--json")
                .arg("--ephemeral")
                .arg("--dangerously-bypass-approvals-and-sandbox")
                .arg("--skip-git-repo-check");

            if let Some(model) = &self.model {
                command.arg("--model").arg(model);
            }

            command
                .arg("-")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .env_remove("CLAUDECODE")
                .env_remove("CLAUDE_CODE_ENTRYPOINT");

            command
        }
    }

    impl Backend for CodexCli {
        fn complete<'a>(
            &'a self,
            prompt: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Output>> + Send + 'a>> {
            Box::pin(self.run_completion(prompt))
        }
    }

    async fn spawn_codex(mut command: Command, prompt: &str) -> Result<Child> {
        let mut child = command.spawn().context("failed to spawn codex")?;
        write_prompt(&mut child, prompt).await?;
        Ok(child)
    }

    fn take_stdout(child: &mut Child) -> Result<tokio::process::ChildStdout> {
        child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("codex stdout was not captured"))
    }

    fn take_stderr(child: &mut Child) -> Result<tokio::process::ChildStderr> {
        child
            .stderr
            .take()
            .ok_or_else(|| anyhow!("codex stderr was not captured"))
    }

    async fn wait_for_completion(
        mut child: Child,
        stdout: tokio::process::ChildStdout,
        stderr: tokio::process::ChildStderr,
        timeout: Option<Duration>,
    ) -> Result<(Output, String, ExitStatus)> {
        let completion = async {
            let stdout_task = read_stdout(stdout);
            let stderr_task = read_stderr(stderr);
            let wait_task = child.wait();
            let (output, stderr, status) = tokio::join!(stdout_task, stderr_task, wait_task);
            Ok((
                output?,
                stderr?,
                status.context("failed to wait for codex")?,
            ))
        };

        match timeout {
            Some(timeout) => tokio::time::timeout(timeout, completion)
                .await
                .context("codex timed out")?,
            None => completion.await,
        }
    }

    fn output_from_completion(completion: (Output, String, ExitStatus)) -> Result<Output> {
        let (output, stderr, status) = completion;
        if status.success() {
            return Ok(output);
        }

        Err(anyhow!(
            "codex exited with status {}: {}",
            status,
            stderr.trim()
        ))
    }

    fn find_binary(name: &str) -> Option<PathBuf> {
        let path = std::env::var_os("PATH")?;
        std::env::split_paths(&path)
            .map(|dir| dir.join(name))
            .find(|candidate| is_executable(candidate))
    }

    fn is_executable(path: &Path) -> bool {
        path.is_file()
    }

    async fn write_prompt(child: &mut tokio::process::Child, prompt: &str) -> Result<()> {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("codex stdin was not captured"))?;
        stdin
            .write_all(prompt.as_bytes())
            .await
            .context("failed to write prompt to codex")?;
        stdin
            .shutdown()
            .await
            .context("failed to close codex stdin")
    }

    async fn read_stdout(stdout: tokio::process::ChildStdout) -> Result<Output> {
        let mut lines = BufReader::new(stdout).lines();
        let mut text = String::new();

        while let Some(line) = lines
            .next_line()
            .await
            .context("failed to read codex stdout")?
        {
            if let Some(message) = extract_message(&line)? {
                text = message;
            }
        }

        Ok(Output { text })
    }

    async fn read_stderr(stderr: tokio::process::ChildStderr) -> Result<String> {
        let mut lines = BufReader::new(stderr).lines();
        let mut output = String::new();

        while let Some(line) = lines
            .next_line()
            .await
            .context("failed to read codex stderr")?
        {
            output.push_str(&line);
            output.push('\n');
        }

        Ok(output)
    }

    fn extract_message(line: &str) -> Result<Option<String>> {
        let value: serde_json::Value = serde_json::from_str(line)
            .with_context(|| format!("failed to parse codex JSON line: {line}"))?;

        if value.get("type").and_then(serde_json::Value::as_str) != Some("item.completed") {
            return Ok(None);
        }

        let Some(item) = value.get("item") else {
            return Ok(None);
        };

        Ok(item
            .get("text")
            .or_else(|| item.get("message"))
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned))
    }
}
