#![cfg(target_os = "macos")]

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const PASSWORD: &str = "MonopassTestPassword1!";
const WINDOW_TITLE: &str = "monopass access requested";

#[test]
#[ignore = "requires a real macOS GUI session and Accessibility permission for System Events"]
fn gui_unlock_allows_once_and_closes_prompt() {
    let env = TestEnv::new();
    env.init_vault();
    let mut agent = env.start_agent();

    let mut client = env.client("ls");
    wait_for_prompt_count(1, &mut [&mut client]);
    submit_prompt(PASSWORD, PromptAction::Allow);

    assert_child_success(&mut client);
    assert_prompt_count(0);
    agent.stop();
}

#[test]
#[ignore = "requires a real macOS GUI session and Accessibility permission for System Events"]
fn gui_unlock_concurrent_requests_use_independent_windows() {
    let env = TestEnv::new();
    env.init_vault();
    let mut agent = env.start_agent();

    let mut first = env.client("ls");
    let mut second = env.client("ls");

    wait_for_prompt_count(2, &mut [&mut first, &mut second]);
    submit_prompt(PASSWORD, PromptAction::Allow);
    wait_for_exact_prompt_count(1);
    submit_prompt(PASSWORD, PromptAction::Allow);

    assert_child_success(&mut first);
    assert_child_success(&mut second);
    assert_prompt_count(0);
    agent.stop();
}

#[test]
#[ignore = "requires a real macOS GUI session and Accessibility permission for System Events"]
fn gui_unlock_deny_is_remembered_for_process_lineage() {
    let env = TestEnv::new();
    env.init_vault();
    let mut agent = env.start_agent();

    let mut denied = env.client("ls");
    wait_for_prompt_count(1, &mut [&mut denied]);
    submit_prompt("", PromptAction::Deny);
    assert_child_failure_containing(&mut denied, "temporarily locked out after denial");
    assert_prompt_count(0);

    let mut suppressed = env.client("ls");
    assert_child_failure_containing(&mut suppressed, "temporarily locked out after denial");
    assert_prompt_count(0);

    agent.stop();
}

#[test]
#[ignore = "requires a real macOS GUI session and Accessibility permission for System Events"]
fn gui_unlock_wrong_password_does_not_retry() {
    let env = TestEnv::new();
    env.init_vault();
    let mut agent = env.start_agent();

    let mut wrong = env.client("ls");
    wait_for_prompt_count(1, &mut [&mut wrong]);
    submit_prompt("wrong password", PromptAction::Allow);
    assert_child_failure(&mut wrong);
    assert_prompt_count(0);

    agent.stop();
}

#[test]
#[ignore = "requires a real macOS GUI session and Accessibility permission for System Events"]
fn gui_unlock_escape_dismissal_is_not_remembered() {
    let env = TestEnv::new();
    env.init_vault();
    let mut agent = env.start_agent();

    let mut dismissed = env.client("ls");
    wait_for_prompt_count(1, &mut [&mut dismissed]);
    dismiss_prompt_with_escape();
    assert_child_failure(&mut dismissed);
    assert_prompt_count(0);

    let mut prompted_again = env.client("ls");
    wait_for_prompt_count(1, &mut [&mut prompted_again]);
    submit_prompt("", PromptAction::Deny);
    assert_child_failure(&mut prompted_again);
    assert_prompt_count(0);

    agent.stop();
}

struct TestEnv {
    _root: tempfile::TempDir,
    runtime: tempfile::TempDir,
    data: tempfile::TempDir,
}

impl TestEnv {
    fn new() -> Self {
        let root = tempfile::Builder::new()
            .prefix("monopass-gui-")
            .tempdir_in("/tmp")
            .unwrap();
        let runtime = tempfile::Builder::new()
            .prefix("monopass-gui-runtime-")
            .tempdir_in(root.path())
            .unwrap();
        let data = tempfile::Builder::new()
            .prefix("monopass-gui-data-")
            .tempdir_in(root.path())
            .unwrap();
        std::fs::create_dir_all(runtime.path()).unwrap();
        std::fs::create_dir_all(data.path()).unwrap();
        std::fs::set_permissions(runtime.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(data.path(), std::fs::Permissions::from_mode(0o700)).unwrap();

        Self {
            _root: root,
            runtime,
            data,
        }
    }

    fn init_vault(&self) {
        let mut init = self
            .command()
            .arg("init")
            .arg("--auto-start")
            .arg("no")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        let stdin = init.stdin.as_mut().unwrap();
        write!(stdin, "{PASSWORD}\n{PASSWORD}\n").unwrap();

        assert_child_success(&mut init);
    }

    fn start_agent(&self) -> AgentGuard {
        let mut child = self
            .command()
            .arg("agent")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        wait_for_agent_socket(self.listen_path(), &mut child, Duration::from_secs(10));
        AgentGuard { child }
    }

    fn client(&self, arg: &str) -> Child {
        self.command()
            .arg(arg)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    }

    fn command(&self) -> Command {
        let mut command = Command::new(binary());
        command
            .env("XDG_RUNTIME_DIR", self.runtime.path())
            .env("XDG_DATA_HOME", self.data.path())
            .env("XDG_DATA_DIR", self.data.path());
        command
    }

    fn listen_path(&self) -> PathBuf {
        self.runtime.path().join("monopass/agent.sock")
    }
}

struct AgentGuard {
    child: Child,
}

impl AgentGuard {
    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for AgentGuard {
    fn drop(&mut self) {
        self.stop();
    }
}

#[derive(Clone, Copy)]
enum PromptAction {
    Allow,
    Deny,
}

fn binary() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_monopass"))
}

fn wait_child(child: &mut Child, timeout: Duration) -> ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("child process timed out");
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn wait_for_agent_socket(path: PathBuf, child: &mut Child, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while !path.exists() {
        if Instant::now() >= deadline {
            let status = child.try_wait().unwrap();
            let mut stderr = String::new();
            if let Some(mut stream) = child.stderr.take() {
                let _ = stream.read_to_string(&mut stderr);
            }
            panic!(
                "timed out waiting for {}; agent status: {:?}; stderr: {}",
                path.display(),
                status,
                stderr
            );
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn assert_child_success(child: &mut Child) {
    let status = wait_child(child, Duration::from_secs(10));
    let output = child_output(child);
    assert!(
        status.success(),
        "expected success, got {status}; output: {output}"
    );
}

fn assert_child_failure(child: &mut Child) {
    let status = wait_child(child, Duration::from_secs(10));
    let output = child_output(child);
    assert!(
        !status.success(),
        "expected failure, got {status}; output: {output}"
    );
}

fn assert_child_failure_containing(child: &mut Child, expected: &str) {
    let status = wait_child(child, Duration::from_secs(10));
    let output = child_output(child);
    assert!(
        !status.success(),
        "expected failure, got {status}; output: {output}"
    );
    assert!(
        output.contains(expected),
        "expected output to contain {expected:?}; output: {output}"
    );
}

fn child_output(child: &mut Child) -> String {
    let mut stdout = String::new();
    let mut stderr = String::new();
    if let Some(mut stream) = child.stdout.take() {
        let _ = stream.read_to_string(&mut stdout);
    }
    if let Some(mut stream) = child.stderr.take() {
        let _ = stream.read_to_string(&mut stderr);
    }
    format!("stdout={stdout:?}, stderr={stderr:?}")
}

fn wait_for_prompt_count(expected: usize, children: &mut [&mut Child]) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let count = prompt_count();
        if count >= expected {
            return;
        }
        if Instant::now() >= deadline {
            panic!(
                "timed out waiting for {expected} prompt windows, found {count}; processes: {}; child statuses: {:?}",
                monopass_process_summary(),
                child_statuses(children)
            );
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn child_statuses(children: &mut [&mut Child]) -> Vec<Option<ExitStatus>> {
    children
        .iter_mut()
        .map(|child| child.try_wait().unwrap())
        .collect()
}

fn monopass_process_summary() -> String {
    osascript(
        r#"
tell application "System Events"
  set summaries to {}
  repeat with appProcess in (processes whose name is "monopass")
    tell appProcess
      set end of summaries to ((name as text) & ": windows=" & ((count windows) as text))
    end tell
  end repeat
  return summaries as text
end tell
"#,
    )
}

fn assert_prompt_count(expected: usize) {
    wait_for_exact_prompt_count(expected);
}

fn wait_for_exact_prompt_count(expected: usize) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let count = prompt_count();
        if count == expected {
            return;
        }
        if Instant::now() >= deadline {
            panic!("expected {expected} prompt windows, found {count}");
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn prompt_count() -> usize {
    let script = format!(
        r#"
tell application "System Events"
  set promptCount to 0
  repeat with appProcess in (processes whose name is "monopass")
    tell appProcess
      set promptCount to promptCount + (count of (windows whose name is "{WINDOW_TITLE}"))
    end tell
  end repeat
  return promptCount
end tell
"#
    );
    osascript(&script).trim().parse().unwrap()
}

fn submit_prompt(password: &str, action: PromptAction) {
    let button = match action {
        PromptAction::Allow => "Allow",
        PromptAction::Deny => "Deny",
    };
    let script = format!(
        r#"
tell application "System Events"
  repeat with appProcess in (processes whose name is "monopass")
    tell appProcess
      if exists window "{WINDOW_TITLE}" then
        set frontmost to true
        tell window "{WINDOW_TITLE}"
          if "{button}" is "Allow" then
            set value of text field 1 to "{password}"
          end if
          click button "{button}"
        end tell
        return
      end if
    end tell
  end repeat
  error "prompt window not found"
end tell
"#
    );
    osascript(&script);
}

fn dismiss_prompt_with_escape() {
    let script = format!(
        r#"
tell application "System Events"
  repeat with appProcess in (processes whose name is "monopass")
    tell appProcess
      if exists window "{WINDOW_TITLE}" then
        set frontmost to true
        key code 53
        return
      end if
    end tell
  end repeat
  error "prompt window not found"
end tell
"#
    );
    osascript(&script);
}

fn osascript(script: &str) -> String {
    let output = Command::new("osascript")
        .arg("-e")
        .arg(script)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "osascript failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8(output.stdout).unwrap()
}
