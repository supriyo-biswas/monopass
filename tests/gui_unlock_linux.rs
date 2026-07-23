#![cfg(all(target_os = "linux", any(feature = "gtk", feature = "qt")))]

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

const PASSWORD: &str = "MonopassTestPassword1!";
const WINDOW_TITLE: &str = "monopass items access requested";

#[test]
#[ignore = "requires an X11 DISPLAY and xdotool"]
fn gui_unlock_allows_once_and_closes_prompt() {
    let _guard = gui_test_lock();
    if !linux_gui_available() {
        return;
    }

    let env = TestEnv::new();
    env.init_vault();
    let mut agent = env.start_agent();

    let mut client = env.client("ls");
    wait_for_prompt_count(1, &mut [&mut client], &mut agent);
    submit_prompt(PASSWORD, PromptAction::Allow);

    assert_child_success(&mut client);
    assert_prompt_count(0);
    agent.stop();
}

#[test]
#[ignore = "requires an X11 DISPLAY and xdotool"]
fn gui_unlock_concurrent_requests_use_independent_windows() {
    let _guard = gui_test_lock();
    if !linux_gui_available() {
        return;
    }

    let env = TestEnv::new();
    env.init_vault();
    let mut agent = env.start_agent();

    let mut first = env.client("ls");
    let mut second = env.client("ls");

    wait_for_prompt_count(2, &mut [&mut first, &mut second], &mut agent);
    submit_prompt(PASSWORD, PromptAction::Allow);
    wait_for_exact_prompt_count(1);
    submit_prompt(PASSWORD, PromptAction::Allow);

    assert_child_success(&mut first);
    assert_child_success(&mut second);
    assert_prompt_count(0);
    agent.stop();
}

#[test]
#[ignore = "requires an X11 DISPLAY and xdotool"]
fn gui_unlock_cancel_or_wrong_password_does_not_retry() {
    let _guard = gui_test_lock();
    if !linux_gui_available() {
        return;
    }

    let env = TestEnv::new();
    env.init_vault();
    let mut agent = env.start_agent();

    let mut cancelled = env.client("ls");
    wait_for_prompt_count(1, &mut [&mut cancelled], &mut agent);
    submit_prompt("", PromptAction::Cancel);
    assert_child_failure(&mut cancelled);
    assert_prompt_count(0);

    let mut wrong = env.client("ls");
    wait_for_prompt_count(1, &mut [&mut wrong], &mut agent);
    submit_prompt("wrong password", PromptAction::Allow);
    assert_child_failure(&mut wrong);
    assert_prompt_count(0);

    agent.stop();
}

#[test]
#[ignore = "requires an X11 DISPLAY and xdotool"]
fn gui_unlock_deny_is_remembered_for_process_lineage() {
    let _guard = gui_test_lock();
    if !linux_gui_available() {
        return;
    }

    let env = TestEnv::new();
    env.init_vault();
    let mut agent = env.start_agent();

    let mut denied = env.client("ls");
    wait_for_prompt_count(1, &mut [&mut denied], &mut agent);
    submit_prompt("", PromptAction::Deny);
    assert_child_failure_containing(&mut denied, "temporarily locked out after denial");
    assert_prompt_count(0);

    let mut suppressed = env.client("ls");
    assert_child_failure_containing(&mut suppressed, "temporarily locked out after denial");
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
            .prefix("monopass-gui-linux-")
            .tempdir_in("/tmp")
            .unwrap();
        let runtime = tempfile::Builder::new()
            .prefix("runtime-")
            .tempdir_in(root.path())
            .unwrap();
        let data = tempfile::Builder::new()
            .prefix("data-")
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
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        wait_for_agent_listening(self.listen_path(), &mut child, Duration::from_secs(10));
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
            .env("XDG_DATA_DIR", self.data.path())
            .env_remove("LISTEN_PID")
            .env("NO_AT_BRIDGE", "1")
            .env("GDK_BACKEND", "x11")
            .env("GTK_CSD", "0")
            .env("GDK_SYNCHRONIZE", "1")
            .env("GSK_RENDERER", "cairo")
            .env("LIBGL_ALWAYS_SOFTWARE", "1")
            .env_remove("LISTEN_FDS");
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
    fn diagnostics(&mut self) -> String {
        let status = self.child.try_wait().unwrap();
        let stderr = if status.is_some() {
            let mut stderr = String::new();
            if let Some(mut stream) = self.child.stderr.take() {
                let _ = stream.read_to_string(&mut stderr);
            }
            stderr
        } else {
            String::from("still running")
        };
        format!("status={status:?}, stderr={stderr:?}")
    }

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
    Cancel,
    Deny,
}

fn binary() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_monopass"))
}

fn gui_test_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn linux_gui_available() -> bool {
    if std::env::var_os("DISPLAY").is_none() {
        eprintln!("skipping Linux GUI unlock test: DISPLAY is not set");
        return false;
    }
    if Command::new("xdotool")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_err()
    {
        eprintln!("skipping Linux GUI unlock test: xdotool is not installed");
        return false;
    }
    true
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

fn wait_for_agent_listening(path: PathBuf, child: &mut Child, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    let stdout = child.stdout.take().expect("agent stdout is piped");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();

    loop {
        match reader.read_line(&mut line) {
            Ok(0) => {
                let status = child.try_wait().unwrap();
                let mut stderr = String::new();
                if let Some(mut stream) = child.stderr.take() {
                    let _ = stream.read_to_string(&mut stderr);
                }
                panic!(
                    "agent exited before listening on {}; status: {:?}; stdout: {}; stderr: {}",
                    path.display(),
                    status,
                    line,
                    stderr
                );
            }
            Ok(_) if line.contains("Listening on") => {
                thread::sleep(Duration::from_millis(100));
                return;
            }
            Ok(_) => {
                line.clear();
            }
            Err(error) => panic!("failed reading agent stdout: {error}"),
        }

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

fn wait_for_prompt_count(expected: usize, children: &mut [&mut Child], agent: &mut AgentGuard) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let count = prompt_windows().len();
        if count >= expected {
            return;
        }
        if Instant::now() >= deadline {
            panic!(
                "timed out waiting for {expected} prompt windows, found {count}; windows: {}; children: {:?}; agent: {}",
                xdotool_search_debug(),
                child_diagnostics(children),
                agent.diagnostics()
            );
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn child_diagnostics(children: &mut [&mut Child]) -> Vec<String> {
    children
        .iter_mut()
        .map(|child| {
            let status = child.try_wait().unwrap();
            let output = if status.is_some() {
                child_output(child)
            } else {
                String::from("still running")
            };
            format!("status={status:?}, {output}")
        })
        .collect()
}

fn assert_prompt_count(expected: usize) {
    wait_for_exact_prompt_count(expected);
}

fn wait_for_exact_prompt_count(expected: usize) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let count = prompt_windows().len();
        if count == expected {
            return;
        }
        if Instant::now() >= deadline {
            panic!(
                "expected {expected} prompt windows, found {count}; windows: {}",
                xdotool_search_debug()
            );
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn prompt_windows() -> Vec<String> {
    let output = Command::new("xdotool")
        .arg("search")
        .arg("--onlyvisible")
        .arg("--name")
        .arg(WINDOW_TITLE)
        .output()
        .unwrap();

    if !output.status.success() {
        return Vec::new();
    }

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn submit_prompt(password: &str, action: PromptAction) {
    let Some(window) = first_prompt_window(Duration::from_secs(2)) else {
        panic!(
            "prompt window not found; windows: {}",
            xdotool_search_debug()
        );
    };

    run_xdotool(&["windowfocus", "--sync", &window]);
    run_xdotool(&["mousemove", "--window", &window, "230", "150"]);
    run_xdotool(&["click", "--window", &window, "1"]);

    match action {
        PromptAction::Allow => {
            if !password.is_empty() {
                run_xdotool(&["type", "--clearmodifiers", password]);
            }
            thread::sleep(Duration::from_millis(100));
            if prompt_windows()
                .iter()
                .any(|candidate| candidate == &window)
            {
                let output = Command::new("xdotool")
                    .args(["key", "Return"])
                    .output()
                    .unwrap();
                if !output.status.success()
                    && prompt_windows()
                        .iter()
                        .any(|candidate| candidate == &window)
                {
                    panic!(
                        "xdotool {:?} failed: stdout={}, stderr={}",
                        ["key", "Return", "", ""],
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
            }
        }
        PromptAction::Cancel => {
            run_xdotool(&["windowfocus", "--sync", &window]);
            if prompt_windows()
                .iter()
                .any(|candidate| candidate == &window)
            {
                let output = Command::new("xdotool")
                    .args(["key", "Escape"])
                    .output()
                    .unwrap();
                if !output.status.success()
                    && prompt_windows()
                        .iter()
                        .any(|candidate| candidate == &window)
                {
                    panic!(
                        "xdotool {:?} failed: stdout={}, stderr={}",
                        ["key", "Escape", "", ""],
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
            }
        }
        PromptAction::Deny => {
            #[cfg(feature = "gtk")]
            {
                run_xdotool(&["windowfocus", "--sync", &window]);
                run_xdotool(&["key", "Tab"]);
                run_xdotool(&["key", "Return"]);
            }
            #[cfg(feature = "qt")]
            {
                run_xdotool(&["mousemove", "--window", &window, "330", "165"]);
                run_xdotool(&["click", "--window", &window, "1"]);
            }
        }
    }
}

fn first_prompt_window(timeout: Duration) -> Option<String> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(window) = prompt_windows().into_iter().next() {
            return Some(window);
        }
        if Instant::now() >= deadline {
            return None;
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn run_xdotool(args: &[&str]) {
    let output = Command::new("xdotool").args(args).output().unwrap();
    assert!(
        output.status.success(),
        "xdotool {:?} failed: stdout={}, stderr={}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn xdotool_search_debug() -> String {
    let output = Command::new("xdotool")
        .arg("search")
        .arg("--onlyvisible")
        .arg("--name")
        .arg(".")
        .output();

    match output {
        Ok(output) => format!(
            "status={}, stdout={}, stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
        Err(error) => format!("xdotool search failed to start: {error}"),
    }
}
