use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

#[test]
fn installer_enables_dynamic_completion_for_supported_shells_idempotently() {
    for shell in ["bash", "zsh", "fish"] {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let install_dir = root.path().join("custom bin's $cash");
        let fake_bin = root.path().join("fake-bin");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&fake_bin).unwrap();
        let archive = make_archive(root.path());
        write_executable(
            &fake_bin.join("curl"),
            "#!/bin/sh\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = -o ]; then output=$2; shift 2; else shift; fi\ndone\ncp \"$TEST_ARCHIVE\" \"$output\"\n",
        );
        write_executable(
            &fake_bin.join("uname"),
            "#!/bin/sh\nprintf 'Linux x86_64\\n'\n",
        );

        run_installer(shell, &home, &install_dir, &fake_bin, &archive);
        run_installer(shell, &home, &install_dir, &fake_bin, &archive);

        assert!(install_dir.join("monopass").is_file());
        let (hook_path, expected) = match shell {
            "bash" => (
                home.join(".bashrc"),
                format!(
                    "source <(COMPLETE=bash {})",
                    shell_quote(&install_dir.join("monopass"))
                ),
            ),
            "zsh" => (
                home.join(".zshrc"),
                format!(
                    "source <(COMPLETE=zsh {})",
                    shell_quote(&install_dir.join("monopass"))
                ),
            ),
            "fish" => (
                home.join(".config/fish/completions/monopass.fish"),
                format!(
                    "COMPLETE=fish {} | source",
                    shell_quote(&install_dir.join("monopass"))
                ),
            ),
            _ => unreachable!(),
        };
        let hook = fs::read_to_string(hook_path).unwrap();
        assert_eq!(1, hook.lines().filter(|line| *line == expected).count());
    }
}

fn make_archive(root: &Path) -> PathBuf {
    let payload = root.join("payload");
    fs::create_dir_all(&payload).unwrap();
    write_executable(&payload.join("monopass"), "#!/bin/sh\nexit 0\n");
    let archive = root.join("monopass-linux-x86_64.tar.gz");
    let status = Command::new("tar")
        .args(["-czf"])
        .arg(&archive)
        .arg("-C")
        .arg(&payload)
        .arg("monopass")
        .status()
        .unwrap();
    assert!(status.success());
    archive
}

fn run_installer(shell: &str, home: &Path, install_dir: &Path, fake_bin: &Path, archive: &Path) {
    let system_path = std::env::var("PATH").unwrap();
    let status = Command::new("sh")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("install.sh"))
        .env("HOME", home)
        .env("SHELL", format!("/bin/{shell}"))
        .env("INSTALL_DIR", install_dir)
        .env("MONOPASS_VARIANT", "cli")
        .env("RELEASE_BASE_URL", "https://example.invalid")
        .env("TEST_ARCHIVE", archive)
        .env("PATH", format!("{}:{system_path}", fake_bin.display()))
        .status()
        .unwrap();
    assert!(status.success());
}

fn write_executable(path: &Path, contents: &str) {
    fs::write(path, contents).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', "'\\''"))
}
