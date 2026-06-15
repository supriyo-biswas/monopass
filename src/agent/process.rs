use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ProcessChainHash([u8; 32]);

impl ProcessChainHash {
    #[cfg(test)]
    pub(crate) fn test(value: u8) -> Self {
        let mut hash = [0u8; 32];
        hash[0] = value;
        Self(hash)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcessElement {
    pid: i32,
    exe: ProcessExe,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ProcessExe {
    Path(PathBuf),
    Missing,
}

pub(crate) fn hash_verified_client_chain(peer_pid: i32) -> Option<ProcessChainHash> {
    let resolver = PlatformProcessResolver;
    hash_verified_client_chain_with_resolver(peer_pid, std::env::current_exe().ok()?, &resolver)
}

trait ProcessResolver {
    fn parent_pid(&self, pid: i32) -> Option<i32>;
    fn exe_path(&self, pid: i32) -> Option<PathBuf>;
}

fn hash_verified_client_chain_with_resolver(
    peer_pid: i32,
    agent_exe: impl AsRef<Path>,
    resolver: &impl ProcessResolver,
) -> Option<ProcessChainHash> {
    let mut chain = client_ancestor_chain(peer_pid, resolver)?;
    chain.reverse();

    if client_executable_matches_agent(&chain, agent_exe.as_ref()) {
        chain.pop();
    }

    Some(hash_client_chain(&chain))
}

fn client_ancestor_chain(
    peer_pid: i32,
    resolver: &impl ProcessResolver,
) -> Option<Vec<ProcessElement>> {
    let mut pid = peer_pid;
    let mut chain = Vec::new();
    let mut reached_root = false;

    for _ in 0..256 {
        if chain
            .iter()
            .any(|element: &ProcessElement| element.pid == pid)
        {
            return None;
        }
        let exe = resolver
            .exe_path(pid)
            .map(ProcessExe::Path)
            .unwrap_or(ProcessExe::Missing);
        chain.push(ProcessElement { pid, exe });

        let parent = resolver.parent_pid(pid)?;
        if parent <= 0 {
            reached_root = true;
            break;
        }
        if parent == pid {
            return None;
        }
        pid = parent;
    }

    if !reached_root {
        return None;
    }

    Some(chain)
}

fn client_executable_matches_agent(chain: &[ProcessElement], agent_exe: &Path) -> bool {
    matches!(
        chain.last().map(|element| &element.exe),
        Some(ProcessExe::Path(client_exe)) if same_executable(client_exe, agent_exe)
    )
}

fn same_executable(left: &Path, right: &Path) -> bool {
    let left = left.canonicalize().unwrap_or_else(|_| left.to_owned());
    let right = right.canonicalize().unwrap_or_else(|_| right.to_owned());
    left == right
}

fn hash_client_chain(chain: &[ProcessElement]) -> ProcessChainHash {
    let mut hasher = Sha256::new();
    for element in chain {
        hasher.update(element.pid.to_ne_bytes());
        hasher.update([0]);
        match &element.exe {
            ProcessExe::Path(path) => {
                hasher.update([1]);
                hasher.update(path.as_os_str().as_encoded_bytes());
            }
            ProcessExe::Missing => {
                hasher.update([2]);
                hasher.update(b"<missing-executable-path>");
            }
        }
        hasher.update([0xff]);
    }

    ProcessChainHash(hasher.finalize().into())
}

struct PlatformProcessResolver;

#[cfg(target_os = "linux")]
impl ProcessResolver for PlatformProcessResolver {
    fn parent_pid(&self, pid: i32) -> Option<i32> {
        linux_parent_pid_from_stat(&std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
    }

    fn exe_path(&self, pid: i32) -> Option<PathBuf> {
        std::fs::read_link(format!("/proc/{pid}/exe")).ok()
    }
}

#[cfg(target_os = "linux")]
fn linux_parent_pid_from_stat(stat: &str) -> Option<i32> {
    let close = stat.rfind(')')?;
    let after_comm = stat.get(close + 2..)?;
    let mut fields = after_comm.split_whitespace();
    let _state = fields.next()?;
    fields.next()?.parse().ok()
}

#[cfg(target_os = "macos")]
impl ProcessResolver for PlatformProcessResolver {
    fn parent_pid(&self, pid: i32) -> Option<i32> {
        macos_parent_pid_from_bsd_info(pid)
            .or_else(|| macos_parent_pid_from_short_bsd_info(pid))
            .or_else(|| (pid == 1).then_some(0))
    }

    fn exe_path(&self, pid: i32) -> Option<PathBuf> {
        let mut buffer = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        let len = unsafe { proc_pidpath(pid, buffer.as_mut_ptr().cast(), buffer.len() as u32) };
        if len <= 0 {
            return None;
        }

        buffer.truncate(len as usize);
        Some(PathBuf::from(String::from_utf8(buffer).ok()?))
    }
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn proc_pidpath(pid: libc::pid_t, buffer: *mut libc::c_void, buffersize: u32) -> libc::c_int;
}

#[cfg(target_os = "macos")]
fn macos_parent_pid_from_bsd_info(pid: i32) -> Option<i32> {
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::uninit();
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
    let result = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };

    (result == size)
        .then(|| i32::try_from(unsafe { info.assume_init() }.pbi_ppid).ok())
        .flatten()
}

#[cfg(target_os = "macos")]
fn macos_parent_pid_from_short_bsd_info(pid: i32) -> Option<i32> {
    const PROC_PIDT_SHORTBSDINFO: i32 = 13;

    #[repr(C)]
    struct ProcBsdShortInfo {
        pbsi_pid: u32,
        pbsi_ppid: u32,
        pbsi_pgid: u32,
        pbsi_status: u32,
        pbsi_comm: [libc::c_char; libc::MAXCOMLEN],
        pbsi_flags: u32,
        pbsi_uid: libc::uid_t,
        pbsi_gid: libc::gid_t,
        pbsi_ruid: libc::uid_t,
        pbsi_rgid: libc::gid_t,
        pbsi_svuid: libc::uid_t,
        pbsi_svgid: libc::gid_t,
        pbsi_rfu: u32,
    }

    let mut info = std::mem::MaybeUninit::<ProcBsdShortInfo>::uninit();
    let size = std::mem::size_of::<ProcBsdShortInfo>() as i32;
    let result = unsafe {
        libc::proc_pidinfo(
            pid,
            PROC_PIDT_SHORTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };

    (result == size)
        .then(|| i32::try_from(unsafe { info.assume_init() }.pbsi_ppid).ok())
        .flatten()
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("process-chain authorization is supported only on Linux and macOS");

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::PathBuf;

    use super::{ProcessElement, ProcessExe, ProcessResolver};

    #[derive(Default)]
    struct FakeResolver {
        parents: HashMap<i32, i32>,
        paths: HashMap<i32, PathBuf>,
    }

    impl FakeResolver {
        fn with(mut self, pid: i32, parent: i32, path: &str) -> Self {
            self.parents.insert(pid, parent);
            self.paths.insert(pid, PathBuf::from(path));
            self
        }

        fn with_missing_path(mut self, pid: i32, parent: i32) -> Self {
            self.parents.insert(pid, parent);
            self
        }
    }

    impl ProcessResolver for FakeResolver {
        fn parent_pid(&self, pid: i32) -> Option<i32> {
            self.parents.get(&pid).copied()
        }

        fn exe_path(&self, pid: i32) -> Option<PathBuf> {
            self.paths.get(&pid).cloned()
        }
    }

    #[test]
    fn independent_client_chain_no_longer_needs_to_reach_agent() {
        let resolver = FakeResolver::default()
            .with(10, 9, "/client")
            .with(9, 1, "/shell")
            .with(1, 0, "/init");

        assert!(super::hash_verified_client_chain_with_resolver(10, "/agent", &resolver).is_some());
    }

    #[test]
    fn root_to_client_chain_is_hashed_in_ancestor_order() {
        let resolver = FakeResolver::default()
            .with(10, 9, "/client")
            .with(9, 1, "/shell")
            .with(1, 0, "/init");

        let verified =
            super::hash_verified_client_chain_with_resolver(10, "/agent", &resolver).unwrap();
        let direct = super::hash_client_chain(&[
            path_element(1, "/init"),
            path_element(9, "/shell"),
            path_element(10, "/client"),
        ]);

        assert_eq!(direct, verified);
    }

    #[test]
    fn same_binary_client_executable_is_excluded_from_hash() {
        let resolver = FakeResolver::default()
            .with(10, 9, "/agent")
            .with(9, 1, "/shell")
            .with(1, 0, "/init");

        let verified =
            super::hash_verified_client_chain_with_resolver(10, "/agent", &resolver).unwrap();
        let direct =
            super::hash_client_chain(&[path_element(1, "/init"), path_element(9, "/shell")]);

        assert_eq!(direct, verified);
    }

    #[test]
    fn same_binary_client_executable_exclusion_allows_independent_invocations_from_same_shell() {
        let first = FakeResolver::default()
            .with(10, 9, "/agent")
            .with(9, 1, "/shell")
            .with(1, 0, "/init");
        let second = FakeResolver::default()
            .with(11, 9, "/agent")
            .with(9, 1, "/shell")
            .with(1, 0, "/init");

        let first_hash = super::hash_verified_client_chain_with_resolver(10, "/agent", &first);
        let second_hash = super::hash_verified_client_chain_with_resolver(11, "/agent", &second);

        assert_eq!(first_hash, second_hash);
    }

    #[test]
    fn different_client_executable_is_included_in_hash() {
        let first = FakeResolver::default()
            .with(10, 9, "/client")
            .with(9, 1, "/shell")
            .with(1, 0, "/init");
        let second = FakeResolver::default()
            .with(11, 9, "/other-client")
            .with(9, 1, "/shell")
            .with(1, 0, "/init");

        let first_hash =
            super::hash_verified_client_chain_with_resolver(10, "/agent", &first).unwrap();
        let second_hash =
            super::hash_verified_client_chain_with_resolver(11, "/agent", &second).unwrap();

        assert_ne!(first_hash, second_hash);
    }

    #[test]
    fn different_shell_ancestor_pids_produce_different_hashes() {
        let first = FakeResolver::default()
            .with(10, 9, "/agent")
            .with(9, 1, "/shell")
            .with(1, 0, "/init");
        let second = FakeResolver::default()
            .with(11, 8, "/agent")
            .with(8, 1, "/shell")
            .with(1, 0, "/init");

        let first_hash =
            super::hash_verified_client_chain_with_resolver(10, "/agent", &first).unwrap();
        let second_hash =
            super::hash_verified_client_chain_with_resolver(11, "/agent", &second).unwrap();

        assert_ne!(first_hash, second_hash);
    }

    #[test]
    fn missing_ancestor_executable_path_hashes_marker_instead_of_rejecting() {
        let resolver = FakeResolver::default()
            .with(10, 9, "/agent")
            .with_missing_path(9, 1)
            .with(1, 0, "/init");

        let verified =
            super::hash_verified_client_chain_with_resolver(10, "/agent", &resolver).unwrap();
        let direct = super::hash_client_chain(&[path_element(1, "/init"), missing_element(9)]);

        assert_eq!(direct, verified);
    }

    #[test]
    fn missing_parent_pid_is_rejected() {
        let resolver = FakeResolver::default()
            .with(10, 9, "/agent")
            .with(9, 1, "/shell");

        assert!(super::hash_verified_client_chain_with_resolver(10, "/agent", &resolver).is_none());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_platform_resolver_hashes_current_process_chain() {
        let resolver = super::PlatformProcessResolver;

        assert!(
            super::hash_verified_client_chain_with_resolver(
                std::process::id() as i32,
                "/not/the/current/test/binary",
                &resolver,
            )
            .is_some()
        );
    }

    #[test]
    fn parent_loop_is_rejected() {
        let resolver = FakeResolver::default()
            .with(10, 9, "/agent")
            .with(9, 8, "/shell")
            .with(8, 9, "/login");

        assert!(super::hash_verified_client_chain_with_resolver(10, "/agent", &resolver).is_none());
    }

    #[test]
    fn chain_deeper_than_traversal_limit_is_rejected() {
        let mut resolver = FakeResolver::default();
        for pid in 1..=257 {
            resolver = resolver.with(pid, pid - 1, "/process");
        }

        assert!(
            super::hash_verified_client_chain_with_resolver(257, "/agent", &resolver).is_none()
        );
    }

    #[test]
    fn direct_self_parent_loop_is_rejected() {
        let resolver = FakeResolver::default()
            .with(10, 9, "/agent")
            .with(9, 9, "/shell");

        assert!(super::hash_verified_client_chain_with_resolver(10, "/agent", &resolver).is_none());
    }

    #[test]
    fn different_pid_chains_produce_different_hashes() {
        let first = super::hash_client_chain(&[ProcessElement {
            pid: 10,
            exe: ProcessExe::Path(PathBuf::from("/client")),
        }]);
        let second = super::hash_client_chain(&[ProcessElement {
            pid: 11,
            exe: ProcessExe::Path(PathBuf::from("/client")),
        }]);

        assert_ne!(first, second);
    }

    #[test]
    fn different_paths_produce_different_hashes() {
        let first = super::hash_client_chain(&[ProcessElement {
            pid: 10,
            exe: ProcessExe::Path(PathBuf::from("/client")),
        }]);
        let second = super::hash_client_chain(&[ProcessElement {
            pid: 10,
            exe: ProcessExe::Path(PathBuf::from("/other-client")),
        }]);

        assert_ne!(first, second);
    }

    #[test]
    fn missing_path_marker_produces_different_hash_from_same_pid_path() {
        let missing = super::hash_client_chain(&[missing_element(10)]);
        let resolved = super::hash_client_chain(&[path_element(10, "/client")]);

        assert_ne!(missing, resolved);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_linux_stat_parent_pid() {
        assert_eq!(
            Some(456),
            super::linux_parent_pid_from_stat("123 (name with ) paren) S 456 1 1 0")
        );
    }

    fn path_element(pid: i32, path: &str) -> ProcessElement {
        ProcessElement {
            pid,
            exe: ProcessExe::Path(PathBuf::from(path)),
        }
    }

    fn missing_element(pid: i32) -> ProcessElement {
        ProcessElement {
            pid,
            exe: ProcessExe::Missing,
        }
    }
}
