use std::fs::Metadata;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use sha2::{Digest, Sha256};

const MAX_PROCESS_CHAIN_DEPTH: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ScopeHash([u8; 32]);

impl ScopeHash {
    #[cfg(test)]
    pub(crate) fn test(value: u8) -> Self {
        let mut hash = [0u8; 32];
        hash[0] = value;
        Self(hash)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProcessStartTime {
    primary: u64,
    secondary: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProcessInstanceIdentity {
    pid: i32,
    start_time: ProcessStartTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExecutableIdentity {
    device: u64,
    inode: u64,
    generation: Option<u32>,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl ExecutableIdentity {
    fn from_path(path: &Path) -> Option<Self> {
        std::fs::metadata(path)
            .ok()
            .map(|metadata| executable_identity(&metadata))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StableProcessIdentity {
    Executable(ExecutableIdentity),
    Instance(ProcessInstanceIdentity),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcessInfo {
    instance: ProcessInstanceIdentity,
    parent_pid: i32,
    uid: u32,
    session_id: i32,
    executable: Option<ExecutableIdentity>,
    executable_path: Option<PathBuf>,
    executable_modified: Option<SystemTime>,
}

impl ProcessInfo {
    fn stable_identity(&self) -> StableProcessIdentity {
        self.executable
            .map(StableProcessIdentity::Executable)
            .unwrap_or(StableProcessIdentity::Instance(self.instance))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthorizationScope {
    uid: u32,
    session_id: i32,
    anchor: ProcessInstanceIdentity,
    chain: Vec<StableProcessIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedAuthorizationScope {
    pub(crate) hash: ScopeHash,
    pub(crate) display: Option<ProcessDisplay>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcessDisplay {
    pub(crate) name: String,
    pub(crate) path: PathBuf,
    pub(crate) icon_path: Option<PathBuf>,
    pub(crate) modified: Option<SystemTime>,
}

#[cfg(test)]
pub(crate) fn resolve_authorization_scope_hash(peer_pid: i32, peer_uid: u32) -> Option<ScopeHash> {
    resolve_authorization_scope(peer_pid, peer_uid).map(|scope| scope.hash)
}

pub(crate) fn resolve_authorization_scope(
    peer_pid: i32,
    peer_uid: u32,
) -> Option<ResolvedAuthorizationScope> {
    let resolver = PlatformProcessResolver;
    resolve_authorization_scope_with_resolver(peer_pid, peer_uid, &resolver)
}

trait ProcessResolver {
    fn process_info(&self, pid: i32) -> Option<ProcessInfo>;
    fn process_uid(&self, pid: i32) -> Option<u32>;
}

#[cfg(test)]
fn resolve_authorization_scope_hash_with_resolver(
    peer_pid: i32,
    peer_uid: u32,
    resolver: &impl ProcessResolver,
) -> Option<ScopeHash> {
    resolve_authorization_scope_with_resolver(peer_pid, peer_uid, resolver).map(|scope| scope.hash)
}

fn resolve_authorization_scope_with_resolver(
    peer_pid: i32,
    peer_uid: u32,
    resolver: &impl ProcessResolver,
) -> Option<ResolvedAuthorizationScope> {
    let mut current = resolver.process_info(peer_pid)?;
    if current.uid != peer_uid {
        return None;
    }

    let session_id = current.session_id;
    let mut chain = Vec::new();

    for _ in 0..MAX_PROCESS_CHAIN_DEPTH {
        if current.uid != peer_uid || current.session_id != session_id {
            break;
        }
        if chain
            .iter()
            .any(|element: &ProcessInfo| element.instance.pid == current.instance.pid)
        {
            return None;
        }

        let parent_pid = current.parent_pid;
        chain.push(current);
        if parent_pid <= 0 {
            break;
        }

        let parent_uid = resolver.process_uid(parent_pid)?;
        if parent_uid != peer_uid {
            break;
        }

        let parent = resolver.process_info(parent_pid)?;
        if parent.uid != peer_uid || parent.session_id != session_id {
            break;
        }
        current = parent;
    }

    if chain.is_empty() {
        return None;
    }
    if chain.len() == MAX_PROCESS_CHAIN_DEPTH
        && chain.last().is_some_and(|process| process.parent_pid > 0)
    {
        return None;
    }

    chain.reverse();
    let anchor = chain.first()?.instance;
    let scope = AuthorizationScope {
        uid: peer_uid,
        session_id,
        anchor,
        chain: chain.iter().map(ProcessInfo::stable_identity).collect(),
    };

    Some(ResolvedAuthorizationScope {
        hash: hash_authorization_scope(&scope),
        display: process_display_from_chain(&chain),
    })
}

fn process_display_from_chain(chain: &[ProcessInfo]) -> Option<ProcessDisplay> {
    let agent_executable = std::env::current_exe()
        .ok()
        .and_then(|path| ExecutableIdentity::from_path(&path));

    process_display_from_chain_with_agent(chain, agent_executable)
}

fn process_display_from_chain_with_agent(
    chain: &[ProcessInfo],
    agent_executable: Option<ExecutableIdentity>,
) -> Option<ProcessDisplay> {
    chain
        .iter()
        .rev()
        .find(|process| {
            process.executable.is_some()
                && process.executable_path.is_some()
                && process.executable != agent_executable
        })
        .or_else(|| {
            chain
                .iter()
                .rev()
                .find(|process| process.executable_path.is_some())
        })
        .and_then(process_display)
}

fn process_display(process: &ProcessInfo) -> Option<ProcessDisplay> {
    let path = process.executable_path.clone()?;
    let bundle_path = app_bundle_path(&path);
    let name_path = bundle_path.as_deref().unwrap_or(path.as_path());
    let name = name_path
        .file_stem()
        .or_else(|| name_path.file_name())
        .map(|name| name.to_string_lossy().into_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| format!("pid {}", process.instance.pid));

    Some(ProcessDisplay {
        name,
        path,
        icon_path: bundle_path,
        modified: process.executable_modified,
    })
}

fn app_bundle_path(path: &Path) -> Option<PathBuf> {
    path.ancestors()
        .find(|ancestor| {
            ancestor
                .extension()
                .is_some_and(|extension| extension == "app")
        })
        .map(Path::to_path_buf)
}

fn hash_authorization_scope(scope: &AuthorizationScope) -> ScopeHash {
    let mut hasher = Sha256::new();
    hasher.update(b"monopass-authorization-scope-v1\0");
    hasher.update(scope.uid.to_le_bytes());
    hasher.update(scope.session_id.to_le_bytes());
    hash_instance(&mut hasher, scope.anchor);
    hasher.update((scope.chain.len() as u64).to_le_bytes());

    for identity in &scope.chain {
        match identity {
            StableProcessIdentity::Executable(executable) => {
                hasher.update([1]);
                hasher.update(executable.device.to_le_bytes());
                hasher.update(executable.inode.to_le_bytes());
                match executable.generation {
                    Some(generation) => {
                        hasher.update([1]);
                        hasher.update(generation.to_le_bytes());
                    }
                    None => hasher.update([0]),
                }
                hasher.update(executable.size.to_le_bytes());
                hasher.update(executable.modified_seconds.to_le_bytes());
                hasher.update(executable.modified_nanoseconds.to_le_bytes());
                hasher.update(executable.changed_seconds.to_le_bytes());
                hasher.update(executable.changed_nanoseconds.to_le_bytes());
            }
            StableProcessIdentity::Instance(instance) => {
                hasher.update([2]);
                hash_instance(&mut hasher, *instance);
            }
        }
    }

    ScopeHash(hasher.finalize().into())
}

fn hash_instance(hasher: &mut Sha256, instance: ProcessInstanceIdentity) {
    hasher.update(instance.pid.to_le_bytes());
    hasher.update(instance.start_time.primary.to_le_bytes());
    hasher.update(instance.start_time.secondary.to_le_bytes());
}

fn executable_identity(metadata: &Metadata) -> ExecutableIdentity {
    use std::os::unix::fs::MetadataExt;

    ExecutableIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        generation: executable_generation(metadata),
        size: metadata.size(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    }
}

#[cfg(target_os = "linux")]
fn executable_generation(_metadata: &Metadata) -> Option<u32> {
    None
}

#[cfg(target_os = "macos")]
fn executable_generation(metadata: &Metadata) -> Option<u32> {
    Some(std::os::darwin::fs::MetadataExt::st_gen(metadata))
}

struct PlatformProcessResolver;

#[cfg(target_os = "linux")]
impl ProcessResolver for PlatformProcessResolver {
    fn process_info(&self, pid: i32) -> Option<ProcessInfo> {
        use std::os::unix::fs::MetadataExt;

        let process_dir = std::fs::metadata(format!("/proc/{pid}")).ok()?;
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let stat = parse_linux_process_stat(&stat)?;

        let executable_path = std::fs::read_link(format!("/proc/{pid}/exe")).ok();
        let executable_metadata = executable_path
            .as_ref()
            .and_then(|path| std::fs::metadata(path).ok());

        Some(ProcessInfo {
            instance: ProcessInstanceIdentity {
                pid,
                start_time: ProcessStartTime {
                    primary: stat.start_time,
                    secondary: 0,
                },
            },
            parent_pid: stat.parent_pid,
            uid: process_dir.uid(),
            session_id: stat.session_id,
            executable: executable_metadata.as_ref().map(executable_identity),
            executable_path,
            executable_modified: executable_metadata.and_then(|metadata| metadata.modified().ok()),
        })
    }

    fn process_uid(&self, pid: i32) -> Option<u32> {
        use std::os::unix::fs::MetadataExt;

        Some(std::fs::metadata(format!("/proc/{pid}")).ok()?.uid())
    }
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LinuxProcessStat {
    parent_pid: i32,
    session_id: i32,
    start_time: u64,
}

#[cfg(any(target_os = "linux", test))]
fn parse_linux_process_stat(stat: &str) -> Option<LinuxProcessStat> {
    let close = stat.rfind(')')?;
    let after_comm = stat.get(close + 2..)?;
    let mut fields = after_comm.split_whitespace();
    let _state = fields.next()?;
    let parent_pid = fields.next()?.parse().ok()?;
    let _process_group = fields.next()?;
    let session_id = fields.next()?.parse().ok()?;
    for _ in 7..=21 {
        fields.next()?;
    }
    let start_time = fields.next()?.parse().ok()?;

    Some(LinuxProcessStat {
        parent_pid,
        session_id,
        start_time,
    })
}

#[cfg(target_os = "macos")]
impl ProcessResolver for PlatformProcessResolver {
    fn process_info(&self, pid: i32) -> Option<ProcessInfo> {
        let info = macos_bsd_info(pid)?;
        let session_id = unsafe { libc::getsid(pid) };
        if session_id < 0 {
            return None;
        }

        let executable_path = macos_executable_path(pid);
        let executable_metadata = executable_path
            .as_ref()
            .and_then(|path| std::fs::metadata(path).ok());

        Some(ProcessInfo {
            instance: ProcessInstanceIdentity {
                pid,
                start_time: ProcessStartTime {
                    primary: info.pbi_start_tvsec,
                    secondary: info.pbi_start_tvusec,
                },
            },
            parent_pid: i32::try_from(info.pbi_ppid).ok()?,
            uid: info.pbi_uid,
            session_id,
            executable: executable_metadata.as_ref().map(executable_identity),
            executable_path,
            executable_modified: executable_metadata.and_then(|metadata| metadata.modified().ok()),
        })
    }

    fn process_uid(&self, pid: i32) -> Option<u32> {
        macos_bsd_info(pid)
            .map(|info| info.pbi_uid)
            .or_else(|| macos_short_bsd_info(pid).map(|info| info.pbsi_uid))
    }
}

#[cfg(target_os = "macos")]
fn macos_executable_path(pid: i32) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStringExt;

    let mut buffer = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let len = unsafe { proc_pidpath(pid, buffer.as_mut_ptr().cast(), buffer.len() as u32) };
    if len <= 0 {
        return None;
    }

    buffer.truncate(len as usize);
    let path = std::ffi::OsString::from_vec(buffer);
    Some(PathBuf::from(path))
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn proc_pidpath(pid: libc::pid_t, buffer: *mut libc::c_void, buffersize: u32) -> libc::c_int;
}

#[cfg(target_os = "macos")]
fn macos_bsd_info(pid: i32) -> Option<libc::proc_bsdinfo> {
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

    (result == size).then(|| unsafe { info.assume_init() })
}

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
fn macos_short_bsd_info(pid: i32) -> Option<ProcBsdShortInfo> {
    const PROC_PIDT_SHORTBSDINFO: i32 = 13;

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

    (result == size).then(|| unsafe { info.assume_init() })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("process-lineage authorization is supported only on Linux and macOS");

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::time::{Duration, UNIX_EPOCH};

    use super::{
        ExecutableIdentity, ProcessInfo, ProcessInstanceIdentity, ProcessResolver, ProcessStartTime,
    };

    const UID: u32 = 501;
    const SID: i32 = 9;

    #[derive(Default)]
    struct FakeResolver {
        processes: HashMap<i32, ProcessInfo>,
        visible_uids: HashMap<i32, u32>,
    }

    impl FakeResolver {
        fn with(mut self, pid: i32, parent: i32, uid: u32, sid: i32, exe: u64) -> Self {
            let process = process(pid, parent, uid, sid, Some(exe));
            self.visible_uids.insert(pid, uid);
            self.processes.insert(pid, process);
            self
        }

        fn with_path(
            mut self,
            pid: i32,
            parent: i32,
            uid: u32,
            sid: i32,
            exe: u64,
            path: &str,
        ) -> Self {
            let mut process = process(pid, parent, uid, sid, Some(exe));
            process.executable_path = Some(PathBuf::from(path));
            process.executable_modified = Some(UNIX_EPOCH + Duration::from_secs(exe));
            self.visible_uids.insert(pid, uid);
            self.processes.insert(pid, process);
            self
        }

        fn with_missing_executable(mut self, pid: i32, parent: i32, uid: u32, sid: i32) -> Self {
            let process = process(pid, parent, uid, sid, None);
            self.visible_uids.insert(pid, uid);
            self.processes.insert(pid, process);
            self
        }

        fn with_uid_only(mut self, pid: i32, uid: u32) -> Self {
            self.visible_uids.insert(pid, uid);
            self
        }
    }

    impl ProcessResolver for FakeResolver {
        fn process_info(&self, pid: i32) -> Option<ProcessInfo> {
            self.processes.get(&pid).cloned()
        }

        fn process_uid(&self, pid: i32) -> Option<u32> {
            self.visible_uids.get(&pid).copied()
        }
    }

    #[test]
    fn transient_process_pids_are_ignored_when_executables_match() {
        let first = FakeResolver::default()
            .with(12, 11, UID, SID, 3)
            .with(11, 10, UID, SID, 2)
            .with(10, 9, UID, SID, 1)
            .with(9, 1, UID, SID, 9)
            .with(1, 0, 0, 1, 8);
        let second = FakeResolver::default()
            .with(22, 21, UID, SID, 3)
            .with(21, 20, UID, SID, 2)
            .with(20, 9, UID, SID, 1)
            .with(9, 1, UID, SID, 9)
            .with(1, 0, 0, 1, 8);

        let first = super::resolve_authorization_scope_hash_with_resolver(12, UID, &first);
        let second = super::resolve_authorization_scope_hash_with_resolver(22, UID, &second);

        assert_eq!(first, second);
    }

    #[test]
    fn direct_client_executable_is_included() {
        let first = FakeResolver::default()
            .with(10, 9, UID, SID, 1)
            .with(9, 1, UID, SID, 9)
            .with_uid_only(1, 0);
        let second = FakeResolver::default()
            .with(11, 9, UID, SID, 2)
            .with(9, 1, UID, SID, 9)
            .with_uid_only(1, 0);

        assert_ne!(
            super::resolve_authorization_scope_hash_with_resolver(10, UID, &first),
            super::resolve_authorization_scope_hash_with_resolver(11, UID, &second)
        );
    }

    #[test]
    fn different_anchor_instances_are_distinct() {
        let first = FakeResolver::default()
            .with(10, 9, UID, SID, 1)
            .with(9, 1, UID, SID, 9)
            .with_uid_only(1, 0);
        let second = FakeResolver::default()
            .with(10, 8, UID, SID, 1)
            .with(8, 1, UID, SID, 9)
            .with_uid_only(1, 0);

        assert_ne!(
            super::resolve_authorization_scope_hash_with_resolver(10, UID, &first),
            super::resolve_authorization_scope_hash_with_resolver(10, UID, &second)
        );
    }

    #[test]
    fn different_sessions_are_distinct() {
        let first = FakeResolver::default()
            .with(10, 9, UID, SID, 1)
            .with(9, 1, UID, SID, 9)
            .with_uid_only(1, 0);
        let second = FakeResolver::default()
            .with(10, 9, UID, 8, 1)
            .with(9, 1, UID, 8, 9)
            .with_uid_only(1, 0);

        assert_ne!(
            super::resolve_authorization_scope_hash_with_resolver(10, UID, &first),
            super::resolve_authorization_scope_hash_with_resolver(10, UID, &second)
        );
    }

    #[test]
    fn missing_executable_falls_back_to_process_instance() {
        let first = FakeResolver::default()
            .with_missing_executable(10, 9, UID, SID)
            .with(9, 1, UID, SID, 9)
            .with_uid_only(1, 0);
        let second = FakeResolver::default()
            .with_missing_executable(11, 9, UID, SID)
            .with(9, 1, UID, SID, 9)
            .with_uid_only(1, 0);

        assert_ne!(
            super::resolve_authorization_scope_hash_with_resolver(10, UID, &first),
            super::resolve_authorization_scope_hash_with_resolver(11, UID, &second)
        );
    }

    #[test]
    fn changed_executable_metadata_changes_scope() {
        let first = FakeResolver::default()
            .with(10, 9, UID, SID, 1)
            .with(9, 1, UID, SID, 9)
            .with_uid_only(1, 0);
        let second = FakeResolver::default()
            .with(10, 9, UID, SID, 2)
            .with(9, 1, UID, SID, 9)
            .with_uid_only(1, 0);

        assert_ne!(
            super::resolve_authorization_scope_hash_with_resolver(10, UID, &first),
            super::resolve_authorization_scope_hash_with_resolver(10, UID, &second)
        );
    }

    #[test]
    fn different_user_parent_is_a_successful_boundary() {
        let resolver = FakeResolver::default()
            .with(10, 9, UID, SID, 1)
            .with(9, 1, UID, SID, 9)
            .with_uid_only(1, 0);

        assert!(
            super::resolve_authorization_scope_hash_with_resolver(10, UID, &resolver).is_some()
        );
    }

    #[test]
    fn different_session_parent_is_a_successful_boundary() {
        let resolver = FakeResolver::default()
            .with(10, 9, UID, SID, 1)
            .with(9, 8, UID, SID, 9)
            .with(8, 1, UID, 8, 8);

        assert!(
            super::resolve_authorization_scope_hash_with_resolver(10, UID, &resolver).is_some()
        );
    }

    #[test]
    fn inaccessible_same_user_parent_is_rejected() {
        let resolver = FakeResolver::default()
            .with(10, 9, UID, SID, 1)
            .with_uid_only(9, UID);

        assert!(
            super::resolve_authorization_scope_hash_with_resolver(10, UID, &resolver).is_none()
        );
    }

    #[test]
    fn missing_parent_uid_is_rejected() {
        let resolver = FakeResolver::default().with(10, 9, UID, SID, 1);

        assert!(
            super::resolve_authorization_scope_hash_with_resolver(10, UID, &resolver).is_none()
        );
    }

    #[test]
    fn parent_loop_is_rejected() {
        let resolver = FakeResolver::default()
            .with(10, 9, UID, SID, 1)
            .with(9, 10, UID, SID, 9);

        assert!(
            super::resolve_authorization_scope_hash_with_resolver(10, UID, &resolver).is_none()
        );
    }

    #[test]
    fn chain_deeper_than_traversal_limit_is_rejected() {
        let mut resolver = FakeResolver::default();
        for pid in 1..=257 {
            resolver = resolver.with(pid, pid - 1, UID, SID, pid as u64);
        }

        assert!(
            super::resolve_authorization_scope_hash_with_resolver(257, UID, &resolver).is_none()
        );
    }

    #[test]
    fn parses_linux_process_stat() {
        let stat = "123 (name with ) paren) S 456 444 333 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 999";

        assert_eq!(
            Some(super::LinuxProcessStat {
                parent_pid: 456,
                session_id: 333,
                start_time: 999,
            }),
            super::parse_linux_process_stat(stat)
        );
    }

    #[test]
    fn platform_resolver_hashes_current_process_scope() {
        assert!(
            super::resolve_authorization_scope_hash(std::process::id() as i32, unsafe {
                libc::geteuid()
            },)
            .is_some()
        );
    }

    #[test]
    fn display_uses_nearest_process_path() {
        let resolver = FakeResolver::default()
            .with_path(
                12,
                11,
                UID,
                SID,
                3,
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            )
            .with_path(11, 10, UID, SID, 2, "/usr/local/bin/monopass")
            .with_path(10, 1, UID, SID, 1, "/bin/bash")
            .with_uid_only(1, 0);

        let scope = super::resolve_authorization_scope_with_resolver(12, UID, &resolver).unwrap();
        let display = scope.display.unwrap();

        assert_eq!("Google Chrome", display.name);
        assert_eq!(
            PathBuf::from("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
            display.path
        );
        assert_eq!(
            Some(PathBuf::from("/Applications/Google Chrome.app")),
            display.icon_path
        );
        assert_eq!(Some(UNIX_EPOCH + Duration::from_secs(3)), display.modified);
    }

    #[test]
    fn display_filters_process_matching_agent_executable_identity() {
        let resolver = FakeResolver::default()
            .with_path(12, 11, UID, SID, 3, "/usr/local/bin/monopass")
            .with_path(
                11,
                10,
                UID,
                SID,
                2,
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            )
            .with_path(10, 1, UID, SID, 1, "/bin/bash")
            .with_uid_only(1, 0);
        let scope = super::resolve_authorization_scope_with_resolver(12, UID, &resolver).unwrap();
        let display = super::process_display_from_chain_with_agent(
            &chain(&resolver, &[10, 11, 12]),
            Some(test_executable(3)),
        )
        .unwrap();

        assert!(scope.display.is_some());
        assert_eq!("Google Chrome", display.name);
    }

    #[test]
    fn display_falls_back_to_plain_executable() {
        let resolver = FakeResolver::default()
            .with_path(12, 11, UID, SID, 3, "/usr/local/bin/example-tool")
            .with_uid_only(11, 0);

        let scope = super::resolve_authorization_scope_with_resolver(12, UID, &resolver).unwrap();
        let display = scope.display.unwrap();

        assert_eq!("example-tool", display.name);
        assert_eq!(PathBuf::from("/usr/local/bin/example-tool"), display.path);
        assert_eq!(None, display.icon_path);
    }

    fn process(
        pid: i32,
        parent_pid: i32,
        uid: u32,
        session_id: i32,
        executable: Option<u64>,
    ) -> ProcessInfo {
        ProcessInfo {
            instance: ProcessInstanceIdentity {
                pid,
                start_time: ProcessStartTime {
                    primary: pid as u64 * 10,
                    secondary: 0,
                },
            },
            parent_pid,
            uid,
            session_id,
            executable: executable.map(test_executable),
            executable_path: executable.map(|inode| PathBuf::from(format!("/bin/test-{inode}"))),
            executable_modified: executable.map(|inode| UNIX_EPOCH + Duration::from_secs(inode)),
        }
    }

    fn chain(resolver: &FakeResolver, pids: &[i32]) -> Vec<ProcessInfo> {
        pids.iter()
            .map(|pid| resolver.process_info(*pid).unwrap())
            .collect()
    }

    fn test_executable(inode: u64) -> ExecutableIdentity {
        ExecutableIdentity {
            device: 1,
            inode,
            generation: Some(1),
            size: 100,
            modified_seconds: 1,
            modified_nanoseconds: 2,
            changed_seconds: 3,
            changed_nanoseconds: 4,
        }
    }
}
