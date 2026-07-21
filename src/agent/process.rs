use std::fs::Metadata;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

const MAX_PROCESS_CHAIN_DEPTH: usize = 256;
#[cfg(target_os = "macos")]
const MACOS_NODEV: u32 = u32::MAX;

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
    executable: Option<ExecutableIdentity>,
    executable_path: Option<PathBuf>,
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
    anchor: ProcessInstanceIdentity,
    chain: Vec<StableProcessIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedAuthorizationScope {
    pub(crate) hash: ScopeHash,
    pub(crate) display: Option<ProcessDisplay>,
    pub(crate) ultimate: UltimateProcess,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UltimateProcess {
    executable: Option<ExecutableIdentity>,
    executable_path: Option<PathBuf>,
}

impl UltimateProcess {
    #[cfg(test)]
    pub(crate) fn test(path: impl Into<PathBuf>) -> Self {
        Self {
            executable: Some(ExecutableIdentity {
                device: 1,
                inode: 1,
                generation: Some(1),
                size: 1,
                modified_seconds: 1,
                modified_nanoseconds: 1,
                changed_seconds: 1,
                changed_nanoseconds: 1,
            }),
            executable_path: Some(path.into()),
        }
    }

    #[cfg(test)]
    pub(crate) fn test_agent() -> Self {
        let path = std::env::current_exe().expect("test executable path must resolve");
        Self {
            executable: ExecutableIdentity::from_path(&path),
            executable_path: Some(path),
        }
    }
}

#[cfg(any(not(target_os = "macos"), test))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DirectUnlockCaller {
    Agent,
    Program(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProcessIconSource {
    Path(PathBuf),
    #[cfg_attr(
        not(all(target_os = "linux", any(feature = "gtk", feature = "qt"))),
        allow(dead_code)
    )]
    ThemeName(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GuiApplication {
    pub(crate) name: String,
    pub(crate) icon: Option<ProcessIconSource>,
    pub(crate) same_as_primary: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcessDisplay {
    pub(crate) name: String,
    pub(crate) path: PathBuf,
    pub(crate) icon: Option<ProcessIconSource>,
    pub(crate) gui_application: Option<GuiApplication>,
}

impl ProcessDisplay {
    #[cfg(any(
        test,
        target_os = "macos",
        all(target_os = "linux", any(feature = "gtk", feature = "qt"))
    ))]
    pub(crate) fn presentation_name(&self) -> String {
        match &self.gui_application {
            Some(application) if application.same_as_primary => application.name.clone(),
            Some(application) => format!("{} (via {})", self.name, application.name),
            None => self.name.clone(),
        }
    }

    #[cfg(any(
        test,
        target_os = "macos",
        all(target_os = "linux", any(feature = "gtk", feature = "qt"))
    ))]
    pub(crate) fn preferred_icon(&self) -> Option<&ProcessIconSource> {
        self.gui_application
            .as_ref()
            .and_then(|application| application.icon.as_ref())
            .or(self.icon.as_ref())
    }
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

    fn verified_parent_across_macos_login_boundary(
        &self,
        _child: &ProcessInfo,
        _parent_pid: i32,
        _peer_uid: u32,
    ) -> Option<ProcessInfo> {
        None
    }
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
    resolve_authorization_scope_with_resolver_and_gui(
        peer_pid,
        peer_uid,
        resolver,
        &PlatformGuiApplicationResolver,
        current_agent_executable_identity(),
    )
}

fn resolve_authorization_scope_with_resolver_and_gui(
    peer_pid: i32,
    peer_uid: u32,
    resolver: &impl ProcessResolver,
    gui_resolver: &impl GuiApplicationResolver,
    agent_executable: Option<ExecutableIdentity>,
) -> Option<ResolvedAuthorizationScope> {
    let mut current = resolver.process_info(peer_pid)?;
    if current.uid != peer_uid {
        return None;
    }

    let mut chain = Vec::new();
    let mut crossed_macos_login_boundary = false;
    let mut remaining_depth = MAX_PROCESS_CHAIN_DEPTH;

    loop {
        if remaining_depth == 0 {
            return None;
        }
        remaining_depth -= 1;

        if current.uid != peer_uid {
            break;
        }
        if chain
            .iter()
            .any(|element: &ProcessInfo| element.instance.pid == current.instance.pid)
        {
            return None;
        }

        let parent_pid = current.parent_pid;
        chain.push(current.clone());
        if parent_pid <= 0 {
            break;
        }
        if remaining_depth == 0 {
            return None;
        }

        let parent_uid = resolver.process_uid(parent_pid)?;
        if parent_uid != peer_uid {
            if !crossed_macos_login_boundary
                && let Some(parent) = resolver
                    .verified_parent_across_macos_login_boundary(&current, parent_pid, peer_uid)
            {
                crossed_macos_login_boundary = true;
                remaining_depth -= 1;
                current = parent;
                continue;
            }
            break;
        }

        let parent = resolver.process_info(parent_pid)?;
        if parent.uid != peer_uid {
            break;
        }
        current = parent;
    }

    if chain.is_empty() {
        return None;
    }

    chain.reverse();
    let anchor = chain.first()?.instance;
    let scope = AuthorizationScope {
        uid: peer_uid,
        anchor,
        chain: chain.iter().map(ProcessInfo::stable_identity).collect(),
    };

    let ultimate = ultimate_process_from_chain(&chain)?;
    let display =
        process_display_from_chain_with_agent_and_gui(&chain, agent_executable, gui_resolver);
    Some(ResolvedAuthorizationScope {
        hash: hash_authorization_scope(&scope),
        display,
        ultimate,
    })
}

fn ultimate_process_from_chain(chain: &[ProcessInfo]) -> Option<UltimateProcess> {
    let process = chain.last()?;
    Some(UltimateProcess {
        executable: process.executable,
        executable_path: process.executable_path.clone(),
    })
}

#[cfg(any(not(target_os = "macos"), test))]
pub(crate) fn direct_unlock_caller(ultimate: &UltimateProcess) -> Option<DirectUnlockCaller> {
    let agent_executable = std::env::current_exe()
        .ok()
        .and_then(|path| ExecutableIdentity::from_path(&path));
    direct_unlock_caller_with_agent(ultimate, agent_executable)
}

#[cfg(any(not(target_os = "macos"), test))]
fn direct_unlock_caller_with_agent(
    ultimate: &UltimateProcess,
    agent_executable: Option<ExecutableIdentity>,
) -> Option<DirectUnlockCaller> {
    let executable = ultimate.executable?;
    if agent_executable.is_some_and(|agent| agent == executable) {
        return Some(DirectUnlockCaller::Agent);
    }
    ultimate
        .executable_path
        .clone()
        .map(DirectUnlockCaller::Program)
}

fn current_agent_executable_identity() -> Option<ExecutableIdentity> {
    std::env::current_exe()
        .ok()
        .and_then(|path| ExecutableIdentity::from_path(&path))
}

#[cfg(test)]
fn process_display_from_chain_with_agent(
    chain: &[ProcessInfo],
    agent_executable: Option<ExecutableIdentity>,
) -> Option<ProcessDisplay> {
    process_display_from_chain_with_agent_and_gui(
        chain,
        agent_executable,
        &PlatformGuiApplicationResolver,
    )
}

fn process_display_from_chain_with_agent_and_gui(
    chain: &[ProcessInfo],
    agent_executable: Option<ExecutableIdentity>,
    gui_resolver: &impl GuiApplicationResolver,
) -> Option<ProcessDisplay> {
    let primary = chain
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
        })?;
    let mut display = process_display(primary)?;
    let resolve_gui_application = || {
        chain.iter().rev().find_map(|process| {
            let mut application = gui_resolver.gui_application(process)?;
            application.same_as_primary = process.instance == primary.instance
                || process
                    .executable
                    .is_some_and(|identity| primary.executable == Some(identity));
            Some(application)
        })
    };
    display.gui_application = resolve_gui_application();
    if display.gui_application.is_none() && gui_resolver.refresh_after_miss() {
        display.gui_application = resolve_gui_application();
    }
    Some(display)
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
        icon: bundle_path.map(ProcessIconSource::Path),
        gui_application: None,
    })
}

trait GuiApplicationResolver {
    fn gui_application(&self, process: &ProcessInfo) -> Option<GuiApplication>;

    fn refresh_after_miss(&self) -> bool {
        false
    }
}

struct PlatformGuiApplicationResolver;

#[cfg(target_os = "macos")]
impl GuiApplicationResolver for PlatformGuiApplicationResolver {
    fn gui_application(&self, process: &ProcessInfo) -> Option<GuiApplication> {
        use objc2_app_kit::{NSApplicationActivationPolicy, NSRunningApplication};

        let application =
            NSRunningApplication::runningApplicationWithProcessIdentifier(process.instance.pid)?;
        if !matches!(
            application.activationPolicy(),
            NSApplicationActivationPolicy::Regular | NSApplicationActivationPolicy::Accessory
        ) {
            return None;
        }
        let bundle_path = application.bundleURL()?.path()?.to_string();
        if bundle_path.is_empty() {
            return None;
        }
        let name = application.localizedName()?.to_string();
        if name.is_empty() {
            return None;
        }
        Some(GuiApplication {
            name,
            icon: Some(ProcessIconSource::Path(PathBuf::from(bundle_path))),
            same_as_primary: false,
        })
    }
}

#[cfg(all(target_os = "linux", any(feature = "gtk", feature = "qt")))]
impl GuiApplicationResolver for PlatformGuiApplicationResolver {
    fn gui_application(&self, process: &ProcessInfo) -> Option<GuiApplication> {
        let executable = process.executable_path.as_deref()?;
        super::desktop::application_for_process(process.instance.pid, executable)
    }

    fn refresh_after_miss(&self) -> bool {
        super::desktop::refresh_gui_application_catalog_after_miss()
    }
}

#[cfg(all(target_os = "linux", not(any(feature = "gtk", feature = "qt"))))]
impl GuiApplicationResolver for PlatformGuiApplicationResolver {
    fn gui_application(&self, _process: &ProcessInfo) -> Option<GuiApplication> {
        None
    }
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

#[cfg(any(target_os = "macos", test))]
#[derive(Debug, Clone, Copy)]
struct MacosCredentialBoundaryEvidence {
    boundary_pid: i32,
    boundary_process_group: i32,
    effective_uid: u32,
    real_uid: u32,
    saved_uid: u32,
    parent_uid: Option<u32>,
    command_is_login: bool,
    child_session_id: Option<i32>,
    child_has_controlling_terminal: bool,
}

#[cfg(any(target_os = "macos", test))]
fn crosses_macos_login_boundary(peer_uid: u32, evidence: MacosCredentialBoundaryEvidence) -> bool {
    evidence.boundary_pid > 0
        && evidence.boundary_process_group == evidence.boundary_pid
        && evidence.effective_uid == 0
        && evidence.real_uid == peer_uid
        && evidence.saved_uid == 0
        && evidence.parent_uid == Some(peer_uid)
        && evidence.command_is_login
        && evidence.child_session_id == Some(evidence.boundary_pid)
        && evidence.child_has_controlling_terminal
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
            executable: executable_metadata.as_ref().map(executable_identity),
            executable_path,
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
    fields.next()?; // Session ID is intentionally excluded from authorization.
    for _ in 7..=21 {
        fields.next()?;
    }
    let start_time = fields.next()?.parse().ok()?;

    Some(LinuxProcessStat {
        parent_pid,
        start_time,
    })
}

#[cfg(target_os = "macos")]
impl ProcessResolver for PlatformProcessResolver {
    fn process_info(&self, pid: i32) -> Option<ProcessInfo> {
        let info = macos_bsd_info(pid)?;

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
            executable: executable_metadata.as_ref().map(executable_identity),
            executable_path,
        })
    }

    fn process_uid(&self, pid: i32) -> Option<u32> {
        macos_bsd_info(pid)
            .map(|info| info.pbi_uid)
            .or_else(|| macos_short_bsd_info(pid).map(|info| info.pbsi_uid))
    }

    fn verified_parent_across_macos_login_boundary(
        &self,
        child: &ProcessInfo,
        parent_pid: i32,
        peer_uid: u32,
    ) -> Option<ProcessInfo> {
        let child_info = macos_bsd_info(child.instance.pid)?;
        if child_info.pbi_uid != peer_uid
            || i32::try_from(child_info.pbi_ppid).ok()? != parent_pid
            || child_info.pbi_start_tvsec != child.instance.start_time.primary
            || child_info.pbi_start_tvusec != child.instance.start_time.secondary
        {
            return None;
        }

        let boundary_info = macos_short_bsd_info(parent_pid)?;
        if i32::try_from(boundary_info.pbsi_pid).ok()? != parent_pid {
            return None;
        }
        let boundary_parent_pid = i32::try_from(boundary_info.pbsi_ppid).ok()?;
        if boundary_parent_pid <= 0 {
            return None;
        }

        let evidence = MacosCredentialBoundaryEvidence {
            boundary_pid: i32::try_from(boundary_info.pbsi_pid).ok()?,
            boundary_process_group: i32::try_from(boundary_info.pbsi_pgid).ok()?,
            effective_uid: boundary_info.pbsi_uid,
            real_uid: boundary_info.pbsi_ruid,
            saved_uid: boundary_info.pbsi_svuid,
            parent_uid: self.process_uid(boundary_parent_pid),
            command_is_login: macos_short_process_name_is(&boundary_info, b"login"),
            child_session_id: macos_session_id(child.instance.pid),
            child_has_controlling_terminal: child_info.e_tdev != MACOS_NODEV,
        };
        if !crosses_macos_login_boundary(peer_uid, evidence) {
            return None;
        }

        let parent = self.process_info(boundary_parent_pid)?;
        if parent.uid != peer_uid {
            return None;
        }

        let revalidated_boundary = macos_short_bsd_info(parent_pid)?;
        if !same_macos_short_process(&boundary_info, &revalidated_boundary) {
            return None;
        }
        let revalidated_child = macos_bsd_info(child.instance.pid)?;
        if !same_macos_process(&child_info, &revalidated_child) {
            return None;
        }
        Some(parent)
    }
}

#[cfg(target_os = "macos")]
fn macos_short_process_name_is(info: &ProcBsdShortInfo, expected: &[u8]) -> bool {
    info.pbsi_comm
        .iter()
        .map(|byte| *byte as u8)
        .take_while(|byte| *byte != 0)
        .eq(expected.iter().copied())
}

#[cfg(target_os = "macos")]
fn macos_session_id(pid: i32) -> Option<i32> {
    let session_id = unsafe { libc::getsid(pid) };
    (session_id >= 0).then_some(session_id)
}

#[cfg(target_os = "macos")]
fn same_macos_process(first: &libc::proc_bsdinfo, second: &libc::proc_bsdinfo) -> bool {
    first.pbi_pid == second.pbi_pid
        && first.pbi_ppid == second.pbi_ppid
        && first.pbi_uid == second.pbi_uid
        && first.pbi_ruid == second.pbi_ruid
        && first.pbi_svuid == second.pbi_svuid
        && first.pbi_start_tvsec == second.pbi_start_tvsec
        && first.pbi_start_tvusec == second.pbi_start_tvusec
        && first.e_tdev == second.e_tdev
}

#[cfg(target_os = "macos")]
fn same_macos_short_process(first: &ProcBsdShortInfo, second: &ProcBsdShortInfo) -> bool {
    first.pbsi_pid == second.pbsi_pid
        && first.pbsi_ppid == second.pbsi_ppid
        && first.pbsi_pgid == second.pbsi_pgid
        && first.pbsi_flags == second.pbsi_flags
        && first.pbsi_uid == second.pbsi_uid
        && first.pbsi_gid == second.pbsi_gid
        && first.pbsi_ruid == second.pbsi_ruid
        && first.pbsi_rgid == second.pbsi_rgid
        && first.pbsi_svuid == second.pbsi_svuid
        && first.pbsi_svgid == second.pbsi_svgid
        && first.pbsi_comm == second.pbsi_comm
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
#[derive(Debug, Clone, Copy)]
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
    use std::cell::Cell;
    use std::collections::HashMap;
    use std::path::PathBuf;

    use super::{
        ExecutableIdentity, ProcessInfo, ProcessInstanceIdentity, ProcessResolver, ProcessStartTime,
    };

    const UID: u32 = 501;
    #[derive(Default)]
    struct FakeResolver {
        processes: HashMap<i32, ProcessInfo>,
        visible_uids: HashMap<i32, u32>,
        verified_macos_login_bridges: HashMap<(i32, i32), i32>,
    }

    impl FakeResolver {
        fn with(mut self, pid: i32, parent: i32, uid: u32, exe: u64) -> Self {
            let process = process(pid, parent, uid, Some(exe));
            self.visible_uids.insert(pid, uid);
            self.processes.insert(pid, process);
            self
        }

        fn with_path(mut self, pid: i32, parent: i32, uid: u32, exe: u64, path: &str) -> Self {
            let mut process = process(pid, parent, uid, Some(exe));
            process.executable_path = Some(PathBuf::from(path));
            self.visible_uids.insert(pid, uid);
            self.processes.insert(pid, process);
            self
        }

        fn with_missing_executable(mut self, pid: i32, parent: i32, uid: u32) -> Self {
            let process = process(pid, parent, uid, None);
            self.visible_uids.insert(pid, uid);
            self.processes.insert(pid, process);
            self
        }

        fn with_uid_only(mut self, pid: i32, uid: u32) -> Self {
            self.visible_uids.insert(pid, uid);
            self
        }

        fn with_verified_macos_login_bridge(
            mut self,
            child_pid: i32,
            bridge_pid: i32,
            parent_pid: i32,
        ) -> Self {
            self.verified_macos_login_bridges
                .insert((child_pid, bridge_pid), parent_pid);
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

        fn verified_parent_across_macos_login_boundary(
            &self,
            child: &ProcessInfo,
            parent_pid: i32,
            peer_uid: u32,
        ) -> Option<ProcessInfo> {
            let verified_parent_pid = self
                .verified_macos_login_bridges
                .get(&(child.instance.pid, parent_pid))?;
            let parent = self.process_info(*verified_parent_pid)?;
            (parent.uid == peer_uid).then_some(parent)
        }
    }

    #[test]
    fn transient_process_pids_are_ignored_when_executables_match() {
        let first = FakeResolver::default()
            .with(12, 11, UID, 3)
            .with(11, 10, UID, 2)
            .with(10, 9, UID, 1)
            .with(9, 1, UID, 9)
            .with(1, 0, 0, 8);
        let second = FakeResolver::default()
            .with(22, 21, UID, 3)
            .with(21, 20, UID, 2)
            .with(20, 9, UID, 1)
            .with(9, 1, UID, 9)
            .with(1, 0, 0, 8);

        let first = super::resolve_authorization_scope_hash_with_resolver(12, UID, &first);
        let second = super::resolve_authorization_scope_hash_with_resolver(22, UID, &second);

        assert_eq!(first, second);
    }

    #[test]
    fn direct_client_executable_is_included() {
        let first = FakeResolver::default()
            .with(10, 9, UID, 1)
            .with(9, 1, UID, 9)
            .with_uid_only(1, 0);
        let second = FakeResolver::default()
            .with(11, 9, UID, 2)
            .with(9, 1, UID, 9)
            .with_uid_only(1, 0);

        assert_ne!(
            super::resolve_authorization_scope_hash_with_resolver(10, UID, &first),
            super::resolve_authorization_scope_hash_with_resolver(11, UID, &second)
        );
    }

    #[test]
    fn different_anchor_instances_are_distinct() {
        let first = FakeResolver::default()
            .with(10, 9, UID, 1)
            .with(9, 1, UID, 9)
            .with_uid_only(1, 0);
        let second = FakeResolver::default()
            .with(10, 8, UID, 1)
            .with(8, 1, UID, 9)
            .with_uid_only(1, 0);

        assert_ne!(
            super::resolve_authorization_scope_hash_with_resolver(10, UID, &first),
            super::resolve_authorization_scope_hash_with_resolver(10, UID, &second)
        );
    }

    #[test]
    fn sibling_terminal_processes_with_common_ancestry_share_scope() {
        let first = FakeResolver::default()
            .with(12, 11, UID, 3)
            .with(11, 9, UID, 2)
            .with(9, 1, UID, 1)
            .with_uid_only(1, 0);
        let second = FakeResolver::default()
            .with(22, 21, UID, 3)
            .with(21, 9, UID, 2)
            .with(9, 1, UID, 1)
            .with_uid_only(1, 0);

        assert_eq!(
            super::resolve_authorization_scope_hash_with_resolver(12, UID, &first),
            super::resolve_authorization_scope_hash_with_resolver(22, UID, &second)
        );
    }

    #[test]
    fn missing_executable_falls_back_to_process_instance() {
        let first = FakeResolver::default()
            .with_missing_executable(10, 9, UID)
            .with(9, 1, UID, 9)
            .with_uid_only(1, 0);
        let second = FakeResolver::default()
            .with_missing_executable(11, 9, UID)
            .with(9, 1, UID, 9)
            .with_uid_only(1, 0);

        assert_ne!(
            super::resolve_authorization_scope_hash_with_resolver(10, UID, &first),
            super::resolve_authorization_scope_hash_with_resolver(11, UID, &second)
        );
    }

    #[test]
    fn changed_executable_metadata_changes_scope() {
        let first = FakeResolver::default()
            .with(10, 9, UID, 1)
            .with(9, 1, UID, 9)
            .with_uid_only(1, 0);
        let second = FakeResolver::default()
            .with(10, 9, UID, 2)
            .with(9, 1, UID, 9)
            .with_uid_only(1, 0);

        assert_ne!(
            super::resolve_authorization_scope_hash_with_resolver(10, UID, &first),
            super::resolve_authorization_scope_hash_with_resolver(10, UID, &second)
        );
    }

    #[test]
    fn different_user_parent_is_a_successful_boundary() {
        let resolver = FakeResolver::default()
            .with(10, 9, UID, 1)
            .with(9, 1, UID, 9)
            .with_uid_only(1, 0);

        assert!(
            super::resolve_authorization_scope_hash_with_resolver(10, UID, &resolver).is_some()
        );
    }

    #[test]
    fn same_user_gui_ancestry_affects_authorization_and_presentation() {
        let first = FakeResolver::default()
            .with_path(12, 11, UID, 4, "/usr/local/bin/monopass")
            .with_path(11, 10, UID, 3, "/bin/bash")
            .with_path(10, 9, UID, 2, "/Applications/Helper")
            .with_path(
                9,
                1,
                UID,
                1,
                "/Applications/Visual Studio Code.app/Contents/MacOS/Code",
            )
            .with_uid_only(1, 0);
        let second = FakeResolver::default()
            .with_path(12, 11, UID, 4, "/usr/local/bin/monopass")
            .with_path(11, 10, UID, 3, "/bin/bash")
            .with_path(10, 9, UID, 22, "/Applications/Other Helper")
            .with_path(
                9,
                1,
                UID,
                11,
                "/Applications/Other.app/Contents/MacOS/Other",
            )
            .with_uid_only(1, 0);
        let gui = FakeGuiResolver::default().with(9, "Visual Studio Code");

        let scope = super::resolve_authorization_scope_with_resolver_and_gui(
            12,
            UID,
            &first,
            &gui,
            Some(test_executable(4)),
        )
        .unwrap();

        assert_eq!(
            "bash (via Visual Studio Code)",
            scope.display.unwrap().presentation_name()
        );
        assert_ne!(
            super::resolve_authorization_scope_hash_with_resolver(12, UID, &first),
            super::resolve_authorization_scope_hash_with_resolver(12, UID, &second)
        );
    }

    #[test]
    fn verified_macos_login_boundary_shares_iterm_scope_across_tabs() {
        let first = FakeResolver::default()
            .with_path(12, 11, UID, 4, "/usr/local/bin/monopass")
            .with_path(11, 10, UID, 3, "/bin/bash")
            .with_uid_only(10, 0)
            .with_path(9, 8, UID, 2, "/Applications/iTermServer")
            .with_path(
                8,
                1,
                UID,
                1,
                "/Applications/iTerm.app/Contents/MacOS/iTerm2",
            )
            .with_uid_only(1, 0)
            .with_verified_macos_login_bridge(11, 10, 9);
        let second = FakeResolver::default()
            .with_path(22, 21, UID, 4, "/usr/local/bin/monopass")
            .with_path(21, 20, UID, 3, "/bin/bash")
            .with_uid_only(20, 0)
            .with_path(9, 8, UID, 2, "/Applications/iTermServer")
            .with_path(
                8,
                1,
                UID,
                1,
                "/Applications/iTerm.app/Contents/MacOS/iTerm2",
            )
            .with_uid_only(1, 0)
            .with_verified_macos_login_bridge(21, 20, 9);
        let gui = FakeGuiResolver::default().with(8, "iTerm2");

        let scope = super::resolve_authorization_scope_with_resolver_and_gui(
            12,
            UID,
            &first,
            &gui,
            Some(test_executable(4)),
        )
        .unwrap();

        assert_eq!(
            "bash (via iTerm2)",
            scope.display.unwrap().presentation_name()
        );
        assert_eq!(
            Some(PathBuf::from("/usr/local/bin/monopass")),
            scope.ultimate.executable_path
        );
        assert_eq!(
            super::resolve_authorization_scope_hash_with_resolver(12, UID, &first),
            super::resolve_authorization_scope_hash_with_resolver(22, UID, &second)
        );
    }

    #[test]
    fn verified_macos_login_boundary_shares_terminal_scope_across_windows() {
        let first = FakeResolver::default()
            .with_path(12, 11, UID, 4, "/usr/local/bin/monopass")
            .with_path(11, 10, UID, 3, "/bin/bash")
            .with_uid_only(10, 0)
            .with_path(
                9,
                1,
                UID,
                2,
                "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
            )
            .with_uid_only(1, 0)
            .with_verified_macos_login_bridge(11, 10, 9);
        let second = FakeResolver::default()
            .with_path(22, 21, UID, 4, "/usr/local/bin/monopass")
            .with_path(21, 20, UID, 3, "/bin/bash")
            .with_uid_only(20, 0)
            .with_path(
                9,
                1,
                UID,
                2,
                "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
            )
            .with_uid_only(1, 0)
            .with_verified_macos_login_bridge(21, 20, 9);
        let gui = FakeGuiResolver::default().with(9, "Terminal");

        let scope = super::resolve_authorization_scope_with_resolver_and_gui(
            12,
            UID,
            &first,
            &gui,
            Some(test_executable(4)),
        )
        .unwrap();
        let display = scope.display.unwrap();

        assert_eq!("bash (via Terminal)", display.presentation_name());
        assert_eq!(PathBuf::from("/bin/bash"), display.path);
        assert_eq!(
            super::resolve_authorization_scope_hash_with_resolver(12, UID, &first),
            super::resolve_authorization_scope_hash_with_resolver(22, UID, &second)
        );
    }

    #[test]
    fn different_terminal_hosts_and_shells_have_distinct_scopes() {
        let bash = FakeResolver::default()
            .with_path(12, 11, UID, 4, "/usr/local/bin/monopass")
            .with_path(11, 10, UID, 3, "/bin/bash")
            .with_uid_only(10, 0)
            .with_path(9, 1, UID, 2, "/Applications/Terminal")
            .with_uid_only(1, 0)
            .with_verified_macos_login_bridge(11, 10, 9);
        let zsh = FakeResolver::default()
            .with_path(22, 21, UID, 4, "/usr/local/bin/monopass")
            .with_path(21, 20, UID, 5, "/bin/zsh")
            .with_uid_only(20, 0)
            .with_path(9, 1, UID, 2, "/Applications/Terminal")
            .with_uid_only(1, 0)
            .with_verified_macos_login_bridge(21, 20, 9);
        let other_host = FakeResolver::default()
            .with_path(32, 31, UID, 4, "/usr/local/bin/monopass")
            .with_path(31, 30, UID, 3, "/bin/bash")
            .with_uid_only(30, 0)
            .with_path(29, 1, UID, 2, "/Applications/Terminal")
            .with_uid_only(1, 0)
            .with_verified_macos_login_bridge(31, 30, 29);
        let other_emulator = FakeResolver::default()
            .with_path(42, 41, UID, 4, "/usr/local/bin/monopass")
            .with_path(41, 40, UID, 3, "/bin/bash")
            .with_uid_only(40, 0)
            .with_path(9, 1, UID, 6, "/Applications/iTerm2")
            .with_uid_only(1, 0)
            .with_verified_macos_login_bridge(41, 40, 9);

        let bash_hash = super::resolve_authorization_scope_hash_with_resolver(12, UID, &bash);
        assert_ne!(
            bash_hash,
            super::resolve_authorization_scope_hash_with_resolver(22, UID, &zsh)
        );
        assert_ne!(
            bash_hash,
            super::resolve_authorization_scope_hash_with_resolver(32, UID, &other_host)
        );
        assert_ne!(
            bash_hash,
            super::resolve_authorization_scope_hash_with_resolver(42, UID, &other_emulator)
        );
    }

    #[test]
    fn only_one_macos_login_boundary_is_crossed() {
        let single_bridge = FakeResolver::default()
            .with_path(12, 11, UID, 4, "/usr/local/bin/monopass")
            .with_path(11, 10, UID, 3, "/bin/bash")
            .with_uid_only(10, 0)
            .with_path(9, 8, UID, 2, "/Applications/TerminalHelper")
            .with_uid_only(8, 0)
            .with_path(7, 1, UID, 1, "/Applications/Terminal")
            .with_uid_only(1, 0)
            .with_verified_macos_login_bridge(11, 10, 9);
        let two_bridges = FakeResolver::default()
            .with_path(12, 11, UID, 4, "/usr/local/bin/monopass")
            .with_path(11, 10, UID, 3, "/bin/bash")
            .with_uid_only(10, 0)
            .with_path(9, 8, UID, 2, "/Applications/TerminalHelper")
            .with_uid_only(8, 0)
            .with_path(7, 1, UID, 1, "/Applications/Terminal")
            .with_uid_only(1, 0)
            .with_verified_macos_login_bridge(11, 10, 9)
            .with_verified_macos_login_bridge(9, 8, 7);

        assert_eq!(
            super::resolve_authorization_scope_hash_with_resolver(12, UID, &single_bridge),
            super::resolve_authorization_scope_hash_with_resolver(12, UID, &two_bridges)
        );
    }

    #[test]
    fn macos_login_boundary_counts_toward_traversal_limit() {
        let mut resolver = FakeResolver::default();
        for pid in 3..=257 {
            resolver = resolver.with(pid, pid - 1, UID, pid as u64);
        }
        resolver = resolver
            .with_uid_only(2, 0)
            .with(1, 0, UID, 1)
            .with_verified_macos_login_bridge(3, 2, 1);

        assert!(
            super::resolve_authorization_scope_hash_with_resolver(257, UID, &resolver).is_none()
        );
    }

    #[test]
    fn unrecognized_privileged_boundary_preserves_plain_display() {
        let resolver = FakeResolver::default()
            .with_path(12, 11, UID, 4, "/usr/local/bin/monopass")
            .with_path(11, 10, UID, 3, "/bin/bash")
            .with_uid_only(10, 0);
        let gui = FakeGuiResolver::default().with(10, "Untrusted");

        let scope = super::resolve_authorization_scope_with_resolver_and_gui(
            12,
            UID,
            &resolver,
            &gui,
            Some(test_executable(4)),
        )
        .unwrap();

        assert_eq!("bash", scope.display.unwrap().presentation_name());
    }

    #[test]
    fn macos_login_boundary_requires_complete_terminal_evidence() {
        let valid = super::MacosCredentialBoundaryEvidence {
            boundary_pid: 10,
            boundary_process_group: 10,
            effective_uid: 0,
            real_uid: UID,
            saved_uid: 0,
            parent_uid: Some(UID),
            command_is_login: true,
            child_session_id: Some(10),
            child_has_controlling_terminal: true,
        };

        assert!(super::crosses_macos_login_boundary(UID, valid));

        for invalid in [
            super::MacosCredentialBoundaryEvidence {
                boundary_pid: 0,
                boundary_process_group: 0,
                child_session_id: Some(0),
                ..valid
            },
            super::MacosCredentialBoundaryEvidence {
                boundary_process_group: 11,
                ..valid
            },
            super::MacosCredentialBoundaryEvidence {
                effective_uid: UID,
                ..valid
            },
            super::MacosCredentialBoundaryEvidence {
                real_uid: 0,
                ..valid
            },
            super::MacosCredentialBoundaryEvidence {
                saved_uid: UID,
                ..valid
            },
            super::MacosCredentialBoundaryEvidence {
                parent_uid: Some(0),
                ..valid
            },
            super::MacosCredentialBoundaryEvidence {
                parent_uid: None,
                ..valid
            },
            super::MacosCredentialBoundaryEvidence {
                command_is_login: false,
                ..valid
            },
            super::MacosCredentialBoundaryEvidence {
                child_session_id: Some(11),
                ..valid
            },
            super::MacosCredentialBoundaryEvidence {
                child_session_id: None,
                ..valid
            },
            super::MacosCredentialBoundaryEvidence {
                child_has_controlling_terminal: false,
                ..valid
            },
        ] {
            assert!(!super::crosses_macos_login_boundary(UID, invalid));
        }
    }

    #[test]
    fn inaccessible_same_user_parent_is_rejected() {
        let resolver = FakeResolver::default()
            .with(10, 9, UID, 1)
            .with_uid_only(9, UID);

        assert!(
            super::resolve_authorization_scope_hash_with_resolver(10, UID, &resolver).is_none()
        );
    }

    #[test]
    fn missing_parent_uid_is_rejected() {
        let resolver = FakeResolver::default().with(10, 9, UID, 1);

        assert!(
            super::resolve_authorization_scope_hash_with_resolver(10, UID, &resolver).is_none()
        );
    }

    #[test]
    fn parent_loop_is_rejected() {
        let resolver = FakeResolver::default()
            .with(10, 9, UID, 1)
            .with(9, 10, UID, 9);

        assert!(
            super::resolve_authorization_scope_hash_with_resolver(10, UID, &resolver).is_none()
        );
    }

    #[test]
    fn chain_deeper_than_traversal_limit_is_rejected() {
        let mut resolver = FakeResolver::default();
        for pid in 1..=257 {
            resolver = resolver.with(pid, pid - 1, UID, pid as u64);
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
                3,
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            )
            .with_path(11, 10, UID, 2, "/usr/local/bin/monopass")
            .with_path(10, 1, UID, 1, "/bin/bash")
            .with_uid_only(1, 0);

        let scope = super::resolve_authorization_scope_with_resolver(12, UID, &resolver).unwrap();
        let display = scope.display.unwrap();

        assert_eq!("Google Chrome", display.name);
        assert_eq!(
            PathBuf::from("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
            display.path
        );
        assert_eq!(
            Some(super::ProcessIconSource::Path(PathBuf::from(
                "/Applications/Google Chrome.app"
            ))),
            display.icon
        );
    }

    #[test]
    fn display_filters_process_matching_agent_executable_identity() {
        let resolver = FakeResolver::default()
            .with_path(12, 11, UID, 3, "/usr/local/bin/monopass")
            .with_path(
                11,
                10,
                UID,
                2,
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            )
            .with_path(10, 1, UID, 1, "/bin/bash")
            .with_uid_only(1, 0);
        let scope = super::resolve_authorization_scope_with_resolver(12, UID, &resolver).unwrap();
        let display = super::process_display_from_chain_with_agent(
            &chain(&resolver, &[10, 11, 12]),
            Some(test_executable(3)),
        )
        .unwrap();

        assert!(scope.display.is_some());
        assert_eq!("Google Chrome", display.name);
        assert_eq!(
            Some(PathBuf::from("/usr/local/bin/monopass")),
            scope.ultimate.executable_path
        );
        assert_eq!(Some(test_executable(3)), scope.ultimate.executable);
    }

    #[test]
    fn shell_display_is_attributed_to_nearest_gui_application() {
        let resolver = FakeResolver::default()
            .with_path(12, 11, UID, 4, "/usr/local/bin/monopass")
            .with_path(11, 10, UID, 3, "/bin/bash")
            .with_path(10, 1, UID, 2, "/usr/bin/gnome-terminal-server")
            .with_uid_only(1, 0);
        let gui = FakeGuiResolver::default().with(10, "Terminal");

        let display = super::process_display_from_chain_with_agent_and_gui(
            &chain(&resolver, &[10, 11, 12]),
            Some(test_executable(4)),
            &gui,
        )
        .unwrap();

        assert_eq!("bash (via Terminal)", display.presentation_name());
        assert_eq!(PathBuf::from("/bin/bash"), display.path);
        assert_eq!(
            Some(&super::ProcessIconSource::ThemeName("test-icon".into())),
            display.preferred_icon()
        );
    }

    #[test]
    fn missing_gui_metadata_is_retried_after_catalog_refresh() {
        let resolver = FakeResolver::default()
            .with_path(12, 11, UID, 4, "/usr/local/bin/monopass")
            .with_path(11, 10, UID, 3, "/bin/bash")
            .with_path(10, 1, UID, 2, "/usr/bin/lxterminal")
            .with_uid_only(1, 0);
        let gui = RefreshingFakeGuiResolver {
            application_pid: 10,
            refreshed: Cell::new(false),
            refreshes: Cell::new(0),
        };

        let display = super::process_display_from_chain_with_agent_and_gui(
            &chain(&resolver, &[10, 11, 12]),
            Some(test_executable(4)),
            &gui,
        )
        .unwrap();

        assert_eq!("bash (via LXTerminal)", display.presentation_name());
        assert_eq!(1, gui.refreshes.get());
    }

    #[test]
    fn nested_gui_ancestors_choose_nearest_application() {
        let resolver = FakeResolver::default()
            .with_path(12, 11, UID, 4, "/usr/local/bin/monopass")
            .with_path(11, 10, UID, 3, "/bin/bash")
            .with_path(10, 9, UID, 2, "/usr/bin/inner-terminal")
            .with_path(9, 1, UID, 1, "/usr/bin/outer-terminal")
            .with_uid_only(1, 0);
        let gui = FakeGuiResolver::default()
            .with(9, "Outer")
            .with(10, "Inner");

        let display = super::process_display_from_chain_with_agent_and_gui(
            &chain(&resolver, &[9, 10, 11, 12]),
            Some(test_executable(4)),
            &gui,
        )
        .unwrap();

        assert_eq!("bash (via Inner)", display.presentation_name());
    }

    #[test]
    fn direct_gui_caller_uses_localized_name_without_via() {
        let resolver = FakeResolver::default()
            .with_path(12, 11, UID, 3, "/usr/local/bin/monopass")
            .with_path(11, 1, UID, 2, "/usr/bin/code")
            .with_uid_only(1, 0);
        let gui = FakeGuiResolver::default().with(11, "Visual Studio Code");

        let display = super::process_display_from_chain_with_agent_and_gui(
            &chain(&resolver, &[11, 12]),
            Some(test_executable(3)),
            &gui,
        )
        .unwrap();

        assert_eq!("Visual Studio Code", display.presentation_name());
        assert!(display.gui_application.unwrap().same_as_primary);
    }

    #[test]
    fn missing_gui_metadata_preserves_plain_display() {
        let resolver = FakeResolver::default()
            .with_path(12, 11, UID, 3, "/usr/local/bin/monopass")
            .with_path(11, 1, UID, 2, "/bin/bash")
            .with_uid_only(1, 0);

        let display = super::process_display_from_chain_with_agent_and_gui(
            &chain(&resolver, &[11, 12]),
            Some(test_executable(3)),
            &FakeGuiResolver::default(),
        )
        .unwrap();

        assert_eq!("bash", display.presentation_name());
        assert!(display.gui_application.is_none());
    }

    #[test]
    fn direct_unlock_caller_uses_ultimate_executable_identity() {
        let agent = test_executable(3);
        let agent_ultimate = super::UltimateProcess {
            executable: Some(agent),
            executable_path: Some(PathBuf::from("/usr/local/bin/monopass")),
        };
        assert_eq!(
            Some(super::DirectUnlockCaller::Agent),
            super::direct_unlock_caller_with_agent(&agent_ultimate, Some(agent))
        );

        let external = super::UltimateProcess {
            executable: Some(test_executable(4)),
            executable_path: Some(PathBuf::from("/usr/local/bin/external")),
        };
        assert_eq!(
            Some(super::DirectUnlockCaller::Program(PathBuf::from(
                "/usr/local/bin/external"
            ))),
            super::direct_unlock_caller_with_agent(&external, Some(agent))
        );
    }

    #[test]
    fn direct_unlock_caller_requires_ultimate_identity_and_non_agent_path() {
        let missing_identity = super::UltimateProcess {
            executable: None,
            executable_path: Some(PathBuf::from("/usr/local/bin/external")),
        };
        assert_eq!(
            None,
            super::direct_unlock_caller_with_agent(&missing_identity, Some(test_executable(3)))
        );

        let missing_path = super::UltimateProcess {
            executable: Some(test_executable(4)),
            executable_path: None,
        };
        assert_eq!(
            None,
            super::direct_unlock_caller_with_agent(&missing_path, Some(test_executable(3)))
        );
    }

    #[test]
    fn display_falls_back_to_plain_executable() {
        let resolver = FakeResolver::default()
            .with_path(12, 11, UID, 3, "/usr/local/bin/example-tool")
            .with_uid_only(11, 0);

        let scope = super::resolve_authorization_scope_with_resolver(12, UID, &resolver).unwrap();
        let display = scope.display.unwrap();

        assert_eq!("example-tool", display.name);
        assert_eq!(PathBuf::from("/usr/local/bin/example-tool"), display.path);
        assert_eq!(None, display.icon);
    }

    fn process(pid: i32, parent_pid: i32, uid: u32, executable: Option<u64>) -> ProcessInfo {
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
            executable: executable.map(test_executable),
            executable_path: executable.map(|inode| PathBuf::from(format!("/bin/test-{inode}"))),
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

    #[derive(Default)]
    struct FakeGuiResolver {
        applications: HashMap<i32, super::GuiApplication>,
    }

    impl FakeGuiResolver {
        fn with(mut self, pid: i32, name: &str) -> Self {
            self.applications.insert(
                pid,
                super::GuiApplication {
                    name: name.to_owned(),
                    icon: Some(super::ProcessIconSource::ThemeName("test-icon".into())),
                    same_as_primary: false,
                },
            );
            self
        }
    }

    impl super::GuiApplicationResolver for FakeGuiResolver {
        fn gui_application(&self, process: &ProcessInfo) -> Option<super::GuiApplication> {
            self.applications.get(&process.instance.pid).cloned()
        }
    }

    struct RefreshingFakeGuiResolver {
        application_pid: i32,
        refreshed: Cell<bool>,
        refreshes: Cell<usize>,
    }

    impl super::GuiApplicationResolver for RefreshingFakeGuiResolver {
        fn gui_application(&self, process: &ProcessInfo) -> Option<super::GuiApplication> {
            (self.refreshed.get() && process.instance.pid == self.application_pid).then(|| {
                super::GuiApplication {
                    name: "LXTerminal".to_owned(),
                    icon: Some(super::ProcessIconSource::ThemeName("lxterminal".into())),
                    same_as_primary: false,
                }
            })
        }

        fn refresh_after_miss(&self) -> bool {
            self.refreshed.set(true);
            self.refreshes.set(self.refreshes.get() + 1);
            true
        }
    }
}
