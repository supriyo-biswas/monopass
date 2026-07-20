#![cfg_attr(test, allow(dead_code))]

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

use freedesktop_desktop_entry::{DesktopEntry, Iter, get_languages_from_env};

use super::process::{GuiApplication, ProcessIconSource};

const MISS_REFRESH_COOLDOWN: Duration = Duration::from_secs(5);

static CATALOG: OnceLock<DesktopCatalogCache> = OnceLock::new();

pub(crate) fn initialize_gui_application_catalog() {
    let _ = CATALOG.set(DesktopCatalogCache::new(DesktopCatalog::load()));
}

pub(crate) fn application_for_process(pid: i32, executable: &Path) -> Option<GuiApplication> {
    CATALOG
        .get_or_init(|| DesktopCatalogCache::new(DesktopCatalog::load()))
        .application_for_process(pid, executable)
}

pub(crate) fn refresh_gui_application_catalog_after_miss() -> bool {
    CATALOG
        .get_or_init(|| DesktopCatalogCache::new(DesktopCatalog::load()))
        .refresh_after_miss(Instant::now(), DesktopCatalog::load)
}

#[derive(Debug, Default)]
struct CatalogRefreshState {
    last_miss_refresh: Option<Instant>,
}

#[derive(Debug)]
struct DesktopCatalogCache {
    catalog: RwLock<DesktopCatalog>,
    refresh: Mutex<CatalogRefreshState>,
}

impl DesktopCatalogCache {
    fn new(catalog: DesktopCatalog) -> Self {
        Self {
            catalog: RwLock::new(catalog),
            refresh: Mutex::new(CatalogRefreshState::default()),
        }
    }

    fn application_for_process(&self, pid: i32, executable: &Path) -> Option<GuiApplication> {
        self.catalog
            .read()
            .ok()?
            .application_for_process(pid, executable)
    }

    fn refresh_after_miss(&self, now: Instant, load: impl FnOnce() -> DesktopCatalog) -> bool {
        let Ok(mut refresh) = self.refresh.lock() else {
            return false;
        };
        if refresh
            .last_miss_refresh
            .is_some_and(|last| now.saturating_duration_since(last) < MISS_REFRESH_COOLDOWN)
        {
            return false;
        }

        let replacement = load();
        let Ok(mut catalog) = self.catalog.write() else {
            return false;
        };
        *catalog = replacement;
        refresh.last_miss_refresh = Some(now);
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CatalogEntry {
    id: String,
    name: String,
    icon: Option<ProcessIconSource>,
    executables: Vec<String>,
}

#[derive(Debug, Default)]
struct DesktopCatalog {
    entries: Vec<CatalogEntry>,
}

impl DesktopCatalog {
    fn load() -> Self {
        let locales = get_languages_from_env();
        let desktops = current_desktops();
        let parsed = Iter::new(desktop_entry_paths().into_iter()).entries(Some(&locales));
        Self::from_entries(parsed, &locales, &desktops)
    }

    fn from_entries(
        entries: impl IntoIterator<Item = DesktopEntry>,
        locales: &[String],
        desktops: &[String],
    ) -> Self {
        let mut seen_ids = HashSet::new();
        let entries = entries
            .into_iter()
            .filter(|entry| seen_ids.insert(entry.id().to_owned()))
            .filter(|entry| is_visible_application(entry, desktops))
            .filter_map(|entry| CatalogEntry::from_desktop_entry(&entry, locales))
            .collect();
        Self { entries }
    }

    fn application_for_process(&self, pid: i32, executable: &Path) -> Option<GuiApplication> {
        let cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok();
        self.application(executable, cgroup.as_deref())
    }

    fn application(&self, executable: &Path, cgroup: Option<&str>) -> Option<GuiApplication> {
        let executable_matches = self
            .entries
            .iter()
            .filter(|entry| entry.matches_executable(executable))
            .collect::<Vec<_>>();
        if executable_matches.len() == 1 {
            return Some(executable_matches[0].application());
        }
        if executable_matches.len() > 1 {
            return None;
        }

        let ids = application_ids_from_cgroup(cgroup?);
        let id_matches = self
            .entries
            .iter()
            .filter(|entry| ids.iter().any(|id| id == &entry.id))
            .collect::<Vec<_>>();
        (id_matches.len() == 1).then(|| id_matches[0].application())
    }
}

impl CatalogEntry {
    fn from_desktop_entry(entry: &DesktopEntry, locales: &[String]) -> Option<Self> {
        let name = entry.name(locales)?.into_owned();
        if name.is_empty() {
            return None;
        }
        let icon = entry.icon().filter(|icon| !icon.is_empty()).map(|icon| {
            let path = PathBuf::from(icon);
            if path.is_absolute() {
                ProcessIconSource::Path(path)
            } else {
                ProcessIconSource::ThemeName(icon.to_owned())
            }
        });
        let executables = [entry.exec().and_then(exec_program), entry.try_exec()]
            .into_iter()
            .flatten()
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        Some(Self {
            id: entry.id().to_owned(),
            name,
            icon,
            executables,
        })
    }

    fn matches_executable(&self, executable: &Path) -> bool {
        self.executables.iter().any(|candidate| {
            let candidate = Path::new(candidate);
            if candidate.is_absolute() {
                candidate == executable
            } else {
                executable.file_name() == candidate.file_name()
            }
        })
    }

    fn application(&self) -> GuiApplication {
        GuiApplication {
            name: self.name.clone(),
            icon: self.icon.clone(),
            same_as_primary: false,
        }
    }
}

fn is_visible_application(entry: &DesktopEntry, desktops: &[String]) -> bool {
    if entry.type_() != Some("Application")
        || entry.hidden()
        || entry.no_display()
        || entry.terminal()
    {
        return false;
    }

    if entry
        .not_show_in()
        .is_some_and(|excluded| list_intersects(&excluded, desktops))
    {
        return false;
    }
    entry
        .only_show_in()
        .is_none_or(|allowed| list_intersects(&allowed, desktops))
}

fn list_intersects(values: &[&str], desktops: &[String]) -> bool {
    values
        .iter()
        .filter(|value| !value.is_empty())
        .any(|value| desktops.iter().any(|desktop| desktop == value))
}

fn current_desktops() -> Vec<String> {
    std::env::var("XDG_CURRENT_DESKTOP")
        .ok()
        .map(|value| value.split(':').map(ToOwned::to_owned).collect())
        .unwrap_or_default()
}

fn desktop_entry_paths() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(data_home) = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share")))
    {
        roots.push(data_home);
    }
    let data_dirs = std::env::var_os("XDG_DATA_DIRS")
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "/usr/local/share:/usr/share".into());
    roots.extend(std::env::split_paths(&data_dirs));
    roots
        .into_iter()
        .map(|root| root.join("applications"))
        .collect()
}

fn exec_program(command: &str) -> Option<&str> {
    let command = command.trim_start();
    if let Some(quoted) = command.strip_prefix('"') {
        let end = quoted.find('"')?;
        return quoted.get(..end);
    }
    command.split_ascii_whitespace().next()
}

fn application_ids_from_cgroup(cgroup: &str) -> Vec<String> {
    let mut ids = Vec::new();
    for path in cgroup.lines().filter_map(|line| line.splitn(3, ':').nth(2)) {
        for unit in path.split('/') {
            let Some(unit) = decode_systemd_unit_name(unit) else {
                continue;
            };
            let Some(body) = unit.strip_prefix("app-") else {
                continue;
            };

            if let Some(stable_id) = body.strip_suffix(".slice") {
                push_application_id_candidates(&mut ids, stable_id);
            } else if let Some(scope) = body.strip_suffix(".scope")
                && let Some((without_random, _random)) = scope.rsplit_once('-')
            {
                push_application_id_candidates(&mut ids, without_random);
            }
        }
    }
    ids
}

fn push_application_id_candidates(ids: &mut Vec<String>, value: &str) {
    push_unique(ids, value.to_owned());
    if let Some((launcher, app_id)) = value.split_once('-')
        && matches!(launcher, "gnome" | "KDE" | "flatpak")
    {
        push_unique(ids, app_id.to_owned());
    }
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.contains(&value) {
        values.push(value);
    }
}

fn decode_systemd_unit_name(unit: &str) -> Option<String> {
    let bytes = unit.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            if bytes.get(index + 1) != Some(&b'x') {
                return None;
            }
            let high = hex(*bytes.get(index + 2)?)?;
            let low = hex(*bytes.get(index + 3)?)?;
            decoded.push((high << 4) | low);
            index += 4;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).ok()
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::time::{Duration, Instant};

    use freedesktop_desktop_entry::DesktopEntry;
    use tempfile::TempDir;

    use super::{DesktopCatalog, DesktopCatalogCache, ProcessIconSource};

    #[test]
    fn parses_gnome_kde_and_escaped_application_scopes() {
        let cgroup = concat!(
            "0::/user.slice/app.slice/app-gnome-org.gnome.Terminal-abc.scope\n",
            "1:name:/app.slice/app-KDE-org.kde.konsole-123.scope\n",
            "2:name:/app.slice/app-org.example.Foo\\x2dBar-deadbeef.scope\n",
        );
        assert_eq!(
            vec![
                "gnome-org.gnome.Terminal",
                "org.gnome.Terminal",
                "KDE-org.kde.konsole",
                "org.kde.konsole",
                "org.example.Foo-Bar",
            ],
            super::application_ids_from_cgroup(cgroup)
        );
    }

    #[test]
    fn parses_stable_gnome_application_slice() {
        let cgroup = concat!(
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/",
            "app-org.gnome.Terminal.slice/gnome-terminal-server.service\n",
        );

        assert_eq!(
            vec!["org.gnome.Terminal"],
            super::application_ids_from_cgroup(cgroup)
        );
    }

    #[test]
    fn resolves_localized_name_and_path_or_theme_icon() {
        let entries = entries(&[
            (
                "org.gnome.Terminal.desktop",
                entry(
                    "Terminal",
                    "/usr/bin/gnome-terminal",
                    "/opt/terminal.png",
                    "Name[fr]=Terminal FR",
                ),
            ),
            (
                "org.kde.konsole.desktop",
                entry("Konsole", "konsole", "utilities-terminal", ""),
            ),
        ]);
        let catalog = DesktopCatalog::from_entries(entries, &["fr".into()], &["GNOME".into()]);

        let gnome = catalog
            .entries
            .iter()
            .find(|entry| entry.id == "org.gnome.Terminal")
            .unwrap();
        assert_eq!("Terminal FR", gnome.name);
        assert_eq!(
            Some(ProcessIconSource::Path("/opt/terminal.png".into())),
            gnome.icon
        );
        let kde = catalog
            .entries
            .iter()
            .find(|entry| entry.id == "org.kde.konsole")
            .unwrap();
        assert_eq!(
            Some(ProcessIconSource::ThemeName("utilities-terminal".into())),
            kde.icon
        );
    }

    #[test]
    fn matches_absolute_and_basename_exec_and_try_exec_exactly() {
        let entries = entries(&[
            (
                "absolute.desktop",
                entry("Absolute", "/usr/bin/terminal --new", "terminal", ""),
            ),
            (
                "basename.desktop",
                format!(
                    "{}TryExec=other-terminal\n",
                    entry("Basename", "other-terminal --new", "terminal", "")
                ),
            ),
        ]);
        let catalog = DesktopCatalog::from_entries(entries, &[], &[]);

        assert_eq!(
            "Absolute",
            catalog
                .application_for_process(0, std::path::Path::new("/usr/bin/terminal"))
                .unwrap()
                .name
        );
        assert_eq!(
            "Basename",
            catalog
                .application_for_process(0, std::path::Path::new("/opt/bin/other-terminal"))
                .unwrap()
                .name
        );
        assert!(
            catalog
                .application_for_process(0, std::path::Path::new("/usr/bin/terminal-extra"))
                .is_none()
        );
    }

    #[test]
    fn rejects_invisible_wrong_desktop_and_ambiguous_entries() {
        let entries = entries(&[
            (
                "hidden.desktop",
                format!("{}Hidden=true\n", entry("Hidden", "hidden", "x", "")),
            ),
            (
                "terminal.desktop",
                format!("{}Terminal=true\n", entry("Hosted", "hosted", "x", "")),
            ),
            (
                "nodisplay.desktop",
                format!(
                    "{}NoDisplay=true\n",
                    entry("No display", "nodisplay", "x", "")
                ),
            ),
            (
                "wrong.desktop",
                format!("{}OnlyShowIn=KDE;\n", entry("Wrong", "wrong", "x", "")),
            ),
            (
                "excluded.desktop",
                format!(
                    "{}NotShowIn=GNOME;\n",
                    entry("Excluded", "excluded", "x", "")
                ),
            ),
            ("one.desktop", entry("One", "ambiguous", "x", "")),
            ("two.desktop", entry("Two", "ambiguous", "x", "")),
        ]);
        let catalog = DesktopCatalog::from_entries(entries, &[], &["GNOME".into()]);

        assert_eq!(2, catalog.entries.len());
        assert!(
            catalog
                .application_for_process(0, std::path::Path::new("/usr/bin/ambiguous"))
                .is_none()
        );
    }

    #[test]
    fn resolves_unique_desktop_id_only_after_exec_does_not_match() {
        let catalog = DesktopCatalog::from_entries(
            entries(&[(
                "org.gnome.Terminal.desktop",
                entry("Terminal", "gnome-terminal", "terminal", ""),
            )]),
            &[],
            &[],
        );
        let cgroup = "0::/user.slice/app.slice/app-gnome-org.gnome.Terminal-abc.scope\n";

        assert_eq!(
            "Terminal",
            catalog
                .application(
                    std::path::Path::new("/usr/libexec/gnome-terminal-server"),
                    Some(cgroup)
                )
                .unwrap()
                .name
        );
        assert!(
            catalog
                .application(
                    std::path::Path::new("/usr/libexec/gnome-terminal-server"),
                    Some("0::/app.slice/app-gnome-org.gnome.Unknown-abc.scope\n")
                )
                .is_none()
        );
    }

    #[test]
    fn resolves_gnome_terminal_server_from_stable_application_slice() {
        let catalog = DesktopCatalog::from_entries(
            entries(&[(
                "org.gnome.Terminal.desktop",
                entry("Terminal", "gnome-terminal", "terminal", ""),
            )]),
            &[],
            &[],
        );
        let cgroup = concat!(
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/",
            "app-org.gnome.Terminal.slice/gnome-terminal-server.service\n",
        );

        assert_eq!(
            "Terminal",
            catalog
                .application(
                    std::path::Path::new("/usr/libexec/gnome-terminal-server"),
                    Some(cgroup)
                )
                .unwrap()
                .name
        );
    }

    #[test]
    fn refresh_after_miss_replaces_catalog_and_is_throttled() {
        let cache = DesktopCatalogCache::new(DesktopCatalog::default());
        let now = Instant::now();

        assert!(
            cache.refresh_after_miss(now, || DesktopCatalog::from_entries(
                entries(&[(
                    "lxterminal.desktop",
                    entry("LXTerminal", "lxterminal", "lxterminal", ""),
                )]),
                &[],
                &[],
            ))
        );
        assert_eq!(
            "LXTerminal",
            cache
                .application_for_process(0, std::path::Path::new("/usr/bin/lxterminal"))
                .unwrap()
                .name
        );

        let loads = AtomicUsize::new(0);
        assert!(!cache.refresh_after_miss(now + Duration::from_secs(1), || {
            loads.fetch_add(1, Ordering::Relaxed);
            DesktopCatalog::default()
        }));
        assert_eq!(0, loads.load(Ordering::Relaxed));
    }

    #[test]
    fn concurrent_misses_trigger_one_catalog_refresh() {
        const THREADS: usize = 8;
        let cache = Arc::new(DesktopCatalogCache::new(DesktopCatalog::default()));
        let barrier = Arc::new(Barrier::new(THREADS));
        let loads = Arc::new(AtomicUsize::new(0));
        let now = Instant::now();
        let threads = (0..THREADS)
            .map(|_| {
                let cache = Arc::clone(&cache);
                let barrier = Arc::clone(&barrier);
                let loads = Arc::clone(&loads);
                std::thread::spawn(move || {
                    barrier.wait();
                    cache.refresh_after_miss(now, || {
                        loads.fetch_add(1, Ordering::Relaxed);
                        DesktopCatalog::default()
                    })
                })
            })
            .collect::<Vec<_>>();

        let refreshed = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .filter(|refreshed| *refreshed)
            .count();
        assert_eq!(1, refreshed);
        assert_eq!(1, loads.load(Ordering::Relaxed));
    }

    fn entries(values: &[(&str, String)]) -> Vec<DesktopEntry> {
        let temp = TempDir::new().unwrap();
        values
            .iter()
            .map(|(name, contents)| {
                let path = temp.path().join(name);
                fs::write(&path, contents).unwrap();
                DesktopEntry::from_path(path, Some(&["fr"])).unwrap()
            })
            .collect()
    }

    fn entry(name: &str, exec: &str, icon: &str, extra: &str) -> String {
        format!(
            "[Desktop Entry]\nType=Application\nName={name}\n{extra}\nExec={exec}\nIcon={icon}\nTerminal=false\n"
        )
    }
}
