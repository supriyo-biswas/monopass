#[cfg(any(
    target_os = "macos",
    all(target_os = "linux", any(feature = "gtk", feature = "qt"))
))]
use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::mpsc;
use std::thread::JoinHandle;

use chrono::{DateTime, Local};
use tokio::sync::oneshot;
use zeroize::Zeroizing;

use super::models::AccessScope;
use super::process::ProcessDisplay;

pub(crate) type PromptRequestReceiver = mpsc::Receiver<PromptRequest>;

pub(crate) enum PromptOutcome {
    Allowed(Zeroizing<String>),
    Denied,
    Dismissed,
}

static PROMPT_DISPATCHER: OnceLock<PromptRequestSender> = OnceLock::new();

#[derive(Clone)]
struct PromptRequestSender(mpsc::Sender<PromptRequest>);

pub(crate) struct PromptRequest {
    display: Option<ProcessDisplay>,
    access_scope: AccessScope,
    response: oneshot::Sender<PromptOutcome>,
}

pub(crate) fn install_prompt_dispatcher() -> PromptRequestReceiver {
    let (sender, receiver) = mpsc::channel();
    let _ = PROMPT_DISPATCHER.set(PromptRequestSender(sender));
    receiver
}

pub(crate) async fn prompt_password(
    display: Option<ProcessDisplay>,
    access_scope: AccessScope,
) -> PromptOutcome {
    prompt_password_with(display, access_scope, dispatch_prompt).await
}

pub(crate) async fn prompt_password_with<F, Fut>(
    display: Option<ProcessDisplay>,
    access_scope: AccessScope,
    prompt: F,
) -> PromptOutcome
where
    F: FnOnce(Option<ProcessDisplay>, AccessScope) -> Fut,
    Fut: std::future::Future<Output = PromptOutcome>,
{
    prompt(display, access_scope).await
}

async fn dispatch_prompt(
    display: Option<ProcessDisplay>,
    access_scope: AccessScope,
) -> PromptOutcome {
    let Some(sender) = PROMPT_DISPATCHER.get().cloned() else {
        return PromptOutcome::Dismissed;
    };
    let (response, receiver) = oneshot::channel();
    if sender
        .0
        .send(PromptRequest {
            display,
            access_scope,
            response,
        })
        .is_err()
    {
        return PromptOutcome::Dismissed;
    }
    receiver.await.unwrap_or(PromptOutcome::Dismissed)
}

pub(crate) fn run_prompt_dispatcher<T>(receiver: PromptRequestReceiver, server: &JoinHandle<T>) {
    initialize_prompt_backend();
    run_prompt_dispatcher_inner(receiver, server);
}

#[cfg(target_os = "macos")]
fn run_prompt_dispatcher_inner<T>(receiver: PromptRequestReceiver, server: &JoinHandle<T>) {
    use objc2_foundation::MainThreadMarker;

    let mtm = MainThreadMarker::new().expect("AppKit prompt dispatcher must run on main thread");
    let mut prompts = Vec::new();

    loop {
        loop {
            match receiver.try_recv() {
                Ok(request) => prompts.push(PromptController::present(request, mtm)),
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    close_prompts(&prompts);
                    return;
                }
            }
        }

        pump_appkit_once(mtm);
        prompts.retain(|prompt| !prompt.is_finished());

        if server.is_finished() && prompts.is_empty() {
            break;
        }

        std::thread::sleep(std::time::Duration::from_millis(25));
    }
}

#[cfg(all(target_os = "linux", any(feature = "gtk", feature = "qt")))]
fn run_prompt_dispatcher_inner<T>(receiver: PromptRequestReceiver, server: &JoinHandle<T>) {
    linux_prompt::run_prompt_dispatcher(receiver, server);
}

#[cfg(not(any(
    target_os = "macos",
    all(target_os = "linux", any(feature = "gtk", feature = "qt"))
)))]
fn run_prompt_dispatcher_inner<T>(receiver: PromptRequestReceiver, server: &JoinHandle<T>) {
    loop {
        match receiver.recv_timeout(std::time::Duration::from_millis(250)) {
            Ok(request) => {
                let _ = request.response.send(PromptOutcome::Dismissed);
            }
            Err(mpsc::RecvTimeoutError::Timeout) if server.is_finished() => break,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
}

#[cfg(target_os = "macos")]
fn initialize_prompt_backend() {
    use objc2_app_kit::{NSApplication, NSApplicationActivationPolicy};
    use objc2_foundation::MainThreadMarker;

    let mtm = MainThreadMarker::new().expect("AppKit prompt dispatcher must run on main thread");
    let app = NSApplication::sharedApplication(mtm);
    app.setActivationPolicy(NSApplicationActivationPolicy::Accessory);
    app.finishLaunching();
}

#[cfg(not(target_os = "macos"))]
fn initialize_prompt_backend() {}

#[cfg(target_os = "macos")]
fn pump_appkit_once(mtm: objc2_foundation::MainThreadMarker) {
    use objc2_app_kit::{NSApplication, NSEventMask};
    use objc2_foundation::{NSDate, NSDefaultRunLoopMode};

    let app = NSApplication::sharedApplication(mtm);
    let until = NSDate::dateWithTimeIntervalSinceNow(0.0);

    while let Some(event) = app.nextEventMatchingMask_untilDate_inMode_dequeue(
        NSEventMask::Any,
        Some(&until),
        unsafe { NSDefaultRunLoopMode },
        true,
    ) {
        app.sendEvent(&event);
    }

    app.updateWindows();
}

#[cfg(target_os = "macos")]
fn close_prompts(prompts: &[objc2::rc::Retained<PromptController>]) {
    for prompt in prompts {
        prompt.finish(PromptOutcome::Dismissed);
    }
}

#[cfg(all(target_os = "linux", feature = "gtk"))]
mod linux_prompt {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;
    use std::sync::mpsc;
    use std::thread::JoinHandle;
    use std::time::Duration;

    use gtk::glib;
    use gtk::prelude::*;
    use gtk4 as gtk;
    use zeroize::Zeroizing;

    use super::{AccessScope, PromptMetadata, PromptOutcome, PromptRequest, PromptRequestReceiver};

    const GENERIC_TERMINAL_ICON_NAMES: &[&str] = &[
        "utilities-terminal",
        "org.gnome.Terminal",
        "org.kde.konsole",
        "terminal",
    ];

    pub(super) fn run_prompt_dispatcher<T>(
        receiver: PromptRequestReceiver,
        server: &JoinHandle<T>,
    ) {
        if gtk::init().is_err() {
            deny_all(receiver, server);
            return;
        }

        let app = gtk::Application::builder()
            .application_id("dev.monopass.AgentPrompt")
            .flags(gtk::gio::ApplicationFlags::NON_UNIQUE)
            .build();

        if app.register(None::<&gtk::gio::Cancellable>).is_err() {
            deny_all(receiver, server);
            return;
        }

        let context = glib::MainContext::default();
        let mut prompts = Vec::new();
        let mut disconnected = false;

        loop {
            loop {
                match receiver.try_recv() {
                    Ok(request) => prompts.push(GtkPrompt::present(request, &app)),
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        disconnected = true;
                        break;
                    }
                }
            }

            while context.pending() {
                context.iteration(false);
            }
            prompts.retain(|prompt| !prompt.is_finished());

            if disconnected {
                close_prompts(&prompts);
                break;
            }
            if server.is_finished() && prompts.is_empty() {
                break;
            }

            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn deny_all<T>(receiver: PromptRequestReceiver, server: &JoinHandle<T>) {
        loop {
            match receiver.recv_timeout(Duration::from_millis(250)) {
                Ok(request) => {
                    let _ = request.response.send(PromptOutcome::Dismissed);
                }
                Err(mpsc::RecvTimeoutError::Timeout) if server.is_finished() => break,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
    }

    fn close_prompts(prompts: &[GtkPrompt]) {
        for prompt in prompts {
            prompt.finish(PromptOutcome::Dismissed);
        }
    }

    struct GtkPrompt {
        window: gtk::Window,
        finished: Rc<Cell<bool>>,
        response: Rc<RefCell<Option<tokio::sync::oneshot::Sender<PromptOutcome>>>>,
    }

    impl GtkPrompt {
        fn present(request: PromptRequest, app: &gtk::Application) -> Self {
            let metadata =
                PromptMetadata::from_display(request.display.as_ref(), request.access_scope);
            let finished = Rc::new(Cell::new(false));
            let response = Rc::new(RefCell::new(Some(request.response)));
            let window = build_window(&metadata, app);
            let password = gtk::PasswordEntry::new();
            password.set_hexpand(true);
            password.set_show_peek_icon(false);

            let (allow, deny) = add_prompt_content(&window, &password, &metadata);
            wire_prompt_actions(
                &window,
                &password,
                &allow,
                &deny,
                Rc::clone(&finished),
                Rc::clone(&response),
            );
            window.present();

            Self {
                window,
                finished,
                response,
            }
        }

        fn finish(&self, outcome: PromptOutcome) {
            finish_prompt(&self.window, &self.finished, &self.response, outcome);
        }

        fn is_finished(&self) -> bool {
            self.finished.get()
        }
    }

    fn build_window(metadata: &PromptMetadata, app: &gtk::Application) -> gtk::Window {
        let window: gtk::Window = gtk::ApplicationWindow::builder()
            .application(app)
            .title(&metadata.title)
            .default_width(460)
            .resizable(false)
            .build()
            .upcast();
        window.set_tooltip_text(Some(&metadata.executable_path_text));
        window
    }

    fn add_prompt_content(
        window: &gtk::Window,
        password: &gtk::PasswordEntry,
        metadata: &PromptMetadata,
    ) -> (gtk::Button, gtk::Button) {
        let root = gtk::Box::new(gtk::Orientation::Vertical, 14);
        root.set_margin_top(20);
        root.set_margin_bottom(20);
        root.set_margin_start(20);
        root.set_margin_end(20);

        let header = gtk::Box::new(gtk::Orientation::Horizontal, 14);
        if let Some(icon) = icon_for_metadata(metadata) {
            header.append(&icon);
        }

        let text = gtk::Box::new(gtk::Orientation::Vertical, 4);
        let intro = gtk::Label::new(Some(&metadata.intro));
        intro.set_xalign(0.0);
        intro.set_wrap(true);
        let app_name = gtk::Label::new(Some(&metadata.app_name));
        app_name.set_xalign(0.0);
        app_name.add_css_class("heading");
        let path = gtk::Label::new(Some(&metadata.executable_path_text));
        path.set_xalign(0.0);
        path.set_ellipsize(gtk::pango::EllipsizeMode::Middle);
        path.add_css_class("monospace");
        text.append(&intro);
        text.append(&app_name);
        if let Some(modified) = metadata.modified_text.as_ref() {
            let modified = gtk::Label::new(Some(modified));
            modified.set_xalign(0.0);
            text.append(&modified);
        }
        text.append(&path);
        header.append(&text);
        root.append(&header);
        root.append(password);

        let actions = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        actions.set_halign(gtk::Align::End);
        let deny = gtk::Button::with_label("Deny");
        deny.set_widget_name("deny");
        let allow = gtk::Button::with_label("Allow");
        allow.add_css_class("suggested-action");
        allow.set_widget_name("allow");
        actions.append(&deny);
        actions.append(&allow);
        root.append(&actions);

        window.set_child(Some(&root));

        (allow, deny)
    }

    fn icon_for_metadata(metadata: &PromptMetadata) -> Option<gtk::Image> {
        if metadata.access_scope == AccessScope::Settings {
            let image = gtk::Image::from_icon_name("preferences-system");
            image.set_pixel_size(40);
            return Some(image);
        }

        if let Some(path) = metadata.preferred_icon_path.as_deref()
            && path.exists()
        {
            let image = gtk::Image::from_file(path);
            image.set_pixel_size(40);
            return Some(image);
        }

        let icon_name = generic_terminal_icon_name()?;
        let image = gtk::Image::from_icon_name(icon_name);
        image.set_pixel_size(40);
        Some(image)
    }

    fn generic_terminal_icon_name() -> Option<&'static str> {
        let display = gtk::gdk::Display::default()?;
        let theme = gtk::IconTheme::for_display(&display);
        GENERIC_TERMINAL_ICON_NAMES
            .iter()
            .copied()
            .find(|name| theme.has_icon(name))
    }

    fn wire_prompt_actions(
        window: &gtk::Window,
        password: &gtk::PasswordEntry,
        allow: &gtk::Button,
        deny: &gtk::Button,
        finished: Rc<Cell<bool>>,
        response: Rc<RefCell<Option<tokio::sync::oneshot::Sender<PromptOutcome>>>>,
    ) {
        let allow_window = window.clone();
        let allow_finished = Rc::clone(&finished);
        let allow_response = Rc::clone(&response);
        let allow_password = password.clone();
        allow.connect_clicked(move |_| {
            let password_text = allow_password.text().to_string();
            allow_password.set_text("");
            finish_prompt(
                &allow_window,
                &allow_finished,
                &allow_response,
                PromptOutcome::Allowed(Zeroizing::new(password_text)),
            );
        });

        let activate_window = window.clone();
        let activate_finished = Rc::clone(&finished);
        let activate_response = Rc::clone(&response);
        password.connect_activate(move |password| {
            let password_text = password.text().to_string();
            password.set_text("");
            finish_prompt(
                &activate_window,
                &activate_finished,
                &activate_response,
                PromptOutcome::Allowed(Zeroizing::new(password_text)),
            );
        });

        let deny_window = window.clone();
        let deny_finished = Rc::clone(&finished);
        let deny_response = Rc::clone(&response);
        deny.connect_clicked(move |_| {
            finish_prompt(
                &deny_window,
                &deny_finished,
                &deny_response,
                PromptOutcome::Denied,
            );
        });

        let close_finished = Rc::clone(&finished);
        let close_response = Rc::clone(&response);
        window.connect_close_request(move |window| {
            finish_prompt(
                window,
                &close_finished,
                &close_response,
                PromptOutcome::Dismissed,
            );
            glib::Propagation::Proceed
        });

        let escape = gtk::EventControllerKey::new();
        let escape_window = window.clone();
        let escape_finished = Rc::clone(&finished);
        let escape_response = Rc::clone(&response);
        escape.connect_key_pressed(move |_, key, _, _| {
            if key == gtk::gdk::Key::Escape {
                finish_prompt(
                    &escape_window,
                    &escape_finished,
                    &escape_response,
                    PromptOutcome::Dismissed,
                );
                return glib::Propagation::Stop;
            }
            glib::Propagation::Proceed
        });
        window.add_controller(escape);
    }

    fn finish_prompt(
        window: &gtk::Window,
        finished: &Rc<Cell<bool>>,
        response: &Rc<RefCell<Option<tokio::sync::oneshot::Sender<PromptOutcome>>>>,
        outcome: PromptOutcome,
    ) {
        if finished.replace(true) {
            return;
        }
        if let Some(response) = response.borrow_mut().take() {
            let _ = response.send(outcome);
        }
        window.close();
    }
}

#[cfg(all(target_os = "linux", not(feature = "gtk"), feature = "qt"))]
mod linux_prompt {
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::ffi::OsStr;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::mpsc;
    use std::thread::JoinHandle;
    use std::time::Duration;

    use qmetaobject::{QObjectPinned, prelude::*};
    use zeroize::Zeroizing;

    use super::{AccessScope, PromptMetadata, PromptOutcome, PromptRequestReceiver};

    const GENERIC_TERMINAL_ICON_NAMES: &[&str] = &[
        "utilities-terminal",
        "org.gnome.Terminal",
        "org.kde.konsole",
        "terminal",
        "Terminal",
    ];

    thread_local! {
        static STATE: RefCell<Option<QtPromptState>> = const { RefCell::new(None) };
        static CURRENT: RefCell<CurrentPrompt> = RefCell::new(CurrentPrompt::default());
    }

    pub(super) fn run_prompt_dispatcher<T>(
        receiver: PromptRequestReceiver,
        server: &JoinHandle<T>,
    ) {
        let (done_sender, done_receiver) = mpsc::channel();
        std::thread::scope(|scope| {
            scope.spawn(move || {
                while !server.is_finished() {
                    std::thread::sleep(Duration::from_millis(100));
                }
                let _ = done_sender.send(());
            });

            STATE.with(|state| {
                *state.borrow_mut() = Some(QtPromptState::new(receiver, done_receiver));
            });

            let bridge = RefCell::new(PromptBridge::default());
            let mut engine = QmlEngine::new();
            engine.set_object_property("_promptBridge".into(), unsafe {
                QObjectPinned::new(&bridge)
            });
            engine.load_data(QT_PROMPT_QML.into());
            engine.exec();

            STATE.with(|state| {
                if let Some(mut state) = state.borrow_mut().take() {
                    state.deny_all();
                }
            });
        });
    }

    struct QtPromptState {
        receiver: PromptRequestReceiver,
        done_receiver: mpsc::Receiver<()>,
        pending: HashMap<u32, tokio::sync::oneshot::Sender<PromptOutcome>>,
        next_id: u32,
        receiver_disconnected: bool,
        server_done: bool,
    }

    impl QtPromptState {
        fn new(receiver: PromptRequestReceiver, done_receiver: mpsc::Receiver<()>) -> Self {
            Self {
                receiver,
                done_receiver,
                pending: HashMap::new(),
                next_id: 1,
                receiver_disconnected: false,
                server_done: false,
            }
        }

        fn poll_prompt(&mut self) -> bool {
            self.poll_server_done();
            match self.receiver.try_recv() {
                Ok(request) => {
                    let id = self.next_id;
                    self.next_id = self.next_id.wrapping_add(1).max(1);
                    let metadata = PromptMetadata::from_display(
                        request.display.as_ref(),
                        request.access_scope,
                    );
                    self.pending.insert(id, request.response);
                    CURRENT.with(|current| {
                        *current.borrow_mut() = CurrentPrompt::from_metadata(id, metadata);
                    });
                    true
                }
                Err(mpsc::TryRecvError::Empty) => false,
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.receiver_disconnected = true;
                    false
                }
            }
        }

        fn poll_server_done(&mut self) {
            while self.done_receiver.try_recv().is_ok() {
                self.server_done = true;
            }
        }

        fn should_quit(&mut self) -> bool {
            self.poll_server_done();
            (self.server_done || self.receiver_disconnected) && self.pending.is_empty()
        }

        fn allow(&mut self, id: u32, password: QString) {
            if let Some(response) = self.pending.remove(&id) {
                let _ = response.send(PromptOutcome::Allowed(Zeroizing::new(password.to_string())));
            }
        }

        fn deny(&mut self, id: u32) {
            if let Some(response) = self.pending.remove(&id) {
                let _ = response.send(PromptOutcome::Denied);
            }
        }

        fn dismiss(&mut self, id: u32) {
            if let Some(response) = self.pending.remove(&id) {
                let _ = response.send(PromptOutcome::Dismissed);
            }
        }

        fn deny_all(&mut self) {
            for (_, response) in self.pending.drain() {
                let _ = response.send(PromptOutcome::Dismissed);
            }
            while let Ok(request) = self.receiver.try_recv() {
                let _ = request.response.send(PromptOutcome::Dismissed);
            }
        }
    }

    #[derive(Default)]
    struct CurrentPrompt {
        id: u32,
        settings_scope: bool,
        title: String,
        intro: String,
        app_name: String,
        modified_text: String,
        path: String,
        icon_sources: String,
    }

    impl CurrentPrompt {
        fn from_metadata(id: u32, metadata: PromptMetadata) -> Self {
            let icon_sources = icon_sources(&metadata);
            Self {
                id,
                settings_scope: metadata.access_scope == AccessScope::Settings,
                title: metadata.title,
                intro: metadata.intro,
                app_name: metadata.app_name,
                modified_text: metadata.modified_text.unwrap_or_default(),
                path: metadata.executable_path_text,
                icon_sources,
            }
        }
    }

    fn icon_sources(metadata: &PromptMetadata) -> String {
        if metadata.access_scope == AccessScope::Settings {
            return ["preferences-system", "settings", "preferences-other"]
                .iter()
                .filter_map(|name| find_xdg_icon(name))
                .filter_map(|path| url::Url::from_file_path(path).ok())
                .map(|url| url.to_string())
                .collect::<Vec<_>>()
                .join("\n");
        }

        let mut sources = Vec::new();
        if let Some(path) = metadata.preferred_icon_path.as_deref()
            && path.exists()
        {
            sources.push(format!("file://{}", path.display()));
        }
        sources.extend(generic_terminal_icon_sources());
        sources.join("\n")
    }

    fn generic_terminal_icon_sources() -> Vec<String> {
        GENERIC_TERMINAL_ICON_NAMES
            .iter()
            .filter_map(|name| find_xdg_icon(name))
            .filter_map(|path| {
                url::Url::from_file_path(path)
                    .ok()
                    .map(|url| url.to_string())
            })
            .collect()
    }

    fn find_xdg_icon(name: &str) -> Option<PathBuf> {
        xdg_icon_roots()
            .into_iter()
            .find_map(|root| find_icon_below(&root, name))
    }

    fn xdg_icon_roots() -> Vec<PathBuf> {
        let mut roots = Vec::new();
        if let Some(data_home) = std::env::var_os("XDG_DATA_HOME") {
            roots.push(PathBuf::from(data_home).join("icons"));
        } else if let Some(home) = std::env::var_os("HOME") {
            roots.push(PathBuf::from(home).join(".local/share/icons"));
        }

        let data_dirs = std::env::var_os("XDG_DATA_DIRS")
            .and_then(|value| value.into_string().ok())
            .unwrap_or_else(|| "/usr/local/share:/usr/share".to_owned());
        roots.extend(
            data_dirs
                .split(':')
                .filter(|value| !value.is_empty())
                .flat_map(|dir| {
                    [
                        PathBuf::from(dir).join("icons"),
                        PathBuf::from(dir).join("pixmaps"),
                    ]
                }),
        );
        roots
    }

    fn find_icon_below(root: &Path, name: &str) -> Option<PathBuf> {
        let mut stack = vec![root.to_path_buf()];
        let mut fallback = None;
        while let Some(dir) = stack.pop() {
            let Ok(entries) = fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.file_stem() != Some(OsStr::new(name)) || !is_supported_icon_file(&path) {
                    continue;
                }
                if path.extension() == Some(OsStr::new("png")) {
                    return Some(path);
                }
                fallback.get_or_insert(path);
            }
        }
        fallback
    }

    fn is_supported_icon_file(path: &Path) -> bool {
        matches!(
            path.extension().and_then(OsStr::to_str),
            Some("png" | "svg" | "xpm")
        )
    }

    #[derive(QObject, Default)]
    struct PromptBridge {
        base: qt_base_class!(trait QObject),
        poll: qt_method!(fn(&self) -> bool),
        should_quit: qt_method!(fn(&self) -> bool),
        allow: qt_method!(fn(&self, id: u32, password: QString)),
        deny: qt_method!(fn(&self, id: u32)),
        dismiss: qt_method!(fn(&self, id: u32)),
        prompt_id: qt_method!(fn(&self) -> u32),
        settings_scope: qt_method!(fn(&self) -> bool),
        title: qt_method!(fn(&self) -> QString),
        intro: qt_method!(fn(&self) -> QString),
        app_name: qt_method!(fn(&self) -> QString),
        modified_text: qt_method!(fn(&self) -> QString),
        executable_path: qt_method!(fn(&self) -> QString),
        icon_sources: qt_method!(fn(&self) -> QString),
    }

    impl PromptBridge {
        fn poll(&self) -> bool {
            STATE.with(|state| {
                state
                    .borrow_mut()
                    .as_mut()
                    .is_some_and(QtPromptState::poll_prompt)
            })
        }

        fn should_quit(&self) -> bool {
            STATE.with(|state| {
                state
                    .borrow_mut()
                    .as_mut()
                    .is_none_or(QtPromptState::should_quit)
            })
        }

        fn allow(&self, id: u32, password: QString) {
            STATE.with(|state| {
                if let Some(state) = state.borrow_mut().as_mut() {
                    state.allow(id, password);
                }
            });
        }

        fn deny(&self, id: u32) {
            STATE.with(|state| {
                if let Some(state) = state.borrow_mut().as_mut() {
                    state.deny(id);
                }
            });
        }

        fn dismiss(&self, id: u32) {
            STATE.with(|state| {
                if let Some(state) = state.borrow_mut().as_mut() {
                    state.dismiss(id);
                }
            });
        }

        fn prompt_id(&self) -> u32 {
            CURRENT.with(|current| current.borrow().id)
        }

        fn settings_scope(&self) -> bool {
            CURRENT.with(|current| current.borrow().settings_scope)
        }

        fn title(&self) -> QString {
            CURRENT.with(|current| current.borrow().title.as_str().into())
        }

        fn intro(&self) -> QString {
            CURRENT.with(|current| current.borrow().intro.as_str().into())
        }

        fn app_name(&self) -> QString {
            CURRENT.with(|current| current.borrow().app_name.as_str().into())
        }

        fn modified_text(&self) -> QString {
            CURRENT.with(|current| current.borrow().modified_text.as_str().into())
        }

        fn executable_path(&self) -> QString {
            CURRENT.with(|current| current.borrow().path.as_str().into())
        }

        fn icon_sources(&self) -> QString {
            CURRENT.with(|current| current.borrow().icon_sources.as_str().into())
        }
    }

    const QT_PROMPT_QML: &str = r##"
import QtQuick 2.12
import QtQuick.Window 2.12
import QtQuick.Controls 2.12
import QtQuick.Layouts 1.12

Window {
    id: root
    width: 1
    height: 1
    visible: true
    x: -10000
    y: -10000
    flags: Qt.Window | Qt.FramelessWindowHint | Qt.WindowDoesNotAcceptFocus
    property var activePrompts: []

    Component.onCompleted: {
        Qt.application.quitOnLastWindowClosed = false
    }

    function addPrompt(prompt) {
        activePrompts.push(prompt)
        activePrompts = activePrompts
    }

    function removePrompt(prompt) {
        var index = activePrompts.indexOf(prompt)
        if (index >= 0) {
            activePrompts.splice(index, 1)
            activePrompts = activePrompts
        }
    }

    Timer {
        interval: 25
        running: true
        repeat: true
        onTriggered: {
            while (_promptBridge.poll()) {
                var prompt = promptComponent.createObject(null, {
                    "promptId": _promptBridge.prompt_id(),
                    "settingsScope": _promptBridge.settings_scope(),
                    "titleText": _promptBridge.title(),
                    "introText": _promptBridge.intro(),
                    "appName": _promptBridge.app_name(),
                    "modifiedText": _promptBridge.modified_text(),
                    "pathText": _promptBridge.executable_path(),
                    "iconSourcesText": _promptBridge.icon_sources()
                })
                if (prompt !== null) {
                    root.addPrompt(prompt)
                }
            }
            if (_promptBridge.should_quit()) {
                Qt.quit()
            }
        }
    }

    Component {
        id: promptComponent
        Window {
            id: prompt
            property int promptId: 0
            property bool settingsScope: false
            property string titleText: ""
            property string introText: ""
            property string appName: ""
            property string modifiedText: ""
            property string pathText: ""
            property string iconSourcesText: ""
            property var iconSources: iconSourcesText.length > 0 ? iconSourcesText.split("\n") : []
            property int iconSourceIndex: 0
            property bool completed: false
            property int activationAttempts: 0

            function currentIconSource() {
                return iconSourceIndex < iconSources.length ? iconSources[iconSourceIndex] : ""
            }

            function tryNextIconSource() {
                iconSourceIndex += 1
                icon.source = currentIconSource()
            }

            function denyPrompt() {
                password.text = ""
                if (!prompt.completed) {
                    _promptBridge.deny(prompt.promptId)
                    prompt.completed = true
                }
                prompt.close()
            }

            function dismissPrompt() {
                password.text = ""
                if (!prompt.completed) {
                    _promptBridge.dismiss(prompt.promptId)
                    prompt.completed = true
                }
                prompt.close()
            }

            function allowPrompt() {
                var submitted = password.text
                password.text = ""
                if (!prompt.completed) {
                    _promptBridge.allow(prompt.promptId, submitted)
                    prompt.completed = true
                }
                prompt.close()
            }

            function activatePrompt() {
                prompt.raise()
                prompt.requestActivate()
                password.forceActiveFocus()
            }

            title: titleText
            width: 460
            minimumWidth: 460
            maximumWidth: 460
            height: 220
            minimumHeight: 220
            maximumHeight: 220
            x: 80 + ((promptId - 1) % 8) * 28
            y: 80 + ((promptId - 1) % 8) * 28
            visible: true
            modality: Qt.NonModal
            flags: Qt.Dialog | Qt.WindowStaysOnTopHint

            Component.onCompleted: {
                activatePrompt()
                activationTimer.start()
            }

            onClosing: {
                if (!completed) {
                    _promptBridge.dismiss(promptId)
                    completed = true
                }
            }

            onVisibleChanged: {
                if (!visible && !completed) {
                    _promptBridge.dismiss(promptId)
                    completed = true
                }
                if (!visible) {
                    root.removePrompt(prompt)
                    prompt.destroy()
                }
            }

            onActiveChanged: {
                if (active) {
                    password.forceActiveFocus()
                }
            }

            Timer {
                id: activationTimer
                interval: 75
                running: false
                repeat: true
                onTriggered: {
                    prompt.activationAttempts += 1
                    prompt.activatePrompt()
                    if (prompt.active || prompt.activationAttempts >= 8) {
                        stop()
                    }
                }
            }

            Shortcut {
                sequence: "Esc"
                onActivated: prompt.dismissPrompt()
            }

            ColumnLayout {
                anchors.fill: parent
                anchors.margins: 20
                spacing: 12

                RowLayout {
                    Layout.fillWidth: true
                    spacing: 14

                    Image {
                        id: icon
                        source: prompt.currentIconSource()
                        visible: source.length > 0 && status !== Image.Error
                        sourceSize.width: 40
                        sourceSize.height: 40
                        Layout.preferredWidth: visible ? 40 : 0
                        Layout.preferredHeight: visible ? 40 : 0
                        fillMode: Image.PreserveAspectFit
                        onStatusChanged: {
                            if (status === Image.Error) {
                                prompt.tryNextIconSource()
                            }
                        }
                    }

                    Label {
                        text: "⚙"
                        visible: prompt.settingsScope && !icon.visible
                        font.pixelSize: 34
                        Layout.preferredWidth: visible ? 40 : 0
                        Layout.preferredHeight: visible ? 40 : 0
                        horizontalAlignment: Text.AlignHCenter
                        verticalAlignment: Text.AlignVCenter
                    }

                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 4

                        Label {
                            text: introText
                            wrapMode: Text.WordWrap
                            Layout.fillWidth: true
                        }
                        Label {
                            text: appName
                            font.bold: true
                            elide: Text.ElideRight
                            Layout.fillWidth: true
                        }
                        Label {
                            text: modifiedText
                            visible: modifiedText.length > 0
                            elide: Text.ElideRight
                            Layout.fillWidth: true
                        }
                        Label {
                            text: pathText
                            font.family: "monospace"
                            elide: Text.ElideMiddle
                            Layout.fillWidth: true
                        }
                    }
                }

                TextField {
                    id: password
                    echoMode: TextInput.Password
                    Layout.fillWidth: true
                    focus: true
                    onAccepted: prompt.allowPrompt()
                    Component.onCompleted: forceActiveFocus()
                }

                RowLayout {
                    Layout.alignment: Qt.AlignRight
                    spacing: 8
                    Button {
                        text: "Deny"
                        onClicked: prompt.denyPrompt()
                    }
                    Button {
                        id: allowButton
                        text: "Allow"
                        onClicked: prompt.allowPrompt()
                    }
                }
            }
        }
    }
}
"##;
}

#[cfg(target_os = "macos")]
fn path_to_string(path: &std::path::Path) -> Option<String> {
    path.to_str().map(ToOwned::to_owned)
}

#[cfg(target_os = "macos")]
mod appkit_prompt {
    use std::cell::RefCell;

    use objc2::rc::Retained;
    use objc2::runtime::ProtocolObject;
    use objc2::{DefinedClass, MainThreadOnly, define_class, msg_send, sel};
    use objc2_app_kit::{
        NSApplication, NSBackingStoreType, NSButton, NSFloatingWindowLevel, NSFont, NSImage,
        NSImageNamePreferencesGeneral, NSImageView, NSLineBreakMode, NSSecureTextField,
        NSTextField, NSView, NSWindow, NSWindowDelegate, NSWindowStyleMask, NSWorkspace,
    };
    use objc2_foundation::{
        MainThreadMarker, NSNotification, NSObject, NSObjectProtocol, NSPoint, NSRect, NSSize,
        NSString, ns_string,
    };
    use objc2_uniform_type_identifiers::UTTypeUnixExecutable;
    use tokio::sync::oneshot;
    use zeroize::Zeroizing;

    use super::{AccessScope, PromptMetadata, PromptOutcome, PromptRequest, path_to_string};

    const WINDOW_WIDTH: f64 = 460.0;
    const WINDOW_HEIGHT: f64 = 196.0;
    const PADDING: f64 = 20.0;
    const ICON_SIZE: f64 = 40.0;
    const BUTTON_WIDTH: f64 = 86.0;
    const BUTTON_HEIGHT: f64 = 32.0;

    #[derive(Default)]
    pub(super) struct PromptControllerIvars {
        state: RefCell<PromptControllerState>,
    }

    #[derive(Default)]
    struct PromptControllerState {
        response: Option<oneshot::Sender<PromptOutcome>>,
        window: Option<Retained<NSWindow>>,
        field: Option<Retained<NSSecureTextField>>,
        finished: bool,
    }

    define_class!(
        // SAFETY:
        // - NSObject has no subclassing requirements relevant to this controller.
        // - The class is main-thread-only because all AppKit objects it owns are main-thread-only.
        #[unsafe(super = NSObject)]
        #[thread_kind = MainThreadOnly]
        #[ivars = PromptControllerIvars]
        pub(super) struct PromptController;

        // SAFETY: NSObjectProtocol has no extra safety requirements.
        unsafe impl NSObjectProtocol for PromptController {}

        impl PromptController {
            #[unsafe(method(allow:))]
            fn allow(&self, _sender: Option<&NSObject>) {
                let password = {
                    let state = self.ivars().state.borrow();
                    let Some(field) = state.field.as_ref() else {
                        return self.finish(PromptOutcome::Dismissed);
                    };
                    let password = field.stringValue().to_string();
                    field.setStringValue(ns_string!(""));
                    Zeroizing::new(password)
                };

                self.finish(PromptOutcome::Allowed(password));
            }

            #[unsafe(method(deny:))]
            fn deny(&self, _sender: Option<&NSObject>) {
                self.finish(PromptOutcome::Denied);
            }

            #[unsafe(method(dismiss:))]
            fn dismiss(&self, _sender: Option<&NSObject>) {
                self.finish(PromptOutcome::Dismissed);
            }
        }

        // SAFETY: NSWindowDelegate has no extra safety requirements.
        unsafe impl NSWindowDelegate for PromptController {
            #[unsafe(method(windowWillClose:))]
            fn window_will_close(&self, _notification: &NSNotification) {
                self.finish(PromptOutcome::Dismissed);
            }
        }
    );

    impl PromptController {
        pub(super) fn present(
            request: PromptRequest,
            mtm: MainThreadMarker,
        ) -> Retained<PromptController> {
            let controller = Self::new(request.response, mtm);
            let metadata =
                PromptMetadata::from_display(request.display.as_ref(), request.access_scope);
            let window = build_window(&controller, metadata, mtm);

            {
                let mut state = controller.ivars().state.borrow_mut();
                state.window = Some(window.clone());
            }

            window.makeKeyAndOrderFront(None);
            window.orderFrontRegardless();

            let app = NSApplication::sharedApplication(mtm);
            #[allow(deprecated)]
            app.activateIgnoringOtherApps(true);

            controller
        }

        fn new(response: oneshot::Sender<PromptOutcome>, mtm: MainThreadMarker) -> Retained<Self> {
            let this = Self::alloc(mtm).set_ivars(PromptControllerIvars {
                state: RefCell::new(PromptControllerState {
                    response: Some(response),
                    window: None,
                    field: None,
                    finished: false,
                }),
            });
            unsafe { msg_send![super(this), init] }
        }

        pub(super) fn finish(&self, outcome: PromptOutcome) {
            let (response, window) = {
                let mut state = self.ivars().state.borrow_mut();
                if state.finished {
                    return;
                }
                state.finished = true;

                if let Some(field) = state.field.as_ref() {
                    field.setStringValue(ns_string!(""));
                }

                (state.response.take(), state.window.clone())
            };

            if let Some(response) = response {
                let _ = response.send(outcome);
            }

            if let Some(window) = window {
                window.close();
            }
        }

        pub(super) fn is_finished(&self) -> bool {
            self.ivars().state.borrow().finished
        }

        fn set_field(&self, field: Retained<NSSecureTextField>) {
            self.ivars().state.borrow_mut().field = Some(field);
        }
    }

    fn build_window(
        controller: &Retained<PromptController>,
        metadata: PromptMetadata,
        mtm: MainThreadMarker,
    ) -> Retained<NSWindow> {
        let window = unsafe {
            NSWindow::initWithContentRect_styleMask_backing_defer(
                NSWindow::alloc(mtm),
                NSRect::new(
                    NSPoint::new(0.0, 0.0),
                    NSSize::new(WINDOW_WIDTH, WINDOW_HEIGHT),
                ),
                NSWindowStyleMask::Titled | NSWindowStyleMask::Closable,
                NSBackingStoreType::Buffered,
                false,
            )
        };

        unsafe { window.setReleasedWhenClosed(false) };
        window.setTitle(&NSString::from_str(&metadata.title));
        window.setLevel(NSFloatingWindowLevel);
        window.center();
        window.setDelegate(Some(ProtocolObject::from_ref(&**controller)));

        let content = window
            .contentView()
            .expect("prompt window must have content view");
        add_prompt_content(controller, &content, metadata, mtm);

        window
    }

    fn add_prompt_content(
        controller: &Retained<PromptController>,
        content: &NSView,
        metadata: PromptMetadata,
        mtm: MainThreadMarker,
    ) {
        let has_icon = metadata.preferred_icon_path.is_some() || metadata.executable_path.is_some();
        let text_x = if has_icon {
            PADDING + ICON_SIZE + 16.0
        } else {
            PADDING
        };
        let text_width = WINDOW_WIDTH - text_x - PADDING;

        if let Some(icon) = load_icon(&metadata) {
            let icon_view = NSImageView::imageViewWithImage(&icon, mtm);
            icon_view.setFrame(NSRect::new(
                NSPoint::new(PADDING, 124.0),
                NSSize::new(ICON_SIZE, ICON_SIZE),
            ));
            content.addSubview(&icon_view);
        }

        let intro = label(&metadata.intro, NSFont::systemFontOfSize(13.0), mtm);
        intro.setFrame(NSRect::new(
            NSPoint::new(text_x, 155.0),
            NSSize::new(text_width, 18.0),
        ));
        content.addSubview(&intro);

        let app_width = if metadata.modified_text.is_some() {
            text_width * 0.52
        } else {
            text_width
        };
        let app_name = label(&metadata.app_name, NSFont::boldSystemFontOfSize(13.0), mtm);
        app_name.setUsesSingleLineMode(true);
        app_name.setLineBreakMode(NSLineBreakMode::ByTruncatingTail);
        app_name.setFrame(NSRect::new(
            NSPoint::new(text_x, 130.0),
            NSSize::new(app_width, 18.0),
        ));
        content.addSubview(&app_name);

        if let Some(modified_text) = metadata.modified_text.as_ref() {
            let modified = label(modified_text, NSFont::systemFontOfSize(13.0), mtm);
            modified.setUsesSingleLineMode(true);
            modified.setLineBreakMode(NSLineBreakMode::ByTruncatingTail);
            modified.setFrame(NSRect::new(
                NSPoint::new(text_x + app_width + 6.0, 130.0),
                NSSize::new(text_width - app_width - 6.0, 18.0),
            ));
            content.addSubview(&modified);
        }

        let path = label(
            &metadata.executable_path_text,
            NSFont::monospacedSystemFontOfSize_weight(11.0, 0.0),
            mtm,
        );
        path.setUsesSingleLineMode(true);
        path.setLineBreakMode(NSLineBreakMode::ByTruncatingMiddle);
        path.setFrame(NSRect::new(
            NSPoint::new(text_x, 110.0),
            NSSize::new(text_width, 16.0),
        ));
        content.addSubview(&path);

        let field = NSSecureTextField::new(mtm);
        field.setFrame(NSRect::new(
            NSPoint::new(text_x, 70.0),
            NSSize::new(text_width, 24.0),
        ));
        content.addSubview(&field);
        controller.set_field(field.clone());

        let deny = unsafe {
            NSButton::buttonWithTitle_target_action(
                ns_string!("Deny"),
                Some(&**controller),
                Some(sel!(deny:)),
                mtm,
            )
        };
        deny.setFrame(NSRect::new(
            NSPoint::new(
                WINDOW_WIDTH - PADDING - (BUTTON_WIDTH * 2.0) - 10.0,
                PADDING,
            ),
            NSSize::new(BUTTON_WIDTH, BUTTON_HEIGHT),
        ));
        content.addSubview(&deny);

        let dismiss = unsafe {
            NSButton::buttonWithTitle_target_action(
                ns_string!(""),
                Some(&**controller),
                Some(sel!(dismiss:)),
                mtm,
            )
        };
        dismiss.setFrame(NSRect::new(
            NSPoint::new(-100.0, -100.0),
            NSSize::new(1.0, 1.0),
        ));
        dismiss.setKeyEquivalent(ns_string!("\u{1b}"));
        content.addSubview(&dismiss);

        let allow = unsafe {
            NSButton::buttonWithTitle_target_action(
                ns_string!("Allow"),
                Some(&**controller),
                Some(sel!(allow:)),
                mtm,
            )
        };
        allow.setFrame(NSRect::new(
            NSPoint::new(WINDOW_WIDTH - PADDING - BUTTON_WIDTH, PADDING),
            NSSize::new(BUTTON_WIDTH, BUTTON_HEIGHT),
        ));
        allow.setKeyEquivalent(ns_string!("\r"));
        content.addSubview(&allow);
    }

    fn label(text: &str, font: Retained<NSFont>, mtm: MainThreadMarker) -> Retained<NSTextField> {
        let label = NSTextField::labelWithString(&NSString::from_str(text), mtm);
        label.setFont(Some(&font));
        label
    }

    fn load_icon(metadata: &PromptMetadata) -> Option<Retained<NSImage>> {
        if metadata.access_scope == AccessScope::Settings {
            // SAFETY: NSImageNamePreferencesGeneral is a system-provided, immutable name.
            return NSImage::imageNamed(unsafe { NSImageNamePreferencesGeneral });
        }

        let workspace = NSWorkspace::sharedWorkspace();

        if let Some(icon_path) = metadata
            .preferred_icon_path
            .as_deref()
            .and_then(path_to_string)
        {
            return Some(workspace.iconForFile(&NSString::from_str(&icon_path)));
        }

        metadata.executable_path.as_ref()?;

        // SAFETY: UTTypeUnixExecutable is a system-provided, immutable UTI constant.
        let executable_type = unsafe { UTTypeUnixExecutable };
        Some(workspace.iconForContentType(executable_type))
    }
}

#[cfg(target_os = "macos")]
use appkit_prompt::PromptController;

#[cfg(any(
    target_os = "macos",
    all(target_os = "linux", any(feature = "gtk", feature = "qt"))
))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct PromptMetadata {
    access_scope: AccessScope,
    title: String,
    intro: String,
    app_name: String,
    modified_text: Option<String>,
    executable_path_text: String,
    executable_path: Option<PathBuf>,
    preferred_icon_path: Option<PathBuf>,
}

#[cfg(any(
    target_os = "macos",
    all(target_os = "linux", any(feature = "gtk", feature = "qt"))
))]
impl PromptMetadata {
    fn from_display(display: Option<&ProcessDisplay>, access_scope: AccessScope) -> Self {
        let intro = prompt_text(access_scope);
        let title = format!("monopass {} access requested", access_scope.as_str());
        let Some(display) = display else {
            return Self {
                access_scope,
                title,
                intro,
                app_name: "this app".to_owned(),
                modified_text: None,
                executable_path_text: "Unknown executable".to_owned(),
                executable_path: None,
                preferred_icon_path: None,
            };
        };

        Self {
            access_scope,
            title,
            intro,
            app_name: display.name.clone(),
            modified_text: modified_text(display.modified),
            executable_path_text: display.path.display().to_string(),
            executable_path: Some(display.path.clone()),
            preferred_icon_path: display.icon_path.clone(),
        }
    }
}

fn modified_text(modified: Option<std::time::SystemTime>) -> Option<String> {
    modified.map(|modified| {
        let modified: DateTime<Local> = modified.into();
        format!(
            "(Modified {})",
            modified.format("%e %b %Y").to_string().trim_start()
        )
    })
}

fn prompt_text(access_scope: AccessScope) -> String {
    format!(
        "Enter your password to allow Monopass {} access to this app:",
        access_scope.as_str()
    )
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "macos")]
    use std::path::PathBuf;
    #[cfg(target_os = "macos")]
    use std::time::{Duration, UNIX_EPOCH};

    use zeroize::{Zeroize, Zeroizing};

    use super::AccessScope;
    #[cfg(target_os = "macos")]
    use super::ProcessDisplay;

    #[test]
    #[cfg(target_os = "macos")]
    fn metadata_for_app_caller_uses_bundle_name_and_icon_path() {
        let metadata = super::PromptMetadata::from_display(
            Some(&ProcessDisplay {
                name: "Google Chrome".to_owned(),
                path: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome".into(),
                icon_path: Some("/Applications/Google Chrome.app".into()),
                modified: Some(UNIX_EPOCH + Duration::from_secs(1_781_225_600)),
            }),
            AccessScope::Items,
        );

        assert_eq!(
            "Enter your password to allow Monopass items access to this app:",
            metadata.intro
        );
        assert_eq!("Google Chrome", metadata.app_name);
        assert!(
            metadata
                .modified_text
                .is_some_and(|text| text.starts_with("(Modified "))
        );
        assert_eq!(
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            metadata.executable_path_text
        );
        assert_eq!(
            Some(PathBuf::from(
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
            )),
            metadata.executable_path
        );
        assert_eq!(
            Some(PathBuf::from("/Applications/Google Chrome.app")),
            metadata.preferred_icon_path
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn metadata_for_plain_executable_uses_default_icon() {
        let metadata = super::PromptMetadata::from_display(
            Some(&ProcessDisplay {
                name: "example-tool".to_owned(),
                path: "/usr/local/bin/example-tool".into(),
                icon_path: None,
                modified: None,
            }),
            AccessScope::Items,
        );

        assert_eq!("example-tool", metadata.app_name);
        assert_eq!(None, metadata.modified_text);
        assert_eq!("/usr/local/bin/example-tool", metadata.executable_path_text);
        assert_eq!(
            Some(PathBuf::from("/usr/local/bin/example-tool")),
            metadata.executable_path
        );
        assert_eq!(None, metadata.preferred_icon_path);
    }

    #[tokio::test]
    async fn prompt_password_with_allows_fake_prompt_injection() {
        let outcome = super::prompt_password_with(None, AccessScope::Items, |_, _| async {
            super::PromptOutcome::Allowed(Zeroizing::new("correct".to_owned()))
        })
        .await;
        let super::PromptOutcome::Allowed(password) = outcome else {
            panic!("expected allowed prompt outcome");
        };

        assert_eq!("correct", &*password);
    }

    #[test]
    fn prompt_text_without_process_display_is_generic() {
        assert_eq!(
            "Enter your password to allow Monopass items access to this app:",
            super::prompt_text(AccessScope::Items)
        );
    }

    #[test]
    fn settings_prompt_uses_scope_specific_title_and_copy() {
        let metadata = super::PromptMetadata::from_display(None, AccessScope::Settings);

        assert_eq!("monopass settings access requested", metadata.title);
        assert_eq!(AccessScope::Settings, metadata.access_scope);
        assert_eq!(
            "Enter your password to allow Monopass settings access to this app:",
            metadata.intro
        );
    }

    #[test]
    fn extracted_password_can_be_zeroized() {
        let mut password = Zeroizing::new("correct".to_owned());
        password.zeroize();

        assert!(password.is_empty());
    }
}
