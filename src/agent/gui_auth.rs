use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::Duration;

use chrono::{DateTime, Local};
use tokio::sync::oneshot;
use zeroize::Zeroizing;

use super::process::ProcessDisplay;

pub(crate) type PromptRequestReceiver = mpsc::Receiver<PromptRequest>;

static PROMPT_DISPATCHER: OnceLock<PromptRequestSender> = OnceLock::new();

#[derive(Clone)]
struct PromptRequestSender(mpsc::Sender<PromptRequest>);

pub(crate) struct PromptRequest {
    display: Option<ProcessDisplay>,
    response: oneshot::Sender<Option<Zeroizing<String>>>,
}

pub(crate) fn install_prompt_dispatcher() -> PromptRequestReceiver {
    let (sender, receiver) = mpsc::channel();
    let _ = PROMPT_DISPATCHER.set(PromptRequestSender(sender));
    receiver
}

pub(crate) async fn prompt_password(display: Option<ProcessDisplay>) -> Option<Zeroizing<String>> {
    prompt_password_with(display, dispatch_prompt).await
}

pub(crate) async fn prompt_password_with<F, Fut>(
    display: Option<ProcessDisplay>,
    prompt: F,
) -> Option<Zeroizing<String>>
where
    F: FnOnce(Option<ProcessDisplay>) -> Fut,
    Fut: std::future::Future<Output = Option<Zeroizing<String>>>,
{
    prompt(display).await
}

async fn dispatch_prompt(display: Option<ProcessDisplay>) -> Option<Zeroizing<String>> {
    let sender = PROMPT_DISPATCHER.get()?.clone();
    let (response, receiver) = oneshot::channel();
    sender.0.send(PromptRequest { display, response }).ok()?;
    receiver.await.ok().flatten()
}

pub(crate) fn run_prompt_dispatcher<T>(receiver: PromptRequestReceiver, server: &JoinHandle<T>) {
    initialize_appkit();
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

        std::thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(not(target_os = "macos"))]
fn run_prompt_dispatcher_inner<T>(receiver: PromptRequestReceiver, server: &JoinHandle<T>) {
    loop {
        match receiver.recv_timeout(Duration::from_millis(250)) {
            Ok(request) => {
                let _ = request.response.send(None);
            }
            Err(mpsc::RecvTimeoutError::Timeout) if server.is_finished() => break,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
}

#[cfg(target_os = "macos")]
fn initialize_appkit() {
    use objc2_app_kit::{NSApplication, NSApplicationActivationPolicy};
    use objc2_foundation::MainThreadMarker;

    let mtm = MainThreadMarker::new().expect("AppKit prompt dispatcher must run on main thread");
    let app = NSApplication::sharedApplication(mtm);
    app.setActivationPolicy(NSApplicationActivationPolicy::Accessory);
    app.finishLaunching();
}

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
        prompt.finish(None);
    }
}

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
        NSImageView, NSLineBreakMode, NSSecureTextField, NSTextField, NSView, NSWindow,
        NSWindowDelegate, NSWindowStyleMask, NSWorkspace,
    };
    use objc2_foundation::{
        MainThreadMarker, NSNotification, NSObject, NSObjectProtocol, NSPoint, NSRect, NSSize,
        NSString, ns_string,
    };
    use tokio::sync::oneshot;
    use zeroize::Zeroizing;

    use super::{PromptMetadata, PromptRequest, path_to_string};

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
        response: Option<oneshot::Sender<Option<Zeroizing<String>>>>,
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
                        return self.finish(None);
                    };
                    let password = field.stringValue().to_string();
                    field.setStringValue(ns_string!(""));
                    Zeroizing::new(password)
                };

                self.finish(Some(password));
            }

            #[unsafe(method(deny:))]
            fn deny(&self, _sender: Option<&NSObject>) {
                self.finish(None);
            }
        }

        // SAFETY: NSWindowDelegate has no extra safety requirements.
        unsafe impl NSWindowDelegate for PromptController {
            #[unsafe(method(windowWillClose:))]
            fn window_will_close(&self, _notification: &NSNotification) {
                self.finish(None);
            }
        }
    );

    impl PromptController {
        pub(super) fn present(
            request: PromptRequest,
            mtm: MainThreadMarker,
        ) -> Retained<PromptController> {
            let controller = Self::new(request.response, mtm);
            let metadata = PromptMetadata::from_display(request.display.as_ref());
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

        fn new(
            response: oneshot::Sender<Option<Zeroizing<String>>>,
            mtm: MainThreadMarker,
        ) -> Retained<Self> {
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

        pub(super) fn finish(&self, password: Option<Zeroizing<String>>) {
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
                let _ = response.send(password);
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
        window.setTitle(ns_string!("monopass access requested"));
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
        deny.setKeyEquivalent(ns_string!("\u{1b}"));
        content.addSubview(&deny);

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
        let path = metadata
            .preferred_icon_path
            .as_deref()
            .or(metadata.executable_path.as_deref())?;
        let icon_path = path_to_string(path)?;
        let icon_path = NSString::from_str(&icon_path);
        Some(NSWorkspace::sharedWorkspace().iconForFile(&icon_path))
    }
}

#[cfg(target_os = "macos")]
use appkit_prompt::PromptController;

#[derive(Debug, Clone, PartialEq, Eq)]
struct PromptMetadata {
    intro: String,
    app_name: String,
    modified_text: Option<String>,
    executable_path_text: String,
    executable_path: Option<PathBuf>,
    preferred_icon_path: Option<PathBuf>,
}

impl PromptMetadata {
    fn from_display(display: Option<&ProcessDisplay>) -> Self {
        let intro = prompt_text(None);
        let Some(display) = display else {
            return Self {
                intro,
                app_name: "this app".to_owned(),
                modified_text: None,
                executable_path_text: "Unknown executable".to_owned(),
                executable_path: None,
                preferred_icon_path: None,
            };
        };

        Self {
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

fn prompt_text(display: Option<&ProcessDisplay>) -> String {
    let Some(display) = display else {
        return "Enter your password to allow password access to this app:".to_owned();
    };

    let modified = modified_text(display.modified)
        .map(|modified| format!(" {modified}"))
        .unwrap_or_default();

    format!(
        "Enter your password to allow password access to this app:\n\n{}{}\n{}",
        display.name,
        modified,
        display.path.display()
    )
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::{Duration, UNIX_EPOCH};

    use zeroize::{Zeroize, Zeroizing};

    use super::ProcessDisplay;

    #[test]
    fn metadata_for_app_caller_uses_bundle_name_and_icon_path() {
        let metadata = super::PromptMetadata::from_display(Some(&ProcessDisplay {
            name: "Google Chrome".to_owned(),
            path: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome".into(),
            icon_path: Some("/Applications/Google Chrome.app".into()),
            modified: Some(UNIX_EPOCH + Duration::from_secs(1_781_225_600)),
        }));

        assert_eq!(
            "Enter your password to allow password access to this app:",
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
    fn metadata_for_plain_executable_uses_default_icon() {
        let metadata = super::PromptMetadata::from_display(Some(&ProcessDisplay {
            name: "example-tool".to_owned(),
            path: "/usr/local/bin/example-tool".into(),
            icon_path: None,
            modified: None,
        }));

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
        let password = super::prompt_password_with(None, |_| async {
            Some(Zeroizing::new("correct".to_owned()))
        })
        .await
        .unwrap();

        assert_eq!("correct", &*password);
    }

    #[test]
    fn prompt_text_without_process_display_is_generic() {
        assert_eq!(
            "Enter your password to allow password access to this app:",
            super::prompt_text(None)
        );
    }

    #[test]
    fn extracted_password_can_be_zeroized() {
        let mut password = Zeroizing::new("correct".to_owned());
        password.zeroize();

        assert!(password.is_empty());
    }
}
