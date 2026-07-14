# Linux GUI Unlock Testing Next Steps

This note summarizes the current GTK and Qt Linux GUI unlock test status, the
issues encountered while testing, and the remaining work needed before the Linux
GUI backends can be considered fully verified.

## Verified So Far

- The default, non-GUI test suite has passed with:

  ```sh
  cargo test --locked
  ```

- The GTK GUI unlock integration tests pass under Xvfb with:

  ```sh
  xvfb-run -a cargo test --locked --no-default-features --features gtk \
    --test gui_unlock_linux -- --ignored --nocapture
  ```

- The Qt GUI unlock integration tests pass under Xvfb with the Qt 5 SDK
  selected:

  ```sh
  QMAKE=qmake QT_SELECT=qt5 xvfb-run -a cargo test --locked \
    --no-default-features --features qt --test gui_unlock_linux \
    -- --ignored --nocapture
  ```

- The Qt release build passes with:

  ```sh
  QMAKE=qmake QT_SELECT=qt5 cargo build --release --locked \
    --no-default-features --features qt
  ```

These Xvfb tests cover successful GUI unlock, cancel, wrong password rejection,
and concurrent prompt windows for both GTK and Qt.

## Issues Found And Fixed

- Xvfb initially failed before the tests could run because the local X socket
  directory was not usable. After fixing the environment, `xvfb-run` could
  launch clients normally.
- Qt selected GNOME's GTK platform integration when desktop-session variables
  were inherited under the forced XCB backend. That caused the Qt agent to exit
  after binding the socket with `Gtk-WARNING **: cannot open display`. The Qt
  agent now removes those desktop integration variables before Qt initializes.
- Qt prompt windows were originally created as children of a hidden root QML
  window, so no visible prompt was mapped. Prompts are now top-level windows.
- Closing the final Qt prompt caused the QML dispatcher loop to exit, which
  made later GUI unlock attempts fail immediately. The dispatcher now keeps a
  persistent offscreen root window alive.
- The Qt fallback icon used unsupported `image://theme/...` URLs. The Qt backend
  now resolves generic terminal icons from XDG icon locations and passes QML
  normal `file://` URLs.
- The shared Xvfb test helper needed focus/click handling for Qt Quick text
  fields and Escape handling for cancel. GTK now handles Escape through a key
  controller too.

## Still Untested

- Real X11 desktop runtime behavior for GTK and Qt.
- Real Wayland desktop runtime behavior while the agent forces GTK/Qt onto the
  X11/XCB backend.
- Visual confirmation on a real desktop that the prompt shows the requesting
  application name, icon, modified date, and executable path as intended.
- CI execution of the ignored GUI tests. They currently pass locally under
  Xvfb, but CI still needs the right packages and display setup before they
  should be enabled automatically.

## Recommended Next Steps

1. Run both ignored GUI test commands in a real desktop session, not only under
   Xvfb.
2. Add a CI job that installs `xvfb`, `xdotool`, GTK4 development packages, and
   the Qt 5 development/QML runtime packages, then runs the ignored GTK and Qt
   GUI tests.
3. Keep the GUI tests ignored by default until CI has a stable graphical
   environment. Once the CI job is reliable, make that job opt into the ignored
   tests explicitly.
