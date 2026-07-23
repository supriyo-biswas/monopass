.PHONY: build build-gtk build-qt build-release-gtk build-release-qt test-gui-gtk test-gui-qt test-gui

build:
	cargo build --locked

build-gtk:
	cargo build --locked --no-default-features --features gtk

build-qt:
	QMAKE=qmake QT_SELECT=qt5 cargo build --locked --no-default-features --features qt

build-release-gtk:
	cargo build --locked --release --no-default-features --features gtk

build-release-qt:
	QMAKE=qmake QT_SELECT=qt5 cargo build --locked --release --no-default-features --features qt

test-gui-gtk:
	xvfb-run -a cargo test --locked --no-default-features --features gtk --test gui_unlock_linux -- --ignored --test-threads=1

test-gui-qt:
	QMAKE=qmake QT_SELECT=qt5 xvfb-run -a cargo test --locked --no-default-features --features qt --test gui_unlock_linux -- --ignored --test-threads=1

test-gui: test-gui-gtk test-gui-qt
