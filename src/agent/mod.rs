mod auth;
mod controller;
#[cfg(any(test, all(target_os = "linux", any(feature = "gtk", feature = "qt"))))]
mod desktop;
mod error;
mod export;
#[cfg(any(
    target_os = "macos",
    all(target_os = "linux", any(feature = "gtk", feature = "qt"))
))]
mod gui_auth;
mod import;
mod models;
pub(crate) mod process;
mod server;
mod state;

pub use auth::PeerConnectInfo;
#[cfg(all(target_os = "linux", any(feature = "gtk", feature = "qt")))]
pub(crate) use desktop::initialize_gui_application_catalog;
#[cfg(any(
    target_os = "macos",
    all(target_os = "linux", any(feature = "gtk", feature = "qt"))
))]
pub(crate) use gui_auth::{install_prompt_dispatcher, run_prompt_dispatcher};
pub use server::Server;
