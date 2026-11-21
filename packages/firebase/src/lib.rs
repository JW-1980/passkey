//! Firebase Authentication for Rust: desktop apps (Tauri), Android apps (Tauri) and backends.
//!
//! Firebase has no Rust SDK; this crate speaks Firebase's public REST API and adds what the
//! standard sign-in component of `docs/functional-design.md` needs:
//!
//! - [`FirebaseClient`]: sign in with a custom token, email and password, or an identity
//!   provider's credential; refresh; look up and delete the signed-in user; password reset mail.
//! - [`SessionManager`]: keeps a [`Session`] and refreshes its ID token before it expires; a
//!   revoked, disabled or deleted user becomes signed out.
//! - [`HubClient`]: the auth hub's routes that apps call themselves (passkey sign-in with a native
//!   authenticator, the handoff exchange).
//! - [`verify::IdTokenVerifier`] (feature `verify`): local verification of ID tokens for Rust
//!   backends, with the same rules as the PHP verifier.
//! - [`desktop::sign_in`] (feature `desktop`): sign-in through the system browser with any method,
//!   ending in a Firebase session in the app.
//!
//! Every network call is async (reqwest with rustls), so the crate works the same on Windows,
//! macOS, Linux and Android.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod client;
mod config;
mod error;
mod hub;
mod session;

#[cfg(feature = "desktop")]
pub mod desktop;
#[cfg(feature = "verify")]
pub mod verify;

pub use client::{FirebaseClient, IdpCredential, UserInfo};
pub use config::FirebaseConfig;
pub use error::Error;
pub use hub::{CustomToken, HubClient};
pub use session::{MemoryTokenStore, Session, SessionManager, TokenStore};

/// Firebase reserves the prefix `demo-` for projects that exist only in the emulator suite.
pub fn is_demo_project(project_id: &str) -> bool {
    is_valid_project_id(project_id) && project_id.starts_with("demo-")
}

/// 6 to 30 characters: lowercase letters, digits and hyphens, starting with a letter.
pub fn is_valid_project_id(project_id: &str) -> bool {
    let bytes = project_id.as_bytes();
    (6..=30).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes[bytes.len() - 1] != b'-'
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}
