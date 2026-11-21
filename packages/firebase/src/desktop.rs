//! Desktop sign-in through the system browser (functional design, flow F4).
//!
//! 1. Opens a loopback listener with a PKCE pair (`passkey-desktop`).
//! 2. Lets the app open the system browser on the hub's sign-in page.
//! 3. The person signs in there with any method and approves; the page sends the browser back to
//!    the loopback address with a single-use code.
//! 4. Redeems the code at the hub for a custom token, and the custom token at Firebase for a
//!    session that belongs to the app.

use passkey_desktop::{CancelHandle, Handoff, HandoffConfig};

use crate::{Error, FirebaseClient, HubClient, Session};

/// A started desktop sign-in. Call [`authorize_url`](Self::authorize_url), open it in the system
/// browser, then [`finish`](Self::finish).
#[derive(Debug)]
pub struct DesktopSignIn {
    handoff: Handoff,
}

impl DesktopSignIn {
    /// Opens the loopback listener.
    pub fn start(config: HandoffConfig) -> Result<Self, Error> {
        Ok(Self {
            handoff: Handoff::start(config).map_err(Error::Handoff)?,
        })
    }

    /// The page to open in the system browser: `page_url` with `challenge`, `port` and `state`.
    pub fn authorize_url(&self, page_url: &str) -> String {
        self.handoff.authorize_url(page_url)
    }

    /// Cancels [`finish`](Self::finish) from elsewhere (for example a "Cancel" button).
    pub fn cancel_handle(&self) -> CancelHandle {
        self.handoff.cancel_handle()
    }

    /// Waits for the browser, then exchanges the code at the hub and the custom token at Firebase.
    pub async fn finish(
        self,
        hub: &HubClient,
        firebase: &FirebaseClient,
    ) -> Result<Session, Error> {
        let handoff = self.handoff;
        let grant = tokio::task::spawn_blocking(move || handoff.wait())
            .await
            .map_err(|e| Error::Configuration(format!("the handoff task stopped: {e}")))?
            .map_err(Error::Handoff)?;
        let custom = hub
            .exchange_handoff(&grant.code, &grant.code_verifier)
            .await?;
        firebase.sign_in_with_custom_token(&custom.0).await
    }
}

/// Runs the whole desktop sign-in. `open_browser` receives the URL to open in the system browser
/// (in Tauri: `tauri_plugin_opener::open_url`).
pub async fn sign_in<F>(
    hub: &HubClient,
    firebase: &FirebaseClient,
    page_url: &str,
    config: HandoffConfig,
    open_browser: F,
) -> Result<Session, Error>
where
    F: FnOnce(&str) -> Result<(), String>,
{
    let sign_in = DesktopSignIn::start(config)?;
    open_browser(&sign_in.authorize_url(page_url)).map_err(Error::Configuration)?;
    sign_in.finish(hub, firebase).await
}
