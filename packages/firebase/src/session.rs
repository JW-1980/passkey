use std::fmt;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime};

use tokio::sync::Mutex;

use crate::{Error, FirebaseClient};

/// A Firebase session: the user, a short-lived ID token and the long-lived refresh token.
#[derive(Clone, PartialEq, Eq)]
pub struct Session {
    /// Firebase uid.
    pub uid: String,
    /// The ID token (about one hour).
    pub id_token: String,
    /// The refresh token. Store it only in the operating system's credential store.
    pub refresh_token: String,
    /// When the ID token expires.
    pub expires_at: SystemTime,
}

impl Session {
    /// A session from its parts.
    pub fn new(
        uid: String,
        id_token: String,
        refresh_token: String,
        expires_at: SystemTime,
    ) -> Self {
        Self {
            uid,
            id_token,
            refresh_token,
            expires_at,
        }
    }

    /// True when the ID token expires within `margin`.
    pub fn expires_within(&self, margin: Duration) -> bool {
        self.expires_at
            .duration_since(SystemTime::now())
            .map_or(true, |left| left <= margin)
    }
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("uid", &self.uid)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// Where the refresh token lives between runs of the app. A desktop app implements it on the
/// operating system's credential store (Windows Credential Manager, Keychain, Secret Service);
/// Android on the Keystore.
pub trait TokenStore: Send + Sync {
    /// The stored refresh token, if any.
    fn load(&self) -> Result<Option<String>, String>;
    /// Stores the refresh token, replacing an older one.
    fn save(&self, refresh_token: &str) -> Result<(), String>;
    /// Forgets the refresh token.
    fn clear(&self) -> Result<(), String>;
}

/// A [`TokenStore`] that forgets everything when the app stops.
#[derive(Debug, Default)]
pub struct MemoryTokenStore(StdMutex<Option<String>>);

impl TokenStore for MemoryTokenStore {
    fn load(&self) -> Result<Option<String>, String> {
        Ok(self.0.lock().map_err(|e| e.to_string())?.clone())
    }

    fn save(&self, refresh_token: &str) -> Result<(), String> {
        *self.0.lock().map_err(|e| e.to_string())? = Some(refresh_token.to_owned());
        Ok(())
    }

    fn clear(&self) -> Result<(), String> {
        *self.0.lock().map_err(|e| e.to_string())? = None;
        Ok(())
    }
}

/// Keeps the app's Firebase session and a fresh ID token.
///
/// - [`id_token`](Self::id_token) refreshes when less than the margin (default 5 minutes) is left;
///   concurrent callers wait for one refresh.
/// - A refresh that Firebase refuses because the session ended (revoked, disabled, deleted)
///   signs out: the stored refresh token is removed and [`Error::SignedOut`] is returned.
/// - A network failure keeps the session: the caller may retry.
pub struct SessionManager {
    client: FirebaseClient,
    store: Arc<dyn TokenStore>,
    margin: Duration,
    state: Mutex<Option<Session>>,
}

impl fmt::Debug for SessionManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionManager")
            .field("margin", &self.margin)
            .finish_non_exhaustive()
    }
}

impl SessionManager {
    /// A manager without a session.
    pub fn new(client: FirebaseClient, store: Arc<dyn TokenStore>) -> Self {
        Self {
            client,
            store,
            margin: Duration::from_secs(300),
            state: Mutex::new(None),
        }
    }

    /// Refresh when less than this is left (at most 30 minutes).
    pub fn with_margin(mut self, margin: Duration) -> Self {
        self.margin = margin.min(Duration::from_secs(1800));
        self
    }

    /// The Firebase client.
    pub fn client(&self) -> &FirebaseClient {
        &self.client
    }

    /// Restores the session from the stored refresh token. `Ok(None)` when there is none or it
    /// no longer works (then it is removed).
    pub async fn restore(&self) -> Result<Option<String>, Error> {
        let Some(refresh_token) = self.store.load().map_err(Error::Configuration)? else {
            return Ok(None);
        };
        let mut state = self.state.lock().await;
        match self.client.refresh(&refresh_token).await {
            Ok(session) => {
                let uid = session.uid.clone();
                self.store
                    .save(&session.refresh_token)
                    .map_err(Error::Configuration)?;
                *state = Some(session);
                Ok(Some(uid))
            }
            Err(error) if error.ends_session() => {
                *state = None;
                self.store.clear().map_err(Error::Configuration)?;
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    /// Takes over a session after a sign-in and stores its refresh token.
    pub async fn set(&self, session: Session) -> Result<(), Error> {
        self.store
            .save(&session.refresh_token)
            .map_err(Error::Configuration)?;
        *self.state.lock().await = Some(session);
        Ok(())
    }

    /// The signed-in uid, if any.
    pub async fn uid(&self) -> Option<String> {
        self.state.lock().await.as_ref().map(|s| s.uid.clone())
    }

    /// A valid ID token, refreshed when needed.
    pub async fn id_token(&self) -> Result<String, Error> {
        self.fresh(false).await
    }

    /// A newly issued ID token, also when the current one is still valid (for example after the
    /// user's claims changed).
    pub async fn force_refresh(&self) -> Result<String, Error> {
        self.fresh(true).await
    }

    /// Ends the session in this app and forgets the refresh token. (Revoking the user's sessions
    /// everywhere is an admin operation of the backend.)
    pub async fn sign_out(&self) -> Result<(), Error> {
        *self.state.lock().await = None;
        self.store.clear().map_err(Error::Configuration)
    }

    async fn fresh(&self, force: bool) -> Result<String, Error> {
        let mut state = self.state.lock().await;
        let session = state.as_ref().ok_or(Error::SignedOut)?;
        if !force && !session.expires_within(self.margin) {
            return Ok(session.id_token.clone());
        }
        match self.client.refresh(&session.refresh_token).await {
            Ok(fresh) => {
                let token = fresh.id_token.clone();
                self.store
                    .save(&fresh.refresh_token)
                    .map_err(Error::Configuration)?;
                *state = Some(fresh);
                Ok(token)
            }
            Err(error) if error.ends_session() => {
                *state = None;
                self.store.clear().map_err(Error::Configuration)?;
                Err(Error::SignedOut)
            }
            Err(error) => Err(error),
        }
    }
}
