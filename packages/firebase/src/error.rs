use std::fmt;

/// Why a Firebase or hub operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The crate is set up wrongly (project ID, emulator, URL). Never caused by the person.
    Configuration(String),
    /// No answer was received (offline, DNS, TLS, timeout).
    Network(String),
    /// Firebase refused, with its error code, for example `USER_DISABLED`, `INVALID_CUSTOM_TOKEN`,
    /// `INVALID_LOGIN_CREDENTIALS`, `TOKEN_EXPIRED`.
    Firebase(String),
    /// The auth hub refused, with the HTTP status and its error code.
    Hub {
        /// HTTP status.
        status: u16,
        /// The hub's code, for example `invalid_passkey` or `invalid_handoff`.
        code: String,
    },
    /// An answer this crate cannot read.
    InvalidResponse(String),
    /// Nobody is signed in, or the session ended (revoked, disabled, deleted).
    SignedOut,
    /// An ID token did not verify (backends). The reason is for logs, not for people.
    InvalidToken(&'static str),
    /// Google's public keys could not be obtained; nothing was decided.
    Unavailable(String),
    /// The desktop handoff did not complete.
    #[cfg(feature = "desktop")]
    Handoff(passkey_desktop::HandoffError),
}

impl Error {
    /// True when the Firebase session cannot continue and the person must sign in again.
    pub fn ends_session(&self) -> bool {
        match self {
            Self::SignedOut => true,
            Self::Firebase(code) => matches!(
                code.split(':').next().unwrap_or("").trim(),
                "TOKEN_EXPIRED"
                    | "USER_DISABLED"
                    | "USER_NOT_FOUND"
                    | "INVALID_REFRESH_TOKEN"
                    | "INVALID_ID_TOKEN"
                    | "CREDENTIAL_TOO_OLD_LOGIN_AGAIN"
            ),
            _ => false,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(m) => write!(f, "configuration error: {m}"),
            Self::Network(m) => write!(f, "network error: {m}"),
            Self::Firebase(code) => write!(f, "Firebase refused: {code}"),
            Self::Hub { status, code } => write!(f, "sign-in service refused ({status}): {code}"),
            Self::InvalidResponse(m) => write!(f, "unreadable answer: {m}"),
            Self::SignedOut => f.write_str("not signed in"),
            Self::InvalidToken(reason) => write!(f, "invalid ID token: {reason}"),
            Self::Unavailable(m) => write!(f, "sign-in keys unavailable: {m}"),
            #[cfg(feature = "desktop")]
            Self::Handoff(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<reqwest::Error> for Error {
    fn from(error: reqwest::Error) -> Self {
        // Never include the URL: it carries the API key.
        Self::Network(error.without_url().to_string())
    }
}
