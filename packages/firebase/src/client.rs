use std::time::{Duration, SystemTime};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{Error, FirebaseConfig, Session};

/// A credential of an identity provider, for [`FirebaseClient::sign_in_with_idp`].
#[derive(Clone, Debug)]
pub enum IdpCredential {
    /// An OpenID Connect ID token, for example from Google (`google.com`) or Apple (`apple.com`).
    IdToken {
        /// Firebase provider ID: `google.com`, `apple.com`, `microsoft.com`, …
        provider: String,
        /// The provider's ID token.
        id_token: String,
    },
    /// An OAuth access token, for example from GitHub (`github.com`).
    AccessToken {
        /// Firebase provider ID.
        provider: String,
        /// The provider's access token.
        access_token: String,
    },
}

/// What Firebase knows about the signed-in user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserInfo {
    /// Firebase uid.
    pub uid: String,
    /// Email address, if any.
    pub email: Option<String>,
    /// Whether the email address is verified.
    pub email_verified: bool,
    /// Display name, if any.
    pub display_name: Option<String>,
    /// Provider IDs linked to the user (`password`, `google.com`, …).
    pub providers: Vec<String>,
}

/// Firebase Authentication's REST API.
#[derive(Clone, Debug)]
pub struct FirebaseClient {
    config: FirebaseConfig,
    http: reqwest::Client,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignInAnswer {
    id_token: String,
    refresh_token: String,
    expires_in: String,
}

#[derive(Deserialize)]
struct RefreshAnswer {
    id_token: String,
    refresh_token: String,
    expires_in: String,
}

impl FirebaseClient {
    /// A client with a default HTTP client (30 s timeout).
    pub fn new(config: FirebaseConfig) -> Result<Self, Error> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(Error::from)?;
        Ok(Self { config, http })
    }

    /// A client with the application's own HTTP client.
    pub fn with_http(config: FirebaseConfig, http: reqwest::Client) -> Self {
        Self { config, http }
    }

    /// The configuration.
    pub fn config(&self) -> &FirebaseConfig {
        &self.config
    }

    /// Exchanges a custom token (from the auth hub) for a Firebase session.
    pub async fn sign_in_with_custom_token(&self, custom_token: &str) -> Result<Session, Error> {
        let answer: SignInAnswer = self
            .post(
                &self.config.identity_toolkit("signInWithCustomToken"),
                json!({ "token": custom_token, "returnSecureToken": true }),
            )
            .await?;
        session(answer.id_token, answer.refresh_token, &answer.expires_in)
    }

    /// Signs in with email and password. Prefer the browser handoff in apps, where Firebase's
    /// abuse protection and the person's password manager work best.
    pub async fn sign_in_with_password(
        &self,
        email: &str,
        password: &str,
    ) -> Result<Session, Error> {
        let answer: SignInAnswer = self
            .post(
                &self.config.identity_toolkit("signInWithPassword"),
                json!({ "email": email, "password": password, "returnSecureToken": true }),
            )
            .await?;
        session(answer.id_token, answer.refresh_token, &answer.expires_in)
    }

    /// Signs in with an identity provider's credential obtained by the app itself, for example
    /// Google's ID token from Android's Credential Manager.
    pub async fn sign_in_with_idp(&self, credential: &IdpCredential) -> Result<Session, Error> {
        let post_body = match credential {
            IdpCredential::IdToken { provider, id_token } => {
                form(&[("id_token", id_token), ("providerId", provider)])
            }
            IdpCredential::AccessToken {
                provider,
                access_token,
            } => form(&[("access_token", access_token), ("providerId", provider)]),
        };
        let answer: SignInAnswer = self
            .post(
                &self.config.identity_toolkit("signInWithIdp"),
                json!({ "postBody": post_body, "requestUri": "http://localhost", "returnSecureToken": true, "returnIdpCredential": true }),
            )
            .await?;
        session(answer.id_token, answer.refresh_token, &answer.expires_in)
    }

    /// Gets a new ID token. Fails with an error for which [`Error::ends_session`] is true when the
    /// refresh token was revoked or the user disabled or deleted.
    pub async fn refresh(&self, refresh_token: &str) -> Result<Session, Error> {
        let response = self
            .http
            .post(self.config.secure_token())
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
            ]))
            .send()
            .await?;
        let answer: RefreshAnswer = read(response).await?;
        session(answer.id_token, answer.refresh_token, &answer.expires_in)
    }

    /// The signed-in user's record.
    pub async fn lookup(&self, id_token: &str) -> Result<UserInfo, Error> {
        let answer: Value = self
            .post(
                &self.config.identity_toolkit("lookup"),
                json!({ "idToken": id_token }),
            )
            .await?;
        let user = answer
            .get("users")
            .and_then(|u| u.get(0))
            .ok_or(Error::SignedOut)?;
        let text = |name: &str| user.get(name).and_then(Value::as_str).map(str::to_owned);
        Ok(UserInfo {
            uid: text("localId")
                .ok_or_else(|| Error::InvalidResponse("user without localId".into()))?,
            email: text("email"),
            email_verified: user.get("emailVerified").and_then(Value::as_bool) == Some(true),
            display_name: text("displayName"),
            providers: user
                .get("providerUserInfo")
                .and_then(Value::as_array)
                .map(|list| {
                    list.iter()
                        .filter_map(|p| p.get("providerId").and_then(Value::as_str))
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default(),
        })
    }

    /// Asks Firebase to mail a password-reset link. Succeeds also for unknown addresses when the
    /// project protects against email enumeration.
    pub async fn send_password_reset(&self, email: &str) -> Result<(), Error> {
        let _: Value = self
            .post(
                &self.config.identity_toolkit("sendOobCode"),
                json!({ "requestType": "PASSWORD_RESET", "email": email }),
            )
            .await?;
        Ok(())
    }

    /// Deletes the signed-in user. Firebase requires a recent sign-in.
    pub async fn delete_account(&self, id_token: &str) -> Result<(), Error> {
        let _: Value = self
            .post(
                &self.config.identity_toolkit("delete"),
                json!({ "idToken": id_token }),
            )
            .await?;
        Ok(())
    }

    async fn post<T: for<'de> Deserialize<'de>>(&self, url: &str, body: Value) -> Result<T, Error> {
        let response = self.http.post(url).json(&body).send().await?;
        read(response).await
    }
}

async fn read<T: for<'de> Deserialize<'de>>(response: reqwest::Response) -> Result<T, Error> {
    let status = response.status();
    let body = response.bytes().await?;
    if !status.is_success() {
        let code = serde_json::from_slice::<Value>(&body)
            .ok()
            .and_then(|v| {
                v.pointer("/error/message")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| format!("HTTP {}", status.as_u16()));
        // "TOO_MANY_ATTEMPTS_TRY_LATER : …" → keep the code, drop Google's explanation.
        let code = code.split(" : ").next().unwrap_or(&code).trim().to_owned();
        return Err(if status.is_server_error() {
            Error::Network(code)
        } else {
            Error::Firebase(code)
        });
    }
    serde_json::from_slice(&body).map_err(|e| Error::InvalidResponse(e.to_string()))
}

fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Builds a session; the uid is read from the ID token Firebase just gave us over TLS.
pub(crate) fn session(
    id_token: String,
    refresh_token: String,
    expires_in: &str,
) -> Result<Session, Error> {
    let seconds: u64 = expires_in
        .parse()
        .map_err(|_| Error::InvalidResponse("expiresIn is not a number".into()))?;
    let uid = uid_of(&id_token)?;
    Ok(Session::new(
        uid,
        id_token,
        refresh_token,
        SystemTime::now() + Duration::from_secs(seconds),
    ))
}

pub(crate) fn uid_of(id_token: &str) -> Result<String, Error> {
    let payload = id_token
        .split('.')
        .nth(1)
        .and_then(|segment| URL_SAFE_NO_PAD.decode(segment).ok())
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .ok_or_else(|| Error::InvalidResponse("the ID token is unreadable".into()))?;
    payload
        .get("user_id")
        .or_else(|| payload.get("sub"))
        .and_then(Value::as_str)
        .filter(|uid| !uid.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| Error::InvalidResponse("the ID token has no uid".into()))
}
