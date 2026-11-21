use std::fmt;
use std::time::Duration;

use serde_json::{json, Value};

use crate::Error;

/// A custom token from the hub, to exchange at Firebase. A secret until used.
#[derive(Clone, PartialEq, Eq)]
pub struct CustomToken(pub String);

impl fmt::Debug for CustomToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CustomToken(<redacted>)")
    }
}

/// The auth hub's routes that apps call themselves (`docs/protocol.md`, functional design §9).
#[derive(Clone, Debug)]
pub struct HubClient {
    base: String,
    http: reqwest::Client,
}

impl HubClient {
    /// `base_url` is the hub's passkey base, for example `https://login.example.nl/passkey`. Must
    /// be `https://`, or `http://` on a loopback host for development.
    pub fn new(base_url: &str) -> Result<Self, Error> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(Error::from)?;
        Self::with_http(base_url, http)
    }

    /// With the application's own HTTP client.
    pub fn with_http(base_url: &str, http: reqwest::Client) -> Result<Self, Error> {
        let base = base_url.trim_end_matches('/').to_owned();
        let secure = base.starts_with("https://")
            || ["http://127.0.0.1", "http://localhost", "http://[::1]"]
                .iter()
                .any(|p| base.starts_with(p));
        if !secure {
            return Err(Error::Configuration(
                "the hub URL must use https (http only on a loopback host)".into(),
            ));
        }
        Ok(Self { base, http })
    }

    /// Step 6 of the desktop handoff: redeems the code with the PKCE verifier for a custom token.
    pub async fn exchange_handoff(
        &self,
        code: &str,
        code_verifier: &str,
    ) -> Result<CustomToken, Error> {
        let answer = self
            .call(
                "handoff/exchange",
                None,
                Some(json!({ "code": code, "code_verifier": code_verifier })),
            )
            .await?;
        custom_token(&answer)
    }

    /// Starts a passkey sign-in; give `publicKey` of the answer to the platform authenticator
    /// (Android Credential Manager) and keep `ceremony` for [`finish_sign_in`](Self::finish_sign_in).
    pub async fn begin_sign_in(&self) -> Result<Value, Error> {
        self.call("login/options", None, None).await
    }

    /// Finishes a passkey sign-in with the authenticator's `AuthenticationResponseJSON`.
    pub async fn finish_sign_in(
        &self,
        ceremony: &str,
        credential: Value,
    ) -> Result<CustomToken, Error> {
        let answer = self
            .call(
                "login/verify",
                None,
                Some(json!({ "ceremony": ceremony, "credential": credential })),
            )
            .await?;
        custom_token(&answer)
    }

    /// Starts registering a passkey for the signed-in Firebase user (a recent ID token).
    pub async fn begin_registration(&self, id_token: &str) -> Result<Value, Error> {
        self.call("register/options", Some(id_token), None).await
    }

    /// Finishes registering with the authenticator's `RegistrationResponseJSON`. Returns the
    /// passkey summary.
    pub async fn finish_registration(
        &self,
        id_token: &str,
        ceremony: &str,
        credential: Value,
        name: Option<&str>,
    ) -> Result<Value, Error> {
        let mut body = json!({ "ceremony": ceremony, "credential": credential });
        if let Some(name) = name {
            body["name"] = json!(name);
        }
        let answer = self
            .call("register/verify", Some(id_token), Some(body))
            .await?;
        answer
            .get("passkey")
            .cloned()
            .ok_or_else(|| Error::InvalidResponse("no passkey in the answer".into()))
    }

    async fn call(
        &self,
        route: &str,
        bearer: Option<&str>,
        body: Option<Value>,
    ) -> Result<Value, Error> {
        let mut request = self
            .http
            .post(format!("{}/{route}", self.base))
            .header("Accept", "application/json")
            .json(&body.unwrap_or_else(|| json!({})));
        if let Some(token) = bearer {
            request = request.bearer_auth(token);
        }
        let response = request.send().await?;
        let status = response.status();
        let value: Value = response
            .json()
            .await
            .map_err(|e| Error::InvalidResponse(e.without_url().to_string()))?;
        if !status.is_success() {
            return Err(Error::Hub {
                status: status.as_u16(),
                code: value
                    .pointer("/error/code")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_owned(),
            });
        }
        Ok(value)
    }
}

fn custom_token(answer: &Value) -> Result<CustomToken, Error> {
    answer
        .pointer("/firebase/customToken")
        .and_then(Value::as_str)
        .filter(|t| t.split('.').count() == 3)
        .map(|t| CustomToken(t.to_owned()))
        .ok_or_else(|| Error::InvalidResponse("no custom token in the answer".into()))
}
