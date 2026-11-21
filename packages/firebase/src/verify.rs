//! Local verification of Firebase ID tokens, for Rust backends (Axum, a Tauri app's own server).
//!
//! Same rules as the PHP `IdTokenVerifier`: RS256 with a current Google key; `iss` =
//! `https://securetoken.google.com/<project>`; `aud` = `<project>`; `exp` in the future; `iat` and
//! `auth_time` not in the future; `sub` 1–128 characters; 60 seconds of clock skew. Revocation is
//! not checked (it needs an admin call to Google).

use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{Algorithm, DecodingKey};
use serde_json::{Map, Value};
use tokio::sync::Mutex;

use crate::{is_demo_project, is_valid_project_id, Error};

/// Google's public keys for Firebase ID tokens, as a JSON Web Key Set.
pub const GOOGLE_JWKS_URL: &str =
    "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";

const SKEW: i64 = 60;
const MAX_CACHE: Duration = Duration::from_secs(86_400);
const REFETCH_INTERVAL: Duration = Duration::from_secs(60);

/// A verified ID token.
#[derive(Clone, Debug, PartialEq)]
pub struct FirebaseIdentity {
    /// Firebase uid.
    pub uid: String,
    /// Email address, if any.
    pub email: Option<String>,
    /// Whether the email address is verified.
    pub email_verified: bool,
    /// Display name, if any.
    pub name: Option<String>,
    /// `firebase.sign_in_provider`: `password`, `google.com`, `custom`, …
    pub sign_in_provider: String,
    /// `firebase.sign_in_second_factor` (`totp`, `phone`), if Firebase MFA was used.
    pub second_factor: Option<String>,
    /// When the person signed in (seconds since the epoch); a refresh keeps it.
    pub auth_time: i64,
    /// When this token was issued.
    pub issued_at: i64,
    /// When this token expires.
    pub expires_at: i64,
    /// All claims.
    pub claims: Map<String, Value>,
}

impl FirebaseIdentity {
    /// `passkey` or `handoff` for a sign-in through the auth hub; `None` otherwise. Trusted only
    /// for `sign_in_provider = custom`, because only the hub can mint custom tokens.
    pub fn login_method(&self) -> Option<&str> {
        if self.sign_in_provider != "custom" {
            return None;
        }
        self.claims.get("login_method").and_then(Value::as_str)
    }

    /// The method behind the sign-in (`passkey`, `password`, `google.com`, …); for a handoff the
    /// method used in the browser.
    pub fn method(&self) -> &str {
        match self.login_method() {
            Some("passkey") => "passkey",
            Some("handoff") => self
                .claims
                .get("login_via")
                .and_then(Value::as_str)
                .unwrap_or(&self.sign_in_provider),
            _ => &self.sign_in_provider,
        }
    }

    /// True for a passkey, Firebase MFA, or a handoff from such a browser session.
    pub fn is_multi_factor(&self) -> bool {
        self.second_factor.is_some()
            || match self.login_method() {
                Some("passkey") => true,
                Some("handoff") => self.claims.get("login_mfa") == Some(&Value::Bool(true)),
                _ => false,
            }
    }

    /// True when the person signed in at most `seconds` ago.
    pub fn is_recent(&self, seconds: i64) -> bool {
        now() - self.auth_time <= seconds
    }
}

enum Keys {
    Google {
        url: String,
        http: reqwest::Client,
        cache: Mutex<Cache>,
    },
    Static(HashMap<String, DecodingKey>),
    Emulator,
}

#[derive(Default)]
struct Cache {
    keys: HashMap<String, DecodingKey>,
    expires: Option<Instant>,
    last_fetch: Option<Instant>,
}

/// Verifies Firebase ID tokens of one project.
pub struct IdTokenVerifier {
    project_id: String,
    keys: Keys,
}

impl std::fmt::Debug for IdTokenVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdTokenVerifier")
            .field("project_id", &self.project_id)
            .finish_non_exhaustive()
    }
}

impl IdTokenVerifier {
    /// Verifies against Google's current keys, fetched and cached for their `max-age`.
    pub fn for_project(project_id: &str) -> Result<Self, Error> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(Error::from)?;
        Self::with_keys_url(project_id, GOOGLE_JWKS_URL, http)
    }

    /// With another JWKS address and HTTP client (tests, proxies).
    pub fn with_keys_url(
        project_id: &str,
        url: &str,
        http: reqwest::Client,
    ) -> Result<Self, Error> {
        check(project_id)?;
        Ok(Self {
            project_id: project_id.to_owned(),
            keys: Keys::Google {
                url: url.to_owned(),
                http,
                cache: Mutex::new(Cache::default()),
            },
        })
    }

    /// With fixed RSA keys (`kid` → PEM public key), for tests and air-gapped setups.
    pub fn with_static_keys(project_id: &str, keys: &[(&str, &str)]) -> Result<Self, Error> {
        check(project_id)?;
        let mut map = HashMap::new();
        for (kid, pem) in keys {
            let key = DecodingKey::from_rsa_pem(pem.as_bytes())
                .map_err(|e| Error::Configuration(e.to_string()))?;
            map.insert((*kid).to_owned(), key);
        }
        Ok(Self {
            project_id: project_id.to_owned(),
            keys: Keys::Static(map),
        })
    }

    /// For the Firebase Auth emulator, which issues **unsigned** tokens. Only for `demo-`
    /// projects, which cannot exist outside the emulator.
    pub fn for_emulator(project_id: &str) -> Result<Self, Error> {
        if !is_demo_project(project_id) {
            return Err(Error::Configuration(
                "the emulator verifier is only allowed for a \"demo-\" project".into(),
            ));
        }
        Ok(Self {
            project_id: project_id.to_owned(),
            keys: Keys::Emulator,
        })
    }

    /// Verifies a token. Every refusal is [`Error::InvalidToken`]; missing keys are
    /// [`Error::Unavailable`].
    pub async fn verify(&self, id_token: &str) -> Result<FirebaseIdentity, Error> {
        if id_token.len() > 16_384 {
            return Err(Error::InvalidToken("too long"));
        }
        let mut parts = id_token.split('.');
        let (Some(h), Some(p), Some(s), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(Error::InvalidToken("not a compact JWT"));
        };
        let header = object(h)?;
        let claims = object(p)?;
        let alg = header.get("alg").and_then(Value::as_str);

        if let Keys::Emulator = self.keys {
            if alg != Some("none") {
                return Err(Error::InvalidToken("emulator tokens are unsigned"));
            }
        } else {
            if alg != Some("RS256") {
                return Err(Error::InvalidToken("alg is not RS256"));
            }
            let kid = header
                .get("kid")
                .and_then(Value::as_str)
                .filter(|k| !k.is_empty())
                .ok_or(Error::InvalidToken("no kid"))?;
            let key = self
                .key(kid)
                .await?
                .ok_or(Error::InvalidToken("unknown kid"))?;
            let message = format!("{h}.{p}");
            let valid = jsonwebtoken::crypto::verify(s, message.as_bytes(), &key, Algorithm::RS256)
                .map_err(|_| Error::InvalidToken("bad signature"))?;
            if !valid {
                return Err(Error::InvalidToken("bad signature"));
            }
        }
        self.claims(claims)
    }

    fn claims(&self, claims: Map<String, Value>) -> Result<FirebaseIdentity, Error> {
        let int = |name: &'static str| {
            claims
                .get(name)
                .and_then(Value::as_i64)
                .ok_or(Error::InvalidToken("a time claim is missing"))
        };
        let (exp, iat, auth_time) = (int("exp")?, int("iat")?, int("auth_time")?);
        let now = now();
        let expected_iss = format!("https://securetoken.google.com/{}", self.project_id);
        if claims.get("iss").and_then(Value::as_str) != Some(expected_iss.as_str()) {
            return Err(Error::InvalidToken("wrong iss"));
        }
        if claims.get("aud").and_then(Value::as_str) != Some(self.project_id.as_str()) {
            return Err(Error::InvalidToken("wrong aud"));
        }
        if exp + SKEW <= now {
            return Err(Error::InvalidToken("expired"));
        }
        if iat - SKEW > now || auth_time - SKEW > now || auth_time > iat + SKEW {
            return Err(Error::InvalidToken("issued in the future"));
        }
        let sub = claims
            .get("sub")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty() && s.len() <= 128)
            .ok_or(Error::InvalidToken("bad sub"))?
            .to_owned();
        if let Some(user_id) = claims.get("user_id") {
            if user_id.as_str() != Some(sub.as_str()) {
                return Err(Error::InvalidToken("user_id differs from sub"));
            }
        }
        let firebase = claims.get("firebase");
        let provider = firebase
            .and_then(|f| f.get("sign_in_provider"))
            .and_then(Value::as_str)
            .filter(|p| !p.is_empty())
            .ok_or(Error::InvalidToken("no sign_in_provider"))?
            .to_owned();
        let second_factor = firebase
            .and_then(|f| f.get("sign_in_second_factor"))
            .and_then(Value::as_str)
            .filter(|p| !p.is_empty())
            .map(str::to_owned);
        let text = |name: &str| claims.get(name).and_then(Value::as_str).map(str::to_owned);
        Ok(FirebaseIdentity {
            uid: sub,
            email: text("email"),
            email_verified: claims.get("email_verified") == Some(&Value::Bool(true)),
            name: text("name"),
            sign_in_provider: provider,
            second_factor,
            auth_time,
            issued_at: iat,
            expires_at: exp,
            claims,
        })
    }

    async fn key(&self, kid: &str) -> Result<Option<DecodingKey>, Error> {
        match &self.keys {
            Keys::Static(map) => Ok(map.get(kid).cloned()),
            Keys::Emulator => Ok(None),
            Keys::Google { url, http, cache } => {
                let mut cache = cache.lock().await;
                let fresh = cache.expires.is_some_and(|e| e > Instant::now());
                if fresh {
                    if let Some(key) = cache.keys.get(kid) {
                        return Ok(Some(key.clone()));
                    }
                    if cache
                        .last_fetch
                        .is_some_and(|t| t.elapsed() < REFETCH_INTERVAL)
                    {
                        return Ok(None);
                    }
                }
                cache.last_fetch = Some(Instant::now());
                let response = http
                    .get(url)
                    .send()
                    .await
                    .map_err(|e| Error::Unavailable(e.without_url().to_string()))?;
                if !response.status().is_success() {
                    return Err(Error::Unavailable(format!(
                        "HTTP {}",
                        response.status().as_u16()
                    )));
                }
                let max_age = response
                    .headers()
                    .get("cache-control")
                    .and_then(|v| v.to_str().ok())
                    .and_then(max_age)
                    .unwrap_or(3600);
                let set: Value = response
                    .json()
                    .await
                    .map_err(|e| Error::Unavailable(e.without_url().to_string()))?;
                let mut keys = HashMap::new();
                for jwk in set
                    .get("keys")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    let field = |n: &str| jwk.get(n).and_then(Value::as_str);
                    if let (Some(kid), Some("RSA"), Some(n), Some(e)) =
                        (field("kid"), field("kty"), field("n"), field("e"))
                    {
                        if let Ok(key) = DecodingKey::from_rsa_components(n, e) {
                            keys.insert(kid.to_owned(), key);
                        }
                    }
                }
                if keys.is_empty() {
                    return Err(Error::Unavailable("no keys in the answer".into()));
                }
                cache.keys = keys;
                cache.expires = Some(Instant::now() + Duration::from_secs(max_age).min(MAX_CACHE));
                Ok(cache.keys.get(kid).cloned())
            }
        }
    }
}

fn check(project_id: &str) -> Result<(), Error> {
    if is_valid_project_id(project_id) {
        Ok(())
    } else {
        Err(Error::Configuration(
            "not a valid Firebase project ID".into(),
        ))
    }
}

fn object(segment: &str) -> Result<Map<String, Value>, Error> {
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| Error::InvalidToken("segment is not base64url"))?;
    match serde_json::from_slice(&bytes) {
        Ok(Value::Object(map)) => Ok(map),
        _ => Err(Error::InvalidToken("segment is not a JSON object")),
    }
}

fn max_age(header: &str) -> Option<u64> {
    header
        .split(',')
        .map(str::trim)
        .find_map(|d| d.strip_prefix("max-age="))
        .and_then(|v| v.parse().ok())
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}
