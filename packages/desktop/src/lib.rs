//! Desktop side of the passkey sign-in handoff.
//!
//! A passkey is bound to a web domain (the relying-party ID). The webview of a desktop app does not
//! run on that domain, so it cannot use the passkey itself. The app therefore signs in through the
//! **system browser** (RFC 8252, "OAuth 2.0 for Native Apps") and receives the result on a loopback
//! address, protected with PKCE (RFC 7636):
//!
//! 1. [`Handoff::start`] creates a `state` and a `code_verifier` (32 random bytes each, base64url),
//!    derives the S256 challenge and listens on `127.0.0.1` on a random port. Never `localhost`,
//!    never `0.0.0.0`, never IPv6.
//! 2. The app opens [`Handoff::authorize_url`] in the system browser. On that page (served from the
//!    real domain) the user signs in with the passkey and approves the handoff. The server stores a
//!    single-use code bound to the challenge and sends the browser to
//!    `http://127.0.0.1:<port>/callback?code=…&state=…` (or `error=denied`).
//! 3. [`Handoff::wait`] accepts exactly one valid callback and returns a [`HandoffGrant`].
//! 4. The app posts `code` and `code_verifier` to the server's exchange endpoint with its own HTTP
//!    client and receives its session.
//!
//! This crate does not open the browser and does not talk to the server: both are the app's choice
//! (for example the Tauri opener plugin and the app's own HTTP client with its TLS settings).

use std::fmt;
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};

/// Largest request head the listener reads. A callback is a single short GET.
const MAX_HEAD_BYTES: usize = 8 * 1024;
/// How long one connection may take to deliver its request head.
const HEAD_TIMEOUT: Duration = Duration::from_secs(5);
/// Pause between two looks at the listener while waiting.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Why a handoff did not produce a grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandoffError {
    /// The loopback listener could not be opened, or random bytes were unavailable.
    Setup(String),
    /// No valid callback arrived before the timeout.
    TimedOut,
    /// The app cancelled the handoff through a [`CancelHandle`].
    Cancelled,
    /// The user declined on the browser page.
    Denied,
    /// A callback arrived with a missing or different `state`, or with malformed parameters. The
    /// handoff ends: the same `state` never gets a second chance.
    InvalidCallback,
}

impl fmt::Display for HandoffError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Setup(reason) => write!(f, "the sign-in handoff could not start: {reason}"),
            Self::TimedOut => f.write_str("the sign-in handoff timed out"),
            Self::Cancelled => f.write_str("the sign-in handoff was cancelled"),
            Self::Denied => f.write_str("the sign-in was declined in the browser"),
            Self::InvalidCallback => {
                f.write_str("the browser returned an invalid sign-in callback")
            }
        }
    }
}

impl std::error::Error for HandoffError {}

/// Settings of one handoff.
#[derive(Debug, Clone)]
pub struct HandoffConfig {
    /// Path of the loopback callback. Must match the server's setting. Default `/callback`.
    pub callback_path: String,
    /// How long [`Handoff::wait`] waits for the callback. Default five minutes.
    pub timeout: Duration,
    /// Text of the page the browser shows after a successful callback.
    pub success_text: String,
    /// Text of the page the browser shows after a declined or invalid callback.
    pub failure_text: String,
}

impl Default for HandoffConfig {
    fn default() -> Self {
        Self {
            callback_path: "/callback".to_owned(),
            timeout: Duration::from_secs(300),
            success_text: "Signed in. You can close this tab and return to the app.".to_owned(),
            failure_text: "Sign-in did not complete. Return to the app and try again.".to_owned(),
        }
    }
}

/// What the app exchanges at the server for a session. Both values are secrets until exchanged.
#[derive(Clone, PartialEq, Eq)]
pub struct HandoffGrant {
    /// Single-use code from the server.
    pub code: String,
    /// PKCE verifier that proves this app started the handoff.
    pub code_verifier: String,
}

impl fmt::Debug for HandoffGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HandoffGrant { code: <redacted>, code_verifier: <redacted> }")
    }
}

/// Cancels a waiting [`Handoff`] from another thread.
#[derive(Debug, Clone)]
pub struct CancelHandle(Arc<AtomicBool>);

impl CancelHandle {
    /// Makes [`Handoff::wait`] return [`HandoffError::Cancelled`].
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// One sign-in handoff: an open loopback listener with its `state` and PKCE pair.
pub struct Handoff {
    listener: TcpListener,
    port: u16,
    state: String,
    code_verifier: String,
    code_challenge: String,
    config: HandoffConfig,
    cancelled: Arc<AtomicBool>,
}

impl fmt::Debug for Handoff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Handoff")
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

impl Handoff {
    /// Opens the loopback listener and creates the `state` and the PKCE pair.
    pub fn start(config: HandoffConfig) -> Result<Self, HandoffError> {
        if !config.callback_path.starts_with('/')
            || config.callback_path.contains(['?', '#', ' ', '\r', '\n'])
        {
            return Err(HandoffError::Setup(
                "the callback path must start with '/' and hold no query".to_owned(),
            ));
        }
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .map_err(|e| HandoffError::Setup(e.to_string()))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| HandoffError::Setup(e.to_string()))?;
        let port = listener
            .local_addr()
            .map_err(|e| HandoffError::Setup(e.to_string()))?
            .port();
        let state = random_token()?;
        let code_verifier = random_token()?;
        let code_challenge = challenge_for(&code_verifier);
        Ok(Self {
            listener,
            port,
            state,
            code_verifier,
            code_challenge,
            config,
            cancelled: Arc::new(AtomicBool::new(false)),
        })
    }

    /// The loopback port the server must redirect to.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The S256 challenge the server binds the code to.
    pub fn code_challenge(&self) -> &str {
        &self.code_challenge
    }

    /// The query the browser page needs: `challenge`, `port` and `state` (all URL-safe).
    pub fn query(&self) -> String {
        format!(
            "challenge={}&port={}&state={}",
            self.code_challenge, self.port, self.state
        )
    }

    /// `page_url` with [`Handoff::query`] appended. The parameters go at the end of the string,
    /// behind `?` or `&`, so both `https://app.example/desktop-sign-in` and a hash route such as
    /// `https://app.example/#/desktop-sign-in` work.
    pub fn authorize_url(&self, page_url: &str) -> String {
        let last_part = page_url.rsplit('#').next().unwrap_or(page_url);
        let separator = if last_part.contains('?') { '&' } else { '?' };
        format!("{page_url}{separator}{}", self.query())
    }

    /// A handle that cancels [`Handoff::wait`] from another thread.
    pub fn cancel_handle(&self) -> CancelHandle {
        CancelHandle(Arc::clone(&self.cancelled))
    }

    /// Waits for the callback. Blocks until a valid callback, a decline, an invalid callback, a
    /// cancel or the timeout. The listener closes when this returns.
    ///
    /// Connections that are not a `GET` on the callback path with `Host: 127.0.0.1:<port>` get an
    /// error page and are ignored; waiting continues.
    pub fn wait(self) -> Result<HandoffGrant, HandoffError> {
        let deadline = Instant::now() + self.config.timeout;
        loop {
            if self.cancelled.load(Ordering::SeqCst) {
                return Err(HandoffError::Cancelled);
            }
            if Instant::now() >= deadline {
                return Err(HandoffError::TimedOut);
            }
            match self.listener.accept() {
                Ok((mut stream, _)) => {
                    let verdict = read_head(&mut stream)
                        .map(|head| {
                            judge(&head, &self.config.callback_path, &self.state, self.port)
                        })
                        .unwrap_or(Verdict::Ignore);
                    match verdict {
                        Verdict::Ignore => {
                            respond(&mut stream, "404 Not Found", &self.config.failure_text)
                        }
                        Verdict::Code(code) => {
                            respond(&mut stream, "200 OK", &self.config.success_text);
                            return Ok(HandoffGrant {
                                code,
                                code_verifier: self.code_verifier,
                            });
                        }
                        Verdict::Denied => {
                            respond(&mut stream, "200 OK", &self.config.failure_text);
                            return Err(HandoffError::Denied);
                        }
                        Verdict::Invalid => {
                            respond(&mut stream, "400 Bad Request", &self.config.failure_text);
                            return Err(HandoffError::InvalidCallback);
                        }
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => std::thread::sleep(POLL_INTERVAL),
                Err(_) => std::thread::sleep(POLL_INTERVAL),
            }
        }
    }
}

/// 32 random bytes as base64url without padding (43 characters).
fn random_token() -> Result<String, HandoffError> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|e| HandoffError::Setup(e.to_string()))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// The S256 challenge of RFC 7636 §4.2: `BASE64URL(SHA256(ASCII(code_verifier)))`.
pub fn challenge_for(code_verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()))
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// Not our callback: answer with an error page and keep waiting.
    Ignore,
    Code(String),
    Denied,
    Invalid,
}

fn read_head(stream: &mut TcpStream) -> Option<String> {
    stream.set_nonblocking(false).ok()?;
    stream.set_read_timeout(Some(HEAD_TIMEOUT)).ok()?;
    stream.set_write_timeout(Some(HEAD_TIMEOUT)).ok()?;
    let started = Instant::now();
    let mut head = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        if head.len() >= MAX_HEAD_BYTES || started.elapsed() >= HEAD_TIMEOUT {
            return None;
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return None,
            Ok(n) => head.extend_from_slice(&chunk[..n]),
        }
    }
    String::from_utf8(head).ok()
}

fn judge(head: &str, callback_path: &str, state: &str, port: u16) -> Verdict {
    let mut lines = head.split("\r\n");
    let mut request = lines.next().unwrap_or("").split(' ');
    let (Some("GET"), Some(target), Some(version), None) = (
        request.next(),
        request.next(),
        request.next(),
        request.next(),
    ) else {
        return Verdict::Ignore;
    };
    if !version.starts_with("HTTP/1.") {
        return Verdict::Ignore;
    }
    let expected_host = format!("127.0.0.1:{port}");
    let hosts: Vec<&str> = lines
        .take_while(|line| !line.is_empty())
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.eq_ignore_ascii_case("host"))
        .map(|(_, value)| value.trim())
        .collect();
    if hosts.len() != 1 || hosts[0] != expected_host {
        return Verdict::Ignore;
    }
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    if path != callback_path {
        return Verdict::Ignore;
    }

    let (mut code, mut given_state, mut error) = (None, None, None);
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        let slot = match name {
            "code" => &mut code,
            "state" => &mut given_state,
            "error" => &mut error,
            _ => return Verdict::Invalid,
        };
        if slot.replace(value).is_some() {
            return Verdict::Invalid;
        }
    }
    match given_state {
        Some(given) if constant_time_eq(given, state) => {}
        _ => return Verdict::Invalid,
    }
    match (code, error) {
        (None, Some("denied")) => Verdict::Denied,
        (Some(code), None) if is_code(code) => Verdict::Code(code.to_owned()),
        _ => Verdict::Invalid,
    }
}

/// A code is base64url text of a sane length; nothing that needs URL decoding.
fn is_code(code: &str) -> bool {
    (16..=512).contains(&code.len())
        && code
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn respond(stream: &mut TcpStream, status: &str, text: &str) {
    let escaped = text
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    let body = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\">\
         <title>Sign-in</title></head><body style=\"font-family:system-ui,sans-serif;margin:3rem\"><p>{escaped}</p></body></html>"
    );
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\n\
         Referrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

#[cfg(test)]
mod tests;
