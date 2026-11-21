#![cfg(feature = "desktop")]
mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use common::{emulator_id_token, Answer, FakeServer};
use firebase_login::desktop::sign_in;
use firebase_login::{Error, FirebaseClient, FirebaseConfig, HubClient};
use passkey_desktop::HandoffConfig;
use serde_json::json;
use sha2::{Digest, Sha256};

const PROJECT: &str = "demo-desktop";

fn config() -> HandoffConfig {
    HandoffConfig {
        timeout: std::time::Duration::from_secs(20),
        ..HandoffConfig::default()
    }
}

/// The fake hub remembers the challenge the "browser page" authorized and checks the verifier,
/// like the real hub; the fake Firebase turns the custom token into a session.
#[tokio::test]
async fn desktop_sign_in_runs_the_whole_handoff_and_ends_in_a_firebase_session() {
    let challenge: Arc<Mutex<String>> = Arc::default();
    let seen = Arc::clone(&challenge);
    let server = FakeServer::start(move |request| match request.path.as_str() {
        "/passkey/handoff/exchange" => {
            let body = request.json();
            let verifier = body["code_verifier"].as_str().unwrap_or("");
            let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
            if body["code"] == "CODEcodeCODEcodeCODEcodeCODEcodeCODEcodeCOD"
                && expected == *seen.lock().expect("lock")
            {
                Answer::json(
                    200,
                    json!({ "firebase": { "customToken": "custom.token.sig", "expiresIn": 300 } }),
                )
            } else {
                Answer::json(400, json!({ "error": { "code": "invalid_handoff" } }))
            }
        }
        path if path.contains("signInWithCustomToken") => {
            assert_eq!(request.json()["token"], "custom.token.sig");
            Answer::json(
                200,
                json!({ "idToken": emulator_id_token(PROJECT, "desk-1"), "refreshToken": "r", "expiresIn": "3600" }),
            )
        }
        other => panic!("unexpected {other}"),
    });
    let hub = HubClient::new(&format!("http://{}/passkey", server.host())).expect("hub");
    let firebase = FirebaseClient::new(
        FirebaseConfig::new("k", PROJECT)
            .and_then(|c| c.with_emulator(server.host()))
            .expect("config"),
    )
    .expect("client");

    let session = sign_in(&hub, &firebase, "https://login.example/desktop", config(), |url| {
        // The "browser": read challenge, port and state; the hub page would authorize, and the
        // browser is sent to the loopback address with the code.
        let query = url.split_once('?').map(|(_, q)| q.to_owned()).ok_or("no query")?;
        let param = |name: &str| {
            query.split('&').find_map(|p| p.strip_prefix(&format!("{name}="))).map(str::to_owned).unwrap_or_default()
        };
        *challenge.lock().map_err(|e| e.to_string())? = param("challenge");
        let (port, state) = (param("port"), param("state"));
        std::thread::spawn(move || {
            let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).expect("connect");
            write!(stream, "GET /callback?code=CODEcodeCODEcodeCODEcodeCODEcodeCODEcodeCOD&state={state} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n").expect("write");
            let mut page = String::new();
            let _ = stream.read_to_string(&mut page);
        });
        Ok(())
    })
    .await
    .expect("signed in");

    assert_eq!(session.uid, "desk-1");
}

#[tokio::test]
async fn a_declined_browser_page_is_reported() {
    let server = FakeServer::start(|_| Answer::json(500, json!({})));
    let hub = HubClient::new(&format!("http://{}/passkey", server.host())).expect("hub");
    let firebase = FirebaseClient::new(
        FirebaseConfig::new("k", PROJECT)
            .and_then(|c| c.with_emulator(server.host()))
            .expect("config"),
    )
    .expect("client");
    let result = sign_in(&hub, &firebase, "https://login.example/desktop", config(), |url| {
        let query = url.split_once('?').map(|(_, q)| q.to_owned()).ok_or("no query")?;
        let param = |name: &str| query.split('&').find_map(|p| p.strip_prefix(&format!("{name}="))).map(str::to_owned).unwrap_or_default();
        let (port, state) = (param("port"), param("state"));
        std::thread::spawn(move || {
            let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).expect("connect");
            write!(stream, "GET /callback?error=denied&state={state} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n").expect("write");
            let mut page = String::new();
            let _ = stream.read_to_string(&mut page);
        });
        Ok(())
    })
    .await;
    assert_eq!(
        result.unwrap_err(),
        Error::Handoff(passkey_desktop::HandoffError::Denied)
    );
    assert!(
        server.requests().is_empty(),
        "nothing is exchanged after a refusal"
    );
}
