mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use common::{emulator_id_token, Answer, FakeServer};
use firebase_login::{
    Error, FirebaseClient, FirebaseConfig, HubClient, MemoryTokenStore, SessionManager, TokenStore,
};
use serde_json::json;

const PROJECT: &str = "demo-unit";

fn client(server: &FakeServer) -> FirebaseClient {
    let config = FirebaseConfig::new("api-key-123", PROJECT)
        .and_then(|c| c.with_emulator(server.host()))
        .expect("config");
    FirebaseClient::new(config).expect("client")
}

#[tokio::test]
async fn custom_token_sign_in_gives_a_session_for_the_uid_in_the_token() {
    let server = FakeServer::start(|request| {
        assert_eq!(
            request.path,
            "/identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key=api-key-123"
        );
        assert_eq!(
            request.json(),
            json!({ "token": "a.b.c", "returnSecureToken": true })
        );
        Answer::json(
            200,
            json!({ "idToken": emulator_id_token(PROJECT, "uid-7"), "refreshToken": "r1", "expiresIn": "3600" }),
        )
    });
    let session = client(&server)
        .sign_in_with_custom_token("a.b.c")
        .await
        .expect("session");
    assert_eq!(session.uid, "uid-7");
    assert_eq!(session.refresh_token, "r1");
    assert!(!session.expires_within(Duration::from_secs(3000)));
    assert!(session.expires_within(Duration::from_secs(3700)));
    assert!(!format!("{session:?}").contains("r1"), "Debug hides tokens");
}

#[tokio::test]
async fn firebase_refusals_keep_only_the_code_and_tell_session_ends_apart() {
    let server = FakeServer::start(|request| {
        let message = if request.path.contains("signInWithCustomToken") {
            "INVALID_CUSTOM_TOKEN : The custom token format is incorrect."
        } else {
            "USER_DISABLED"
        };
        Answer::json(400, json!({ "error": { "code": 400, "message": message } }))
    });
    let error = client(&server)
        .sign_in_with_custom_token("a.b.c")
        .await
        .unwrap_err();
    assert_eq!(error, Error::Firebase("INVALID_CUSTOM_TOKEN".into()));
    assert!(!error.ends_session());

    let error = client(&server).refresh("r").await.unwrap_err();
    assert_eq!(error, Error::Firebase("USER_DISABLED".into()));
    assert!(error.ends_session());
}

#[tokio::test]
async fn server_errors_are_network_errors_and_never_show_the_api_key() {
    let server = FakeServer::start(|_| Answer::json(503, json!({})));
    let error = client(&server)
        .sign_in_with_password("a@b.c", "pw")
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Network(_)));

    let unreachable = FirebaseConfig::new("secret-looking-key", PROJECT)
        .and_then(|c| c.with_emulator("127.0.0.1:1"))
        .expect("config");
    let error = FirebaseClient::new(unreachable)
        .expect("client")
        .refresh("r")
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Network(_)), "{error:?}");
    assert!(!error.to_string().contains("secret-looking-key"));
}

#[tokio::test]
async fn refresh_uses_the_secure_token_endpoint_with_a_form() {
    let server = FakeServer::start(|request| {
        assert_eq!(
            request.path,
            "/securetoken.googleapis.com/v1/token?key=api-key-123"
        );
        assert_eq!(request.body, "grant_type=refresh_token&refresh_token=r%2F1");
        Answer::json(
            200,
            json!({ "id_token": emulator_id_token(PROJECT, "uid-7"), "refresh_token": "r2", "expires_in": "3600", "user_id": "uid-7" }),
        )
    });
    let session = client(&server).refresh("r/1").await.expect("refresh");
    assert_eq!(session.refresh_token, "r2");
}

#[tokio::test]
async fn idp_sign_in_sends_the_provider_credential_as_post_body() {
    let server = FakeServer::start(|request| {
        let body = request.json();
        assert_eq!(body["postBody"], "id_token=g.t.x&providerId=google.com");
        assert_eq!(body["requestUri"], "http://localhost");
        Answer::json(
            200,
            json!({ "idToken": emulator_id_token(PROJECT, "g-1"), "refreshToken": "r", "expiresIn": "3600" }),
        )
    });
    let session = client(&server)
        .sign_in_with_idp(&firebase_login::IdpCredential::IdToken {
            provider: "google.com".into(),
            id_token: "g.t.x".into(),
        })
        .await
        .expect("session");
    assert_eq!(session.uid, "g-1");
}

#[tokio::test]
async fn configuration_guards() {
    assert!(FirebaseConfig::new("k", "real-project")
        .expect("ok")
        .with_emulator("127.0.0.1:9099")
        .is_err());
    assert!(FirebaseConfig::new("k", "demo").is_err(), "too short");
    assert!(FirebaseConfig::new("", "demo-project").is_err());
    assert!(FirebaseConfig::new("k", "demo-project")
        .expect("ok")
        .with_emulator("no-port")
        .is_err());
    assert!(HubClient::new("http://login.example/passkey").is_err());
    assert!(HubClient::new("https://login.example/passkey").is_ok());
    assert!(HubClient::new("http://127.0.0.1:8080/passkey").is_ok());
}

#[tokio::test]
async fn session_manager_refreshes_near_expiry_and_signs_out_when_firebase_ends_the_session() {
    let refreshes = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&refreshes);
    let server = FakeServer::start(move |request| {
        if request.path.contains("securetoken") {
            let n = counter.fetch_add(1, Ordering::SeqCst);
            if request.body.contains("refresh_token=revoked") {
                return Answer::json(400, json!({ "error": { "message": "TOKEN_EXPIRED" } }));
            }
            if request.body.contains("refresh_token=offline") {
                return Answer::json(503, json!({}));
            }
            return Answer::json(
                200,
                json!({ "id_token": emulator_id_token(PROJECT, "uid-1"), "refresh_token": format!("r{}", n + 2), "expires_in": "3600" }),
            );
        }
        Answer::json(
            200,
            json!({ "idToken": emulator_id_token(PROJECT, "uid-1"), "refreshToken": "r1", "expiresIn": "60" }),
        )
    });
    let store = Arc::new(MemoryTokenStore::default());
    let manager = SessionManager::new(client(&server), store.clone());
    assert_eq!(manager.id_token().await, Err(Error::SignedOut));

    let session = manager
        .client()
        .sign_in_with_custom_token("a.b.c")
        .await
        .expect("sign in");
    manager.set(session).await.expect("set");
    assert_eq!(store.load().expect("load").as_deref(), Some("r1"));

    // 60 s left is within the 5-minute margin: refresh, once, even for concurrent callers.
    let (a, b) = tokio::join!(manager.id_token(), manager.id_token());
    assert!(a.is_ok() && b.is_ok());
    assert_eq!(refreshes.load(Ordering::SeqCst), 1);
    assert_eq!(
        store.load().expect("load").as_deref(),
        Some("r2"),
        "the rotated refresh token is stored"
    );
    manager.id_token().await.expect("cached");
    assert_eq!(refreshes.load(Ordering::SeqCst), 1);

    // A network failure keeps the session; a refusal ends it.
    store.save("offline").expect("save");
    assert_eq!(
        manager
            .restore()
            .await
            .map_err(|e| matches!(e, Error::Network(_))),
        Err(true)
    );
    store.save("revoked").expect("save");
    assert_eq!(manager.restore().await, Ok(None));
    assert_eq!(
        store.load().expect("load"),
        None,
        "the dead refresh token is removed"
    );
    assert_eq!(manager.uid().await, None);
}

#[tokio::test]
async fn hub_exchange_and_refusals() {
    let server = FakeServer::start(|request| match request.path.as_str() {
        "/passkey/handoff/exchange" => {
            if request.json()["code_verifier"] == "good" {
                Answer::json(
                    200,
                    json!({ "firebase": { "customToken": "h.p.s", "expiresIn": 300 } }),
                )
            } else {
                Answer::json(
                    400,
                    json!({ "error": { "code": "invalid_handoff", "message": "x" } }),
                )
            }
        }
        "/passkey/register/options" => {
            assert_eq!(request.header("authorization"), Some("Bearer id-tok"));
            Answer::json(200, json!({ "ceremony": "c", "publicKey": {} }))
        }
        _ => Answer::json(200, json!({ "ok": true })),
    });
    let hub = HubClient::new(&format!("http://127.0.0.1:{}/passkey/", server.port)).expect("hub");
    assert_eq!(
        hub.exchange_handoff("code", "good").await.expect("token").0,
        "h.p.s"
    );
    assert_eq!(
        hub.exchange_handoff("code", "bad").await.unwrap_err(),
        Error::Hub {
            status: 400,
            code: "invalid_handoff".into()
        }
    );
    assert!(
        matches!(
            hub.finish_sign_in("c", json!({})).await,
            Err(Error::InvalidResponse(_))
        ),
        "no custom token"
    );
    assert_eq!(
        hub.begin_registration("id-tok").await.expect("options")["ceremony"],
        "c"
    );
}
