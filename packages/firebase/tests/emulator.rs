//! Against a running Firebase Auth emulator (`FIREBASE_AUTH_EMULATOR_HOST`, project
//! `FIREBASE_PROJECT_ID`, default `demo-passkey-test`). Skipped without the variable.
mod common;

use common::{now, unsigned_jwt};
use firebase_login::verify::IdTokenVerifier;
use firebase_login::{FirebaseClient, FirebaseConfig, MemoryTokenStore, SessionManager};
use serde_json::{json, Value};
use std::sync::Arc;

fn setup() -> Option<(String, String, FirebaseClient)> {
    let host = std::env::var("FIREBASE_AUTH_EMULATOR_HOST")
        .ok()
        .filter(|h| !h.is_empty())?;
    let project =
        std::env::var("FIREBASE_PROJECT_ID").unwrap_or_else(|_| "demo-passkey-test".into());
    let config = FirebaseConfig::new("fake-api-key", &project)
        .and_then(|c| c.with_emulator(&host))
        .expect("config");
    Some((host, project, FirebaseClient::new(config).expect("client")))
}

#[tokio::test]
async fn password_sign_in_lookup_refresh_and_delete() {
    let Some((host, project, client)) = setup() else {
        eprintln!("skipped: FIREBASE_AUTH_EMULATOR_HOST is not set");
        return;
    };
    let email = format!("rust-{}@example.com", now());
    let created: Value = reqwest::Client::new()
        .post(format!("http://{host}/identitytoolkit.googleapis.com/v1/accounts:signUp?key=fake-api-key"))
        .json(&json!({ "email": email, "password": "a long password 123", "returnSecureToken": true }))
        .send().await.expect("sign up").json().await.expect("json");
    let uid = created["localId"].as_str().expect("uid").to_owned();

    let wrong = client
        .sign_in_with_password(&email, "wrong password")
        .await
        .unwrap_err();
    assert!(
        matches!(wrong, firebase_login::Error::Firebase(_)),
        "{wrong:?}"
    );

    let session = client
        .sign_in_with_password(&email, "a long password 123")
        .await
        .expect("sign in");
    assert_eq!(session.uid, uid);
    let info = client.lookup(&session.id_token).await.expect("lookup");
    assert_eq!(info.email.as_deref(), Some(email.as_str()));

    let identity = IdTokenVerifier::for_emulator(&project)
        .expect("verifier")
        .verify(&session.id_token)
        .await
        .expect("valid");
    assert_eq!(identity.uid, uid);
    assert_eq!(identity.sign_in_provider, "password");

    let manager = SessionManager::new(client.clone(), Arc::new(MemoryTokenStore::default()));
    manager.set(session.clone()).await.expect("set");
    let fresh = manager.force_refresh().await.expect("refresh");
    assert_eq!(
        IdTokenVerifier::for_emulator(&project)
            .expect("v")
            .verify(&fresh)
            .await
            .expect("valid")
            .uid,
        uid
    );

    client.delete_account(&fresh).await.expect("delete");
    let after = manager.force_refresh().await;
    assert_eq!(
        after,
        Err(firebase_login::Error::SignedOut),
        "a deleted user is signed out"
    );
}

#[tokio::test]
async fn custom_token_keeps_the_hub_claims() {
    let Some((_, project, client)) = setup() else {
        eprintln!("skipped: FIREBASE_AUTH_EMULATOR_HOST is not set");
        return;
    };
    let now = now();
    let uid = format!("rust-custom-{now}");
    let custom = unsigned_jwt(&json!({
        "iss": "x@demo.iam.gserviceaccount.com", "sub": "x@demo.iam.gserviceaccount.com",
        "aud": "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit",
        "iat": now, "exp": now + 300, "uid": uid, "claims": { "login_method": "handoff", "login_via": "google.com", "login_mfa": false },
    }));
    let session = client
        .sign_in_with_custom_token(&custom)
        .await
        .expect("sign in");
    assert_eq!(session.uid, uid);
    let identity = IdTokenVerifier::for_emulator(&project)
        .expect("verifier")
        .verify(&session.id_token)
        .await
        .expect("valid");
    assert_eq!(identity.login_method(), Some("handoff"));
    assert_eq!(identity.method(), "google.com");
}
