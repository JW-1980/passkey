mod common;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use common::{now, unsigned_jwt, Answer, FakeServer};
use firebase_login::verify::IdTokenVerifier;
use firebase_login::Error;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::{EncodePublicKey, LineEnding};
use rsa::signature::{SignatureEncoding, Signer};
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use serde_json::{json, Value};
use sha2::Sha256;
use std::sync::OnceLock;

const PROJECT: &str = "shop-test-123";

fn keys() -> &'static (RsaPrivateKey, RsaPrivateKey) {
    static KEYS: OnceLock<(RsaPrivateKey, RsaPrivateKey)> = OnceLock::new();
    KEYS.get_or_init(|| {
        let mut rng = rand::thread_rng();
        (
            RsaPrivateKey::new(&mut rng, 2048).expect("key"),
            RsaPrivateKey::new(&mut rng, 2048).expect("key"),
        )
    })
}

fn google_pem() -> String {
    keys()
        .0
        .to_public_key()
        .to_public_key_pem(LineEnding::LF)
        .expect("pem")
}

fn claims(overrides: Value) -> Value {
    let now = now();
    let mut base = json!({
        "iss": format!("https://securetoken.google.com/{PROJECT}"), "aud": PROJECT,
        "auth_time": now - 30, "iat": now - 30, "exp": now + 3570,
        "sub": "uid-1", "user_id": "uid-1", "email": "ann@example.com", "email_verified": true,
        "firebase": { "sign_in_provider": "password" },
    });
    for (key, value) in overrides.as_object().expect("object") {
        if value.is_null() {
            base.as_object_mut().expect("object").remove(key);
        } else {
            base[key] = value.clone();
        }
    }
    base
}

fn sign(header: Value, claims: &Value, key: &RsaPrivateKey) -> String {
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let signature = SigningKey::<Sha256>::new(key.clone()).sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

fn token(overrides: Value) -> String {
    sign(
        json!({ "alg": "RS256", "kid": "k1", "typ": "JWT" }),
        &claims(overrides),
        &keys().0,
    )
}

fn verifier() -> IdTokenVerifier {
    IdTokenVerifier::with_static_keys(PROJECT, &[("k1", &google_pem())]).expect("verifier")
}

#[tokio::test]
async fn a_valid_token_gives_the_identity() {
    let identity = verifier().verify(&token(json!({}))).await.expect("valid");
    assert_eq!(identity.uid, "uid-1");
    assert_eq!(identity.email.as_deref(), Some("ann@example.com"));
    assert!(identity.email_verified);
    assert_eq!(identity.method(), "password");
    assert!(!identity.is_multi_factor());
    assert!(identity.is_recent(60));
    assert!(!identity.is_recent(10));
}

#[tokio::test]
async fn broken_tokens_are_refused() {
    let now = now();
    let cases: Vec<(&str, String)> = vec![
        ("alg none", unsigned_jwt(&claims(json!({})))),
        (
            "HS256",
            sign(
                json!({ "alg": "HS256", "kid": "k1" }),
                &claims(json!({})),
                &keys().0,
            ),
        ),
        (
            "no kid",
            sign(json!({ "alg": "RS256" }), &claims(json!({})), &keys().0),
        ),
        (
            "unknown kid",
            sign(
                json!({ "alg": "RS256", "kid": "k9" }),
                &claims(json!({})),
                &keys().0,
            ),
        ),
        (
            "other key",
            sign(
                json!({ "alg": "RS256", "kid": "k1" }),
                &claims(json!({})),
                &keys().1,
            ),
        ),
        (
            "iss",
            token(json!({ "iss": "https://securetoken.google.com/other-project" })),
        ),
        ("aud", token(json!({ "aud": "other-project" }))),
        ("expired", token(json!({ "exp": now - 61 }))),
        ("iat future", token(json!({ "iat": now + 120 }))),
        ("auth_time future", token(json!({ "auth_time": now + 120 }))),
        ("empty sub", token(json!({ "sub": "", "user_id": "" }))),
        (
            "long sub",
            token(json!({ "sub": "a".repeat(129), "user_id": "a".repeat(129) })),
        ),
        ("user_id differs", token(json!({ "user_id": "mallory" }))),
        ("no provider", token(json!({ "firebase": {} }))),
        ("exp text", token(json!({ "exp": "soon" }))),
        ("garbage", "a.b".to_owned()),
    ];
    for (name, bad) in cases {
        match verifier().verify(&bad).await {
            Err(Error::InvalidToken(_)) => {}
            other => panic!("{name}: {other:?}"),
        }
    }
}

#[tokio::test]
async fn tampered_payload_is_refused() {
    let good = token(json!({}));
    let evil = token(json!({ "sub": "mallory", "user_id": "mallory" }));
    let parts: Vec<&str> = good.split('.').collect();
    let evil_payload = evil.split('.').nth(1).expect("payload");
    let forged = format!("{}.{}.{}", parts[0], evil_payload, parts[2]);
    assert!(matches!(
        verifier().verify(&forged).await,
        Err(Error::InvalidToken(_))
    ));
}

#[tokio::test]
async fn passkey_claims_count_only_for_custom_sign_ins() {
    let passkey = verifier()
        .verify(&token(json!({ "login_method": "passkey", "login_mfa": true, "firebase": { "sign_in_provider": "custom" } })))
        .await
        .expect("valid");
    assert_eq!(passkey.method(), "passkey");
    assert!(passkey.is_multi_factor());

    let fake = verifier()
        .verify(&token(
            json!({ "login_method": "passkey", "login_mfa": true }),
        ))
        .await
        .expect("valid");
    assert_eq!(fake.login_method(), None);
    assert!(!fake.is_multi_factor());

    let handoff = verifier()
        .verify(&token(json!({ "login_method": "handoff", "login_via": "google.com", "login_mfa": false, "firebase": { "sign_in_provider": "custom" } })))
        .await
        .expect("valid");
    assert_eq!(handoff.method(), "google.com");
    assert!(!handoff.is_multi_factor());
}

#[tokio::test]
async fn keys_come_from_the_jwks_and_are_cached() {
    let public = keys().0.to_public_key();
    let jwks = json!({ "keys": [{
        "kid": "k1", "kty": "RSA", "alg": "RS256", "use": "sig",
        "n": URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
        "e": URL_SAFE_NO_PAD.encode(public.e().to_bytes_be()),
    }]});
    let server = FakeServer::start(move |_| {
        let mut answer = Answer::json(200, jwks.clone());
        answer.headers.push((
            "Cache-Control".into(),
            "public, max-age=19000, must-revalidate".into(),
        ));
        answer
    });
    let verifier = IdTokenVerifier::with_keys_url(
        PROJECT,
        &format!("http://{}/jwks", server.host()),
        reqwest::Client::new(),
    )
    .expect("verifier");
    verifier.verify(&token(json!({}))).await.expect("valid");
    verifier.verify(&token(json!({}))).await.expect("valid");
    assert!(verifier
        .verify(&sign(
            json!({ "alg": "RS256", "kid": "nope" }),
            &claims(json!({})),
            &keys().0
        ))
        .await
        .is_err());
    assert!(verifier
        .verify(&sign(
            json!({ "alg": "RS256", "kid": "nope" }),
            &claims(json!({})),
            &keys().0
        ))
        .await
        .is_err());
    assert_eq!(
        server.requests().len(),
        1,
        "an unknown kid within a minute of the last fetch does not fetch again"
    );
}

#[tokio::test]
async fn missing_keys_are_unavailable_not_a_refusal() {
    let server = FakeServer::start(|_| Answer::json(500, json!({})));
    let verifier = IdTokenVerifier::with_keys_url(
        PROJECT,
        &format!("http://{}/jwks", server.host()),
        reqwest::Client::new(),
    )
    .expect("verifier");
    assert!(matches!(
        verifier.verify(&token(json!({}))).await,
        Err(Error::Unavailable(_))
    ));
}

#[tokio::test]
async fn emulator_mode_is_for_demo_projects_and_unsigned_tokens_only() {
    assert!(IdTokenVerifier::for_emulator("shop-test-123").is_err());
    let verifier = IdTokenVerifier::for_emulator("demo-shop").expect("verifier");
    let now = now();
    let ok = unsigned_jwt(&json!({
        "iss": "https://securetoken.google.com/demo-shop", "aud": "demo-shop", "auth_time": now, "iat": now,
        "exp": now + 3600, "sub": "u", "firebase": { "sign_in_provider": "custom" } }));
    assert_eq!(verifier.verify(&ok).await.expect("valid").uid, "u");
    assert!(verifier
        .verify(&token(
            json!({ "iss": "https://securetoken.google.com/demo-shop", "aud": "demo-shop" })
        ))
        .await
        .is_err());
}
