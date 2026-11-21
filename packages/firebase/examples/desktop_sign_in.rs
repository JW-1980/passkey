//! A desktop sign-in from the command line, against a hub and the Firebase Auth emulator.
//!
//! `cargo run --features desktop --example desktop_sign_in -- <hub base> <page url> <project> <emulator host>`
//!
//! Prints `OPEN <url>` (the page to open in the browser), then `SESSION <uid> <method>` once the
//! browser approved and the app holds a Firebase session.

use firebase_login::desktop::DesktopSignIn;
use firebase_login::verify::IdTokenVerifier;
use firebase_login::{FirebaseClient, FirebaseConfig, HubClient};
use passkey_desktop::HandoffConfig;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [hub, page, project, emulator] = args.as_slice() else {
        eprintln!("usage: desktop_sign_in <hub base> <page url> <project> <emulator host>");
        std::process::exit(2);
    };
    let hub = HubClient::new(hub).expect("hub");
    let config = FirebaseConfig::new("fake-api-key", project.as_str())
        .and_then(|c| c.with_emulator(emulator.as_str()))
        .expect("config");
    let firebase = FirebaseClient::new(config).expect("client");

    let sign_in = DesktopSignIn::start(HandoffConfig::default()).expect("start");
    println!("OPEN {}", sign_in.authorize_url(page));
    match sign_in.finish(&hub, &firebase).await {
        Ok(session) => {
            let identity = IdTokenVerifier::for_emulator(project)
                .expect("verifier")
                .verify(&session.id_token)
                .await
                .expect("verified");
            println!("SESSION {} {}", session.uid, identity.method());
        }
        Err(error) => {
            println!("ERROR {error}");
            std::process::exit(1);
        }
    }
}
