//! Runs one sign-in handoff from the command line.
//!
//! `cargo run --example handoff -- https://app.example/desktop-sign-in`
//!
//! Prints the address to open in the browser, waits for the callback and prints what the app
//! would post to the server's exchange endpoint.

use passkey_desktop::{Handoff, HandoffConfig};

fn main() {
    let page = std::env::args().nth(1).expect("usage: handoff <page url>");
    let handoff = Handoff::start(HandoffConfig::default()).expect("start");
    println!("OPEN {}", handoff.authorize_url(&page));
    match handoff.wait() {
        Ok(grant) => println!(
            "GRANT {{\"code\":\"{}\",\"code_verifier\":\"{}\"}}",
            grant.code, grant.code_verifier
        ),
        Err(error) => {
            println!("ERROR {error}");
            std::process::exit(1);
        }
    }
}
