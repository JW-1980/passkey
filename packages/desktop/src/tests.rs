use super::*;
use std::thread;

fn get(port: u16, target: &str, host: &str) -> String {
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).expect("connect");
    write!(
        stream,
        "GET {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    )
    .expect("write");
    let mut answer = String::new();
    stream.read_to_string(&mut answer).expect("read");
    answer
}

fn start(timeout: Duration) -> Handoff {
    Handoff::start(HandoffConfig {
        timeout,
        ..HandoffConfig::default()
    })
    .expect("start")
}

/// Runs `wait` on a thread and the browser side on this one.
fn run(
    handoff: Handoff,
    browser: impl FnOnce(u16, &str) -> Vec<String>,
) -> (Result<HandoffGrant, HandoffError>, Vec<String>) {
    let (port, state) = (handoff.port, handoff.state.clone());
    let waiter = thread::spawn(move || handoff.wait());
    let answers = browser(port, &state);
    (waiter.join().expect("join"), answers)
}

const CODE: &str = "c29tZS1zaW5nbGUtdXNlLWNvZGU";

#[test]
fn rfc_7636_appendix_b_challenge() {
    assert_eq!(
        challenge_for("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
}

#[test]
fn state_and_verifier_are_independent_random_tokens() {
    let (a, b) = (start(Duration::from_secs(1)), start(Duration::from_secs(1)));
    assert_eq!(a.state.len(), 43);
    assert_eq!(a.code_verifier.len(), 43);
    assert_ne!(a.state, a.code_verifier);
    assert_ne!(a.state, b.state);
    assert_ne!(a.code_verifier, b.code_verifier);
    assert_eq!(a.code_challenge, challenge_for(&a.code_verifier));
}

#[test]
fn listens_on_ipv4_loopback_only() {
    let handoff = start(Duration::from_secs(1));
    let address = handoff.listener.local_addr().expect("address");
    assert_eq!(address.ip(), std::net::IpAddr::V4(Ipv4Addr::LOCALHOST));
}

#[test]
fn authorize_url_appends_to_plain_query_and_hash_routes() {
    let handoff = start(Duration::from_secs(1));
    let query = handoff.query();
    assert!(
        query.starts_with("challenge=")
            && query.contains(&format!("&port={}&state=", handoff.port))
    );
    assert_eq!(
        handoff.authorize_url("https://app.example/in"),
        format!("https://app.example/in?{query}")
    );
    assert_eq!(
        handoff.authorize_url("https://app.example/in?x=1"),
        format!("https://app.example/in?x=1&{query}")
    );
    assert_eq!(
        handoff.authorize_url("https://app.example/?x=1#/in"),
        format!("https://app.example/?x=1#/in?{query}")
    );
    assert_eq!(
        handoff.authorize_url("https://app.example/#/in?y=2"),
        format!("https://app.example/#/in?y=2&{query}")
    );
}

#[test]
fn valid_callback_yields_the_code_and_the_verifier() {
    let handoff = start(Duration::from_secs(10));
    let verifier = handoff.code_verifier.clone();
    let (result, answers) = run(handoff, |port, state| {
        vec![get(
            port,
            &format!("/callback?code={CODE}&state={state}"),
            &format!("127.0.0.1:{port}"),
        )]
    });
    let grant = result.expect("grant");
    assert_eq!(grant.code, CODE);
    assert_eq!(grant.code_verifier, verifier);
    assert!(answers[0].starts_with("HTTP/1.1 200 OK"));
    assert!(answers[0].contains("Cache-Control: no-store"));
    assert!(
        !format!("{grant:?}").contains(CODE),
        "Debug must not print the code"
    );
}

#[test]
fn wrong_path_method_and_host_are_ignored_and_waiting_continues() {
    let handoff = start(Duration::from_secs(10));
    let (result, answers) = run(handoff, |port, state| {
        let good_host = format!("127.0.0.1:{port}");
        let target = format!("/callback?code={CODE}&state={state}");
        let mut post = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).expect("connect");
        write!(post, "POST {target} HTTP/1.1\r\nHost: {good_host}\r\n\r\n").expect("write");
        let mut post_answer = String::new();
        post.read_to_string(&mut post_answer).expect("read");
        vec![
            get(
                port,
                &format!("/other?code={CODE}&state={state}"),
                &good_host,
            ),
            get(port, &target, &format!("localhost:{port}")),
            get(port, &target, "evil.example"),
            post_answer,
            get(port, &target, &good_host),
        ]
    });
    assert_eq!(result.expect("grant").code, CODE);
    for ignored in &answers[..4] {
        assert!(ignored.starts_with("HTTP/1.1 404"), "{ignored}");
    }
    assert!(answers[4].starts_with("HTTP/1.1 200 OK"));
}

#[test]
fn wrong_state_ends_the_handoff() {
    let handoff = start(Duration::from_secs(10));
    let (result, answers) = run(handoff, |port, _| {
        vec![get(
            port,
            &format!("/callback?code={CODE}&state=someone-elses-state"),
            &format!("127.0.0.1:{port}"),
        )]
    });
    assert_eq!(result, Err(HandoffError::InvalidCallback));
    assert!(answers[0].starts_with("HTTP/1.1 400"));
}

#[test]
fn missing_state_duplicate_and_unknown_parameters_are_invalid() {
    for query in [
        format!("code={CODE}"),
        format!("code={CODE}&code={CODE}&state=STATE"),
        format!("code={CODE}&state=STATE&extra=1"),
        "state=STATE".to_owned(),
        "code=short&state=STATE".to_owned(),
        "code=has%20escape-0123456789&state=STATE".to_owned(),
        format!("code={CODE}&error=denied&state=STATE"),
        "error=other&state=STATE".to_owned(),
    ] {
        let handoff = start(Duration::from_secs(10));
        let (result, _) = run(handoff, |port, state| {
            vec![get(
                port,
                &format!("/callback?{}", query.replace("STATE", state)),
                &format!("127.0.0.1:{port}"),
            )]
        });
        assert_eq!(result, Err(HandoffError::InvalidCallback), "{query}");
    }
}

#[test]
fn a_decline_is_reported_as_denied() {
    let handoff = start(Duration::from_secs(10));
    let (result, _) = run(handoff, |port, state| {
        vec![get(
            port,
            &format!("/callback?error=denied&state={state}"),
            &format!("127.0.0.1:{port}"),
        )]
    });
    assert_eq!(result, Err(HandoffError::Denied));
}

#[test]
fn times_out_without_a_callback() {
    let started = Instant::now();
    assert_eq!(
        start(Duration::from_millis(200)).wait(),
        Err(HandoffError::TimedOut)
    );
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn can_be_cancelled_from_another_thread() {
    let handoff = start(Duration::from_secs(30));
    let cancel = handoff.cancel_handle();
    let waiter = thread::spawn(move || handoff.wait());
    cancel.cancel();
    assert_eq!(waiter.join().expect("join"), Err(HandoffError::Cancelled));
}

#[test]
fn a_silent_connection_does_not_block_later_callbacks_forever() {
    let handoff = start(Duration::from_secs(20));
    let (result, _) = run(handoff, |port, state| {
        let silent = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).expect("connect");
        drop(silent);
        vec![get(
            port,
            &format!("/callback?code={CODE}&state={state}"),
            &format!("127.0.0.1:{port}"),
        )]
    });
    assert_eq!(result.expect("grant").code, CODE);
}

#[test]
fn rejects_a_callback_path_with_a_query() {
    let config = HandoffConfig {
        callback_path: "/cb?x=1".to_owned(),
        ..HandoffConfig::default()
    };
    assert!(matches!(
        Handoff::start(config),
        Err(HandoffError::Setup(_))
    ));
}
