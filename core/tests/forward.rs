use firewall::aliasing::forward::{downgrade, upstream_url};
use firewall::FirewallState;
use rama::http::{Body, Request};

fn request(target: &str, host: Option<&str>) -> Request {
    let mut builder = Request::builder().method("GET").uri(target);
    if let Some(host) = host {
        builder = builder.header("host", host);
    }
    builder.body(Body::empty()).expect("valid request")
}

#[test]
fn requests_always_go_out_over_tls() {
    for target in ["http://pypi.org/six", "HTTP://pypi.org/six", "https://pypi.org/six"] {
        assert_eq!(
            upstream_url(&request(target, None)).unwrap_or_default(),
            "https://pypi.org/six"
        );
    }
    assert_eq!(
        upstream_url(&request("/six", Some("pypi.org"))).unwrap_or_default(),
        "https://pypi.org/six"
    );
    assert_eq!(upstream_url(&request("/six", None)), None);
}

#[test]
fn downgrade_touches_known_hosts_in_text_only() {
    let text = b"https://pypi.org/x https://example.com/y".to_vec();
    let state = FirewallState::default();
    assert_eq!(downgrade(&state, text), b"http://pypi.org/x https://example.com/y".to_vec());
    let binary = vec![0x1f, 0x8b, 0xff, 0xfe];
    assert_eq!(downgrade(&state, binary.clone()), binary);
}
