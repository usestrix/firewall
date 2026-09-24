use firewall::aliasing::forward::downgrade;
use firewall::http::https_url;
use firewall::Firewall;
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
    let targets = [
        "http://pypi.org/six",
        "HTTP://pypi.org/six",
        "https://pypi.org/six",
        "http://pypi.org:443/six",
        "http://user:pass@pypi.org/six",
        "http://PYPI.ORG./six",
    ];
    for target in targets {
        assert_eq!(https_url(&request(target, None)).unwrap_or_default(), "https://pypi.org/six");
    }
    assert_eq!(
        https_url(&request("/six", Some("pypi.org"))).unwrap_or_default(),
        "https://pypi.org/six"
    );
    assert_eq!(
        https_url(&request("/six", Some("PyPI.org."))).unwrap_or_default(),
        "https://pypi.org/six"
    );
    assert_eq!(https_url(&request("/six", None)), None);
}

#[tokio::test]
async fn downgrade_touches_known_hosts_in_text_only() {
    let text = b"https://pypi.org/x https://example.com/y".to_vec();
    let firewall = Firewall::default();
    assert_eq!(downgrade(&firewall, text), b"http://pypi.org/x https://example.com/y".to_vec());
    let binary = vec![0x1f, 0x8b, 0xff, 0xfe];
    assert_eq!(downgrade(&firewall, binary.clone()), binary);
}
