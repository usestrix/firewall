use firewall::aliasing::forward::downgrade;
use firewall::http::https_url;
use firewall::{aliasing, Firewall, FirewallConfig};
use rama::http::{Body, Request};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

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

#[test]
fn a_plain_http_upstream_is_not_upgraded() {
    let upstream = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = upstream.local_addr().expect("address");
    std::thread::spawn(move || {
        let (mut stream, _) = upstream.accept().expect("accept");
        let _ = stream.read(&mut [0; 4096]);
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    });

    let port = aliasing::spawn(0, FirewallConfig::default()).expect("spawn");
    let mut proxy = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let request = format!("GET http://{addr}/x HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    proxy.write_all(request.as_bytes()).expect("write");
    let mut response = String::new();
    proxy.read_to_string(&mut response).expect("read");
    assert!(response.starts_with("HTTP/1.1 200") && response.ends_with("ok"), "{response}");
}

#[tokio::test]
async fn downgrade_touches_known_hosts_in_text_only() {
    let text = b"https://pypi.org/x https://example.com/y".to_vec();
    let firewall = Firewall::default();
    assert_eq!(downgrade(&firewall, text), b"http://pypi.org/x https://example.com/y".to_vec());
    let binary = vec![0x1f, 0x8b, 0xff, 0xfe];
    assert_eq!(downgrade(&firewall, binary.clone()), binary);
}
