use super::*;
use crate::directions::{IncomingDataEvent, IncomingDirection, OutgoingDirection};
use crate::proxy_handler::ProxyHandler;
use crate::session_info::{IpProtocol, SessionInfo};
use std::net::{Ipv4Addr, SocketAddr};

/// Helper: create an `HttpConnection` with Basic auth, consume the initial CONNECT request,
/// and return `(conn, shared_auth)`.
async fn setup_conn_consume_first_request() -> (
    HttpConnection,
    Arc<Mutex<Option<Arc<dyn HttpAuthenticator>>>>,
) {
    let src = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 12345);
    let dst = SocketAddr::new(Ipv4Addr::new(93, 184, 216, 34).into(), 443);
    let proxy_addr = SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), 8080);
    let info = SessionInfo::new(src, dst, IpProtocol::Tcp);

    let credentials = UserKey::new("testuser", "testpass");
    let basic_auth: Arc<dyn HttpAuthenticator> =
        Arc::new(BasicPasswordAuthenticator::new(credentials));
    let shared_auth: Arc<Mutex<Option<Arc<dyn HttpAuthenticator>>>> =
        Arc::new(Mutex::new(Some(basic_auth.clone())));

    let mut conn = HttpConnection::new(
        proxy_addr,
        info,
        None,
        Some(basic_auth),
        shared_auth.clone(),
    )
    .await
    .expect("HttpConnection::new should succeed");

    // Consume the initial CONNECT request so callers can feed responses directly.
    let len = conn.data_len(OutgoingDirection::ToServer);
    conn.consume_data(OutgoingDirection::ToServer, len);

    (conn, shared_auth)
}

#[tokio::test]
async fn test_basic_to_digest_upgrade() {
    let src = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 12345);
    let dst = SocketAddr::new(Ipv4Addr::new(93, 184, 216, 34).into(), 443);
    let proxy_addr = SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), 8080);
    let info = SessionInfo::new(src, dst, IpProtocol::Tcp);

    let credentials = UserKey::new("testuser", "testpass");
    let basic_auth: Arc<dyn HttpAuthenticator> =
        Arc::new(BasicPasswordAuthenticator::new(credentials));
    let shared_auth: Arc<Mutex<Option<Arc<dyn HttpAuthenticator>>>> =
        Arc::new(Mutex::new(Some(basic_auth.clone())));

    let mut conn = HttpConnection::new(
        proxy_addr,
        info,
        None,
        Some(basic_auth),
        shared_auth.clone(),
    )
    .await
    .expect("HttpConnection::new should succeed");

    // ① + ② The constructor sends the first CONNECT request; verify it contains Basic auth.
    let event = conn.peek_data(OutgoingDirection::ToServer);
    let request = str::from_utf8(event.buffer).expect("request should be valid UTF-8");
    assert!(
        request.contains("CONNECT"),
        "first request should be a CONNECT request"
    );
    assert!(
        request.contains("Proxy-Authorization: Basic "),
        "first request should contain Basic auth header, got:\n{request}"
    );

    // ③ Consume the first request.
    let len = conn.data_len(OutgoingDirection::ToServer);
    conn.consume_data(OutgoingDirection::ToServer, len);

    // ④ Feed a 407 Proxy Authentication Required with a Digest challenge (keep-alive path).
    let response_407 = b"HTTP/1.1 407 Proxy Authentication Required\r\n\
        Proxy-Authenticate: Digest realm=\"test\", nonce=\"testnonce123\", qop=\"auth\"\r\n\
        Content-Length: 0\r\n\
        \r\n";
    conn.push_data(IncomingDataEvent {
        direction: IncomingDirection::FromServer,
        buffer: response_407,
    })
    .await
    .expect("push_data with 407 should succeed");

    // ⑤ The state machine should have generated a new CONNECT with Digest auth.
    assert!(
        !conn.connection_established(),
        "should not be established after 407"
    );
    let event = conn.peek_data(OutgoingDirection::ToServer);
    let request = str::from_utf8(event.buffer).expect("request should be valid UTF-8");
    assert!(
        request.contains("CONNECT"),
        "second request should be a CONNECT request"
    );
    assert!(
        request.contains("Proxy-Authorization: Digest "),
        "second request should contain Digest auth header, got:\n{request}"
    );
    assert!(
        !request.contains("Basic"),
        "second request should NOT contain Basic, got:\n{request}"
    );

    // ⑥ Consume the second request.
    let len = conn.data_len(OutgoingDirection::ToServer);
    conn.consume_data(OutgoingDirection::ToServer, len);

    // ⑦ Feed a 200 Connection Established.
    let response_200 = b"HTTP/1.1 200 Connection Established\r\n\r\n";
    conn.push_data(IncomingDataEvent {
        direction: IncomingDirection::FromServer,
        buffer: response_200,
    })
    .await
    .expect("push_data with 200 should succeed");

    // ⑧ The tunnel should now be established.
    assert!(
        conn.connection_established(),
        "connection should be established after 200"
    );

    // ⑨ Verify data passthrough: server → client.
    let tunnel_data = b"Hello from server";
    conn.push_data(IncomingDataEvent {
        direction: IncomingDirection::FromServer,
        buffer: tunnel_data,
    })
    .await
    .expect("push_data with tunnel data should succeed");

    let event = conn.peek_data(OutgoingDirection::ToClient);
    assert_eq!(
        event.buffer, tunnel_data,
        "tunnel data should be forwarded to client"
    );

    // ⑩ Verify shared_auth has been upgraded to DigestPasswordAuthenticator.
    let guard = shared_auth.lock().await;
    let auth = guard.as_ref().expect("shared_auth should be Some");
    // Generate headers and verify they produce Digest (not Basic).
    let headers = auth
        .generate_auth_headers("test:443")
        .await
        .expect("generate_auth_headers should succeed");
    assert_eq!(headers.len(), 1);
    assert!(
        headers[0].1.starts_with("Digest "),
        "shared_auth should produce Digest headers, got: {}",
        headers[0].1
    );
}

#[tokio::test]
async fn test_non_407_error_propagates() {
    let (mut conn, _shared_auth) = setup_conn_consume_first_request().await;

    // Feed a 403 Forbidden — the authenticator returns Abort for non-407 status codes,
    // so the state machine should propagate the error.
    let response_403 = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
    let result = conn
        .push_data(IncomingDataEvent {
            direction: IncomingDirection::FromServer,
            buffer: response_403,
        })
        .await;

    assert!(result.is_err(), "non-407 error should propagate as Err");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("403") && err_msg.contains("Forbidden"),
        "error should contain status code and reason, got: {err_msg}"
    );
    assert!(
        !conn.connection_established(),
        "connection should not be established after 403"
    );
}

#[tokio::test]
async fn test_non_407_error_without_auth() {
    let src = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 12345);
    let dst = SocketAddr::new(Ipv4Addr::new(93, 184, 216, 34).into(), 443);
    let proxy_addr = SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), 8080);
    let info = SessionInfo::new(src, dst, IpProtocol::Tcp);

    let shared_auth: Arc<Mutex<Option<Arc<dyn HttpAuthenticator>>>> =
        Arc::new(Mutex::new(None));

    let mut conn = HttpConnection::new(proxy_addr, info, None, None, shared_auth)
        .await
        .expect("HttpConnection::new should succeed");

    // Consume the initial (unauthenticated) CONNECT request.
    let len = conn.data_len(OutgoingDirection::ToServer);
    conn.consume_data(OutgoingDirection::ToServer, len);

    // Without an authenticator, any non-200 response should error immediately
    // because there is no authenticator to delegate to.
    let response_502 = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
    let result = conn
        .push_data(IncomingDataEvent {
            direction: IncomingDirection::FromServer,
            buffer: response_502,
        })
        .await;

    assert!(result.is_err(), "non-200 without auth should be an error");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("502") && err_msg.contains("Bad Gateway"),
        "error should contain status code and reason, got: {err_msg}"
    );
}
