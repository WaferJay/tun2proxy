use super::*;
use crate::directions::{IncomingDataEvent, OutgoingDataEvent, OutgoingDirection};
use crate::proxy_handler::ProxyHandler;
use crate::session_info::{IpProtocol, SessionInfo};
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::net::TcpListener;

/// Mock ProxyHandler for testing handle_proxy_session's ProxyResult mapping.
///
/// - When `established` is true at construction, the handshake loop exits immediately
///   (no TCP I/O needed). Used for Established and UdpAssociate tests.
/// - When `bypass_to` is Some, the handler starts unestablished with a dummy outbuf byte.
///   On `push_data`, it changes `server_addr` to `bypass_to` and sets `established = true`.
///   This simulates a proxy handler that triggers the Bypass path.
struct MockHandler {
    server_addr: SocketAddr,
    session_info: SessionInfo,
    udp_associate: Option<SocketAddr>,
    bypass_to: Option<SocketAddr>,
    established: bool,
    outbuf: Vec<u8>,
}

impl MockHandler {
    fn established(server_addr: SocketAddr, udp_associate: Option<SocketAddr>) -> Self {
        let info = SessionInfo::new(
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 1111),
            SocketAddr::new(Ipv4Addr::new(93, 184, 216, 34).into(), 443),
            IpProtocol::Tcp,
        );
        Self {
            server_addr,
            session_info: info,
            udp_associate,
            bypass_to: None,
            established: true,
            outbuf: vec![],
        }
    }

    fn bypass(server_addr: SocketAddr, bypass_to: SocketAddr) -> Self {
        let info = SessionInfo::new(
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 1111),
            SocketAddr::new(Ipv4Addr::new(93, 184, 216, 34).into(), 443),
            IpProtocol::Tcp,
        );
        Self {
            server_addr,
            session_info: info,
            udp_associate: None,
            bypass_to: Some(bypass_to),
            established: false,
            outbuf: vec![0x01], // dummy handshake byte
        }
    }
}

#[async_trait::async_trait]
impl ProxyHandler for MockHandler {
    fn get_server_addr(&self) -> SocketAddr {
        self.server_addr
    }
    fn get_session_info(&self) -> SessionInfo {
        self.session_info
    }
    fn get_domain_name(&self) -> Option<String> {
        None
    }
    async fn push_data(&mut self, _event: IncomingDataEvent<'_>) -> std::io::Result<()> {
        if let Some(addr) = self.bypass_to {
            self.server_addr = addr;
        }
        self.established = true;
        Ok(())
    }
    fn consume_data(&mut self, _dir: OutgoingDirection, size: usize) {
        self.outbuf.drain(..size);
    }
    fn peek_data(&mut self, dir: OutgoingDirection) -> OutgoingDataEvent<'_> {
        OutgoingDataEvent {
            direction: dir,
            buffer: &self.outbuf,
        }
    }
    fn connection_established(&self) -> bool {
        self.established
    }
    fn data_len(&self, _dir: OutgoingDirection) -> usize {
        self.outbuf.len()
    }
    fn reset_connection(&self) -> bool {
        false
    }
    fn get_udp_associate(&self) -> Option<SocketAddr> {
        self.udp_associate
    }
}

/// Create a connected TCP pair using a loopback listener.
async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = TcpStream::connect(addr).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();
    (client, server)
}

#[tokio::test]
async fn test_proxy_result_established() {
    let (mut client, _server_side) = tcp_pair().await;
    let proxy_addr = SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), 8080);
    let handler: Arc<Mutex<dyn ProxyHandler>> = Arc::new(Mutex::new(MockHandler::established(proxy_addr, None)));

    let result = handle_proxy_session(&mut client, handler).await.unwrap();
    assert!(matches!(result, ProxyResult::Established));
}

#[tokio::test]
async fn test_proxy_result_udp_associate() {
    let (mut client, _server_side) = tcp_pair().await;
    let proxy_addr = SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), 8080);
    let udp_addr = SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), 9090);
    let handler: Arc<Mutex<dyn ProxyHandler>> = Arc::new(Mutex::new(MockHandler::established(proxy_addr, Some(udp_addr))));

    let result = handle_proxy_session(&mut client, handler).await.unwrap();
    if let ProxyResult::UdpAssociate(addr) = result {
        assert_eq!(addr, udp_addr);
    } else {
        panic!("expected ProxyResult::UdpAssociate");
    }
}

#[tokio::test]
async fn test_proxy_result_bypass() {
    let (mut client, mut server_side) = tcp_pair().await;
    let proxy_addr = SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), 8080);
    let bypass_addr = SocketAddr::new(Ipv4Addr::new(93, 184, 216, 34).into(), 443);
    let handler: Arc<Mutex<dyn ProxyHandler>> = Arc::new(Mutex::new(MockHandler::bypass(proxy_addr, bypass_addr)));

    // The mock sends one dummy byte, then reads a response to trigger push_data.
    // Spawn a task to echo back so the handshake loop can proceed.
    tokio::spawn(async move {
        let mut buf = [0u8; 64];
        let n = server_side.read(&mut buf).await.unwrap();
        server_side.write_all(&buf[..n]).await.unwrap();
    });

    let result = handle_proxy_session(&mut client, handler).await.unwrap();
    if let ProxyResult::Bypass(addr) = result {
        assert_eq!(addr, bypass_addr);
    } else {
        panic!("expected ProxyResult::Bypass");
    }
}

// --- try_resolve_from_cache tests ---

fn make_shared_dns_cache() -> dns_mapping::SharedDnsCache {
    Arc::new(Mutex::new(dns_mapping::DnsCache::new()))
}

#[tokio::test]
async fn test_try_resolve_from_cache_hit() {
    let cache = make_shared_dns_cache();
    let ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
    cache.lock().await.insert("example.com", &[(ip, 300)]);

    let query = dns::build_dns_query("example.com", 0xABCD).unwrap();
    let result = try_resolve_from_cache(&query, &cache, true).await;

    assert!(result.is_some());
    let response_bytes = result.unwrap();
    let msg = dns::parse_data_to_dns_message(&response_bytes, false).unwrap();
    assert_eq!(msg.id(), 0xABCD);
    assert_eq!(msg.answers().len(), 1);
    let extracted = dns::extract_ipaddr_from_dns_message(&msg).unwrap();
    assert_eq!(extracted, ip);
}

#[tokio::test]
async fn test_try_resolve_from_cache_miss() {
    let cache = make_shared_dns_cache();
    // Cache is empty — should return None
    let query = dns::build_dns_query("example.com", 0x1234).unwrap();
    let result = try_resolve_from_cache(&query, &cache, true).await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_try_resolve_from_cache_miss_different_domain() {
    let cache = make_shared_dns_cache();
    let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    cache.lock().await.insert("other.com", &[(ip, 300)]);

    // Query for a domain not in cache
    let query = dns::build_dns_query("example.com", 0x5678).unwrap();
    let result = try_resolve_from_cache(&query, &cache, true).await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_try_resolve_from_cache_ipv6_disabled_v4_only() {
    let cache = make_shared_dns_cache();
    let v4 = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    cache.lock().await.insert("example.com", &[(v4, 300)]);

    let query = dns::build_dns_query("example.com", 0x1111).unwrap();
    let result = try_resolve_from_cache(&query, &cache, false).await;

    // IPv4-only cache entry should still return when ipv6 disabled
    assert!(result.is_some());
    let msg = dns::parse_data_to_dns_message(&result.unwrap(), false).unwrap();
    assert_eq!(msg.answers().len(), 1);
}

#[tokio::test]
async fn test_try_resolve_from_cache_ipv6_disabled_v6_only() {
    let cache = make_shared_dns_cache();
    let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    cache.lock().await.insert("example.com", &[(v6, 300)]);

    let query = dns::build_dns_query("example.com", 0x2222).unwrap();
    let result = try_resolve_from_cache(&query, &cache, false).await;

    // Only IPv6 cached, but ipv6 disabled → all records removed → should return None
    assert!(result.is_none());
}

#[tokio::test]
async fn test_try_resolve_from_cache_ipv6_disabled_mixed() {
    let cache = make_shared_dns_cache();
    let v4 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    cache.lock().await.insert("dual.example.com", &[(v4, 300), (v6, 300)]);

    let query = dns::build_dns_query("dual.example.com", 0x3333).unwrap();
    let result = try_resolve_from_cache(&query, &cache, false).await;

    // IPv6 removed, IPv4 remains
    assert!(result.is_some());
    let msg = dns::parse_data_to_dns_message(&result.unwrap(), false).unwrap();
    assert_eq!(msg.answers().len(), 1);
    let extracted = dns::extract_ipaddr_from_dns_message(&msg).unwrap();
    assert_eq!(extracted, v4);
}

#[tokio::test]
async fn test_try_resolve_from_cache_ipv6_enabled_mixed() {
    let cache = make_shared_dns_cache();
    let v4 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    cache.lock().await.insert("dual.example.com", &[(v4, 300), (v6, 300)]);

    let query = dns::build_dns_query("dual.example.com", 0x4444).unwrap();
    let result = try_resolve_from_cache(&query, &cache, true).await;

    // Both records should be present
    assert!(result.is_some());
    let msg = dns::parse_data_to_dns_message(&result.unwrap(), false).unwrap();
    assert_eq!(msg.answers().len(), 2);
}

#[tokio::test]
async fn test_try_resolve_from_cache_invalid_data() {
    let cache = make_shared_dns_cache();
    // Garbage data that can't be parsed as DNS
    let result = try_resolve_from_cache(&[0xFF, 0xFE, 0x00], &cache, true).await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_try_resolve_from_cache_preserves_query_id() {
    let cache = make_shared_dns_cache();
    let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    cache.lock().await.insert("dns.google", &[(ip, 60)]);

    // Different query IDs should produce responses with matching IDs
    for id in [0x0001, 0x9999, 0xFFFF] {
        let query = dns::build_dns_query("dns.google", id).unwrap();
        let result = try_resolve_from_cache(&query, &cache, true).await.unwrap();
        let msg = dns::parse_data_to_dns_message(&result, false).unwrap();
        assert_eq!(msg.id(), id);
    }
}

#[tokio::test]
async fn test_try_resolve_from_cache_multiple_v4_records() {
    let cache = make_shared_dns_cache();
    let ip1 = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    let ip2 = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));
    let ip3 = IpAddr::V4(Ipv4Addr::new(9, 10, 11, 12));
    cache.lock().await.insert("cdn.example.com", &[(ip1, 60), (ip2, 120), (ip3, 180)]);

    let query = dns::build_dns_query("cdn.example.com", 0x7777).unwrap();
    let result = try_resolve_from_cache(&query, &cache, true).await;

    assert!(result.is_some());
    let msg = dns::parse_data_to_dns_message(&result.unwrap(), false).unwrap();
    assert_eq!(msg.answers().len(), 3);
    let pairs = dns::extract_ip_ttl_pairs_from_dns_message(&msg);
    assert_eq!(pairs[0].0, ip1);
    assert_eq!(pairs[1].0, ip2);
    assert_eq!(pairs[2].0, ip3);
}
