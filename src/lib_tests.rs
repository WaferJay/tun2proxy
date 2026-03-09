use super::*;
use crate::directions::{IncomingDataEvent, OutgoingDataEvent, OutgoingDirection};
use crate::proxy_handler::ProxyHandler;
use crate::session_info::{IpProtocol, SessionInfo};
use std::net::Ipv4Addr;
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
    let handler: Arc<Mutex<dyn ProxyHandler>> =
        Arc::new(Mutex::new(MockHandler::established(proxy_addr, None)));

    let result = handle_proxy_session(&mut client, handler).await.unwrap();
    assert!(matches!(result, ProxyResult::Established));
}

#[tokio::test]
async fn test_proxy_result_udp_associate() {
    let (mut client, _server_side) = tcp_pair().await;
    let proxy_addr = SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), 8080);
    let udp_addr = SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), 9090);
    let handler: Arc<Mutex<dyn ProxyHandler>> =
        Arc::new(Mutex::new(MockHandler::established(proxy_addr, Some(udp_addr))));

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
    let handler: Arc<Mutex<dyn ProxyHandler>> =
        Arc::new(Mutex::new(MockHandler::bypass(proxy_addr, bypass_addr)));

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
