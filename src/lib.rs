#[cfg(feature = "udpgw")]
use crate::udpgw::UdpGwClient;
pub use crate::{
    directions::{IncomingDataEvent, IncomingDirection, OutgoingDirection},
    no_proxy::NoProxyManager,
    session_info::{IpProtocol, SessionInfo},
    virtual_dns::VirtualDns,
};
pub use clap::ValueEnum;
use ipstack::{IpStackStream, IpStackTcpStream, IpStackUdpStream};
pub use proxy_handler::ProxyHandler;
use socks::SocksProxyManager;
pub use socks5_impl::protocol::UserKey;
#[cfg(feature = "udpgw")]
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::{
    collections::VecDeque,
    io::ErrorKind,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpSocket, TcpStream, UdpSocket},
    sync::{Mutex, mpsc::Receiver},
};
pub use tokio_util::sync::CancellationToken;
use tproxy_config::is_private_ip;
pub use tun::DEFAULT_MTU;
use udp_stream::UdpStream;
#[cfg(feature = "udpgw")]
use udpgw::{UDPGW_KEEPALIVE_TIME, UDPGW_MAX_CONNECTIONS, UdpGwClientStream, UdpGwResponse};

pub use {
    args::{ArgDns, ArgProxy, ArgVerbosity, Args, ProxyType},
    error::{BoxError, Error, Result},
    http::{AuthResult, HttpAuthenticator, HttpManager, PasswordAuthenticator},
    proxy_handler::ProxyHandlerManager,
    traffic_status::{TrafficStatus, tun2proxy_set_traffic_status_callback},
};

#[cfg(feature = "mimalloc")]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

pub use general_api::general_run_async;

pub const FORCE_EXIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

mod android;
mod args;
mod directions;
mod dns;
mod dns_mapping;
mod dump_logger;
mod error;
mod general_api;
mod http;
mod no_proxy;
mod proxy_handler;
mod session_info;
pub mod socket_transfer;
mod socks;
mod traffic_status;
#[cfg(feature = "udpgw")]
pub mod udpgw;
mod virtual_dns;
#[doc(hidden)]
pub mod win_svc;

const DNS_PORT: u16 = 53;

/// Result of a proxy handshake session.
enum ProxyResult {
    /// Proxy connection established normally.
    Established,
    /// Proxy indicated bypass; connect directly to this address instead.
    Bypass(SocketAddr),
    /// Proxy returned a UDP associate address.
    UdpAssociate(SocketAddr),
}

#[allow(unused)]
#[derive(Hash, Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(
    target_os = "linux",
    derive(bincode::Encode, bincode::Decode, serde::Serialize, serde::Deserialize)
)]
pub enum SocketProtocol {
    Tcp,
    Udp,
}

#[allow(unused)]
#[derive(Hash, Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(
    target_os = "linux",
    derive(bincode::Encode, bincode::Decode, serde::Serialize, serde::Deserialize)
)]
pub enum SocketDomain {
    IpV4,
    IpV6,
}

impl From<IpAddr> for SocketDomain {
    fn from(value: IpAddr) -> Self {
        match value {
            IpAddr::V4(_) => Self::IpV4,
            IpAddr::V6(_) => Self::IpV6,
        }
    }
}

struct SocketQueue {
    tcp_v4: Mutex<Receiver<TcpSocket>>,
    tcp_v6: Mutex<Receiver<TcpSocket>>,
    udp_v4: Mutex<Receiver<UdpSocket>>,
    udp_v6: Mutex<Receiver<UdpSocket>>,
}

impl SocketQueue {
    async fn recv_tcp(&self, domain: SocketDomain) -> Result<TcpSocket, std::io::Error> {
        match domain {
            SocketDomain::IpV4 => &self.tcp_v4,
            SocketDomain::IpV6 => &self.tcp_v6,
        }
        .lock()
        .await
        .recv()
        .await
        .ok_or(ErrorKind::Other.into())
    }
    async fn recv_udp(&self, domain: SocketDomain) -> Result<UdpSocket, std::io::Error> {
        match domain {
            SocketDomain::IpV4 => &self.udp_v4,
            SocketDomain::IpV6 => &self.udp_v6,
        }
        .lock()
        .await
        .recv()
        .await
        .ok_or(ErrorKind::Other.into())
    }
}

async fn create_tcp_stream(socket_queue: &Option<Arc<SocketQueue>>, peer: SocketAddr) -> std::io::Result<TcpStream> {
    match &socket_queue {
        None => TcpStream::connect(peer).await,
        Some(queue) => queue.recv_tcp(peer.ip().into()).await?.connect(peer).await,
    }
}

async fn create_udp_stream(socket_queue: &Option<Arc<SocketQueue>>, peer: SocketAddr) -> std::io::Result<UdpStream> {
    match &socket_queue {
        None => UdpStream::connect(peer).await,
        Some(queue) => {
            let socket = queue.recv_udp(peer.ip().into()).await?;
            socket.connect(peer).await?;
            UdpStream::from_tokio(socket, peer).await
        }
    }
}

async fn resolve_domain(
    domain: &str,
    port: u16,
    dns_addr: SocketAddr,
    socket_queue: &Option<Arc<SocketQueue>>,
    dns_cache: &dns_mapping::SharedDnsCache,
) -> crate::Result<SocketAddr> {
    // 1. Cache lookup
    if let Some(ips) = dns_cache.lock().await.lookup_ips(domain) {
        if let Some(ip) = ips.first() {
            return Ok(SocketAddr::new(*ip, port));
        }
    }

    // 2. Cache miss → network query
    let id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u16)
        .unwrap_or(0);
    let query = dns::build_dns_query(domain, id)?;

    let mut dns_server = create_udp_stream(socket_queue, dns_addr).await?;
    dns_server.write_all(&query).await?;

    let mut buf = [0u8; 4096];
    let len = tokio::time::timeout(std::time::Duration::from_secs(5), dns_server.read(&mut buf))
        .await
        .map_err(|_| "DNS resolve timeout")?
        .map_err(|e| format!("DNS resolve read error: {e}"))?;

    let message = dns::parse_data_to_dns_message(&buf[..len], false)?;
    let ip = dns::extract_ipaddr_from_dns_message(&message)?;

    // 3. Store results in cache
    let records = dns::extract_dns_records_from_message(&message);
    if records
        .iter()
        .any(|r| matches!(r, dns_mapping::DnsRecord::A(..) | dns_mapping::DnsRecord::AAAA(..)))
    {
        dns_cache.lock().await.insert(domain, &records);
    }

    Ok(SocketAddr::new(ip, port))
}

async fn lookup_domain_name(
    ip: &IpAddr,
    virtual_dns: &Option<Arc<Mutex<VirtualDns>>>,
    dns_cache: &dns_mapping::SharedDnsCache,
) -> Option<String> {
    let domain_name = if let Some(virtual_dns) = virtual_dns {
        let mut virtual_dns = virtual_dns.lock().await;
        virtual_dns.touch_ip(ip);
        virtual_dns.resolve_ip(ip).cloned()
    } else {
        None
    };
    match domain_name {
        Some(name) => Some(name),
        None => dns_cache
            .lock()
            .await
            .lookup_domains(ip)
            .and_then(|domains| domains.first().map(|s| s.to_string())),
    }
}

/// Conservative bypass check: only bypass when ALL domains for an IP match.
///
/// Virtual DNS provides a 1:1 mapping (one fake IP per domain), so a single
/// match is sufficient.  DNS cache, however, can map one IP to many domains
/// (e.g. CDN shared IPs), so ALL associated domains must match.
async fn check_bypass_ip(
    ip: &IpAddr,
    virtual_dns: &Option<Arc<Mutex<VirtualDns>>>,
    dns_cache: &dns_mapping::SharedDnsCache,
    bypass_matcher: &dns_mapping::BypassMatcher,
) -> bool {
    if bypass_matcher.is_empty() {
        return false;
    }

    // Virtual DNS: 1:1 mapping, single domain is definitive.
    if let Some(virtual_dns) = virtual_dns {
        let mut virtual_dns = virtual_dns.lock().await;
        if let Some(domain) = virtual_dns.resolve_ip(ip) {
            return bypass_matcher.matches(domain);
        }
    }

    // DNS cache: one IP may map to multiple domains.
    // Conservative: only bypass when ALL associated domains match.
    let cache = dns_cache.lock().await;
    cache.lookup_domains(ip).is_some_and(|domains| bypass_matcher.matches_all(&domains))
}

/// When bypassing in Virtual DNS mode, resolve the fake IP to a real address.
/// Returns `false` if resolution fails, signaling the caller to fall back to proxy.
async fn resolve_bypass_destination(
    info: &mut SessionInfo,
    domain_name: &Option<String>,
    is_virtual_dns: bool,
    dns_addr: IpAddr,
    socket_queue: &Option<Arc<SocketQueue>>,
    dns_cache: &dns_mapping::SharedDnsCache,
) -> bool {
    if is_virtual_dns {
        if let Some(domain) = domain_name {
            let dns_sock = SocketAddr::new(dns_addr, DNS_PORT);
            match resolve_domain(domain, info.dst.port(), dns_sock, socket_queue, dns_cache).await {
                Ok(addr) => info.dst = addr,
                Err(e) => {
                    log::warn!("Cannot resolve {domain} for bypass, falling back to proxy: {e}");
                    return false;
                }
            }
        }
    }
    log::info!("Bypassing proxy for {info} (domain: {domain_name:?})");
    true
}

async fn snoop_dns_response(data: &[u8], dns_cache: &dns_mapping::SharedDnsCache, ipv6_enabled: bool) -> crate::Result<Vec<u8>> {
    let mut message = dns::parse_data_to_dns_message(data, false)?;
    if let Ok(name) = dns::extract_domain_from_dns_message(&message) {
        let records = dns::extract_dns_records_from_message(&message);
        if records
            .iter()
            .any(|r| matches!(r, dns_mapping::DnsRecord::A(..) | dns_mapping::DnsRecord::AAAA(..)))
        {
            dns_cache.lock().await.insert(&name, &records);
        }
    }
    if !ipv6_enabled {
        dns::remove_ipv6_entries(&mut message);
    }
    Ok(message.to_vec()?)
}

/// Run the proxy server
/// # Arguments
/// * `device` - The network device to use
/// * `mtu` - The MTU of the network device
/// * `args` - The arguments to use
/// * `shutdown_token` - The token to exit the server
/// # Returns
/// * The number of sessions while exiting
pub async fn run<D>(
    device: D,
    mtu: u16,
    args: Args,
    shutdown_token: CancellationToken,
    proxy_handler_manager: Option<Arc<dyn ProxyHandlerManager>>,
) -> crate::Result<usize>
where
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    log::info!("{} {} starting...", env!("CARGO_PKG_NAME"), version_info!());
    log::info!("Proxy {} server: {}", args.proxy.proxy_type, args.proxy.addr);

    let server_addr = args.proxy.addr;
    let key = args.proxy.credentials.clone();
    let dns_addr = args.dns_addr;
    let ipv6_enabled = args.ipv6_enabled;
    let virtual_dns = if args.dns == ArgDns::Virtual {
        Some(Arc::new(Mutex::new(VirtualDns::new(args.virtual_dns_pool))))
    } else {
        None
    };

    let bypass_matcher = dns_mapping::BypassMatcher::new(&args.bypass_domain);
    let dns_cache: dns_mapping::SharedDnsCache = Arc::new(Mutex::new(dns_mapping::DnsCache::new()));
    let no_proxy_mgr: Arc<dyn ProxyHandlerManager> = Arc::new(NoProxyManager::new());

    // Periodically evict expired DNS cache entries.
    {
        let dns_cache = dns_cache.clone();
        let shutdown = shutdown_token.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = tokio::time::sleep(dns_mapping::MIN_TTL) => {
                        dns_cache.lock().await.evict_expired();
                    }
                }
            }
        });
    }

    #[cfg(target_os = "linux")]
    let socket_queue = match args.socket_transfer_fd {
        None => None,
        Some(fd) => {
            use crate::socket_transfer::{reconstruct_socket, reconstruct_transfer_socket, request_sockets};
            use tokio::sync::mpsc::channel;

            let fd = reconstruct_socket(fd)?;
            let socket = reconstruct_transfer_socket(fd)?;
            let socket = Arc::new(Mutex::new(socket));

            macro_rules! create_socket_queue {
                ($domain:ident) => {{
                    const SOCKETS_PER_REQUEST: usize = 64;

                    let socket = socket.clone();
                    let (tx, rx) = channel(SOCKETS_PER_REQUEST);
                    tokio::spawn(async move {
                        loop {
                            let sockets =
                                match request_sockets(socket.lock().await, SocketDomain::$domain, SOCKETS_PER_REQUEST as u32).await {
                                    Ok(sockets) => sockets,
                                    Err(err) => {
                                        log::warn!("Socket allocation request failed: {err}");
                                        continue;
                                    }
                                };
                            for s in sockets {
                                if let Err(_) = tx.send(s).await {
                                    return;
                                }
                            }
                        }
                    });
                    Mutex::new(rx)
                }};
            }

            Some(Arc::new(SocketQueue {
                tcp_v4: create_socket_queue!(IpV4),
                tcp_v6: create_socket_queue!(IpV6),
                udp_v4: create_socket_queue!(IpV4),
                udp_v6: create_socket_queue!(IpV6),
            }))
        }
    };

    #[cfg(not(target_os = "linux"))]
    let socket_queue = None;

    let mgr: Arc<dyn ProxyHandlerManager> = match proxy_handler_manager {
        Some(m) => m,
        None => {
            use socks5_impl::protocol::Version::{V4, V5};
            match args.proxy.proxy_type {
                ProxyType::Socks5 => Arc::new(SocksProxyManager::new(server_addr, V5, key)),
                ProxyType::Socks4 => Arc::new(SocksProxyManager::new(server_addr, V4, key)),
                ProxyType::Http => {
                    let authenticator: Option<Arc<dyn HttpAuthenticator>> =
                        key.map(|credentials| Arc::new(PasswordAuthenticator::new(credentials)) as Arc<dyn HttpAuthenticator>);
                    Arc::new(HttpManager::new(server_addr, authenticator))
                }
                ProxyType::None => Arc::new(NoProxyManager::new()),
            }
        }
    };

    let mut ipstack_config = ipstack::IpStackConfig::default();
    ipstack_config.mtu(mtu)?;
    let mut tcp_cfg = ipstack::TcpConfig::default();
    tcp_cfg.timeout = std::time::Duration::from_secs(args.tcp_timeout);
    ipstack_config.with_tcp_config(tcp_cfg);
    ipstack_config.udp_timeout(std::time::Duration::from_secs(args.udp_timeout));

    let mut ip_stack = ipstack::IpStack::new(ipstack_config, device);

    #[cfg(feature = "udpgw")]
    let udpgw_client = args.udpgw_server.map(|addr| {
        log::info!("UDP Gateway enabled, server: {addr}");
        use std::time::Duration;
        let client = Arc::new(UdpGwClient::new(
            mtu,
            args.udpgw_connections.unwrap_or(UDPGW_MAX_CONNECTIONS),
            args.udpgw_keepalive.map(Duration::from_secs).unwrap_or(UDPGW_KEEPALIVE_TIME),
            args.udp_timeout,
            addr,
        ));
        let client_keepalive = client.clone();
        let shutdown_clone = shutdown_token.clone();
        tokio::spawn(async move {
            if let Err(err) = client_keepalive.heartbeat_task(shutdown_clone).await {
                log::error!("UDP Gateway heartbeat task error: {err}");
            }
        });
        client
    });

    let task_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    use std::sync::atomic::Ordering::Relaxed;

    loop {
        let task_count = task_count.clone();
        let virtual_dns = virtual_dns.clone();
        let ip_stack_stream = tokio::select! {
            _ = shutdown_token.cancelled() => {
                log::info!("Shutdown received");
                break;
            }
            ip_stack_stream = ip_stack.accept() => {
                ip_stack_stream?
            }
        };
        let max_sessions = args.max_sessions;
        match ip_stack_stream {
            IpStackStream::Tcp(tcp) => {
                if task_count.load(Relaxed) >= max_sessions {
                    if args.exit_on_fatal_error {
                        log::info!("Too many sessions that over {max_sessions}, exiting...");
                        break;
                    }
                    log::warn!("Too many sessions that over {max_sessions}, dropping new session");
                    continue;
                }
                log::trace!("Session count {}", task_count.fetch_add(1, Relaxed).saturating_add(1));
                let mut info = SessionInfo::new(tcp.local_addr(), tcp.peer_addr(), IpProtocol::Tcp);
                let domain_name = lookup_domain_name(&tcp.peer_addr().ip(), &virtual_dns, &dns_cache).await;
                let mut should_bypass = check_bypass_ip(&tcp.peer_addr().ip(), &virtual_dns, &dns_cache, &bypass_matcher).await;

                if should_bypass {
                    should_bypass =
                        resolve_bypass_destination(&mut info, &domain_name, virtual_dns.is_some(), dns_addr, &socket_queue, &dns_cache)
                            .await;
                }

                let handler_mgr = if should_bypass { &no_proxy_mgr } else { &mgr };
                let proxy_handler = handler_mgr.new_proxy_handler(info, domain_name, false).await?;
                let socket_queue = socket_queue.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_tcp_session(tcp, proxy_handler, socket_queue).await {
                        log::error!("{info} error \"{err}\"");
                    }
                    log::trace!("Session count {}", task_count.fetch_sub(1, Relaxed).saturating_sub(1));
                });
            }
            IpStackStream::Udp(udp) => {
                if task_count.load(Relaxed) >= max_sessions {
                    if args.exit_on_fatal_error {
                        log::info!("Too many sessions that over {max_sessions}, exiting...");
                        break;
                    }
                    log::warn!("Too many sessions that over {max_sessions}, dropping new session");
                    continue;
                }
                log::trace!("Session count {}", task_count.fetch_add(1, Relaxed).saturating_add(1));
                let mut info = SessionInfo::new(udp.local_addr(), udp.peer_addr(), IpProtocol::Udp);
                if info.dst.port() == DNS_PORT {
                    if is_private_ip(info.dst.ip()) {
                        info.dst.set_ip(dns_addr); // !!! Here we change the destination address to remote DNS server!!!
                    }
                    if args.dns == ArgDns::OverTcp {
                        info.protocol = IpProtocol::Tcp;
                        let proxy_handler = mgr.new_proxy_handler(info, None, false).await?;
                        let socket_queue = socket_queue.clone();
                        let dns_cache = dns_cache.clone();
                        tokio::spawn(async move {
                            if let Err(err) = handle_dns_over_tcp_session(udp, proxy_handler, socket_queue, ipv6_enabled, dns_cache).await {
                                log::error!("{info} error \"{err}\"");
                            }
                            log::trace!("Session count {}", task_count.fetch_sub(1, Relaxed).saturating_sub(1));
                        });
                        continue;
                    }
                    if args.dns == ArgDns::Virtual {
                        tokio::spawn(async move {
                            if let Some(virtual_dns) = virtual_dns {
                                if let Err(err) = handle_virtual_dns_session(udp, virtual_dns).await {
                                    log::error!("{info} error \"{err}\"");
                                }
                            }
                            log::trace!("Session count {}", task_count.fetch_sub(1, Relaxed).saturating_sub(1));
                        });
                        continue;
                    }
                    if args.dns == ArgDns::Direct {
                        let dns_dest = info.dst;
                        let socket_queue = socket_queue.clone();
                        let dns_cache = dns_cache.clone();
                        tokio::spawn(async move {
                            if let Err(err) = handle_direct_dns_session(udp, dns_dest, socket_queue, ipv6_enabled, dns_cache).await {
                                log::error!("{info} error \"{err}\"");
                            }
                            log::trace!("Session count {}", task_count.fetch_sub(1, Relaxed).saturating_sub(1));
                        });
                        continue;
                    }
                    // ArgDns::OverProxy falls through to general UDP handling below
                }
                let domain_name = lookup_domain_name(&udp.peer_addr().ip(), &virtual_dns, &dns_cache).await;
                let mut should_bypass = check_bypass_ip(&udp.peer_addr().ip(), &virtual_dns, &dns_cache, &bypass_matcher).await;
                #[cfg(feature = "udpgw")]
                if let Some(udpgw) = udpgw_client.clone() {
                    if !should_bypass {
                        let tcp_src = match udp.peer_addr() {
                            SocketAddr::V4(_) => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
                            SocketAddr::V6(_) => SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
                        };
                        let tcpinfo = SessionInfo::new(tcp_src, udpgw.get_udpgw_server_addr(), IpProtocol::Tcp);
                        let proxy_handler = mgr.new_proxy_handler(tcpinfo, None, false).await?;
                        let queue = socket_queue.clone();
                        let dns_cache = dns_cache.clone();
                        tokio::spawn(async move {
                            let dst = info.dst; // real UDP destination address
                            let dst_addr = match domain_name {
                                Some(ref d) => socks5_impl::protocol::Address::from((d.clone(), dst.port())),
                                None => dst.into(),
                            };
                            if let Err(e) =
                                handle_udp_gateway_session(udp, udpgw, &dst_addr, proxy_handler, queue, ipv6_enabled, dns_cache).await
                            {
                                log::info!("Ending {info} with \"{e}\"");
                            }
                            log::trace!("Session count {}", task_count.fetch_sub(1, Relaxed).saturating_sub(1));
                        });
                        continue;
                    }
                }

                if should_bypass {
                    should_bypass =
                        resolve_bypass_destination(&mut info, &domain_name, virtual_dns.is_some(), dns_addr, &socket_queue, &dns_cache)
                            .await;
                }

                let handler_mgr = if should_bypass { &no_proxy_mgr } else { &mgr };
                let ty = if should_bypass { ProxyType::None } else { args.proxy.proxy_type };
                let dns_cache = dns_cache.clone();
                match handler_mgr.new_proxy_handler(info, domain_name, true).await {
                    Ok(proxy_handler) => {
                        let socket_queue = socket_queue.clone();
                        tokio::spawn(async move {
                            if let Err(err) =
                                handle_udp_associate_session(udp, ty, proxy_handler, socket_queue, ipv6_enabled, dns_cache).await
                            {
                                log::info!("Ending {info} with \"{err}\"");
                            }
                            log::trace!("Session count {}", task_count.fetch_sub(1, Relaxed).saturating_sub(1));
                        });
                    }
                    Err(e) => {
                        log::error!("Failed to create UDP connection: {e}");
                    }
                }
            }
            IpStackStream::UnknownTransport(u) => {
                let len = u.payload().len();
                log::info!("#0 unhandled transport - Ip Protocol {:?}, length {}", u.ip_protocol(), len);
                continue;
            }
            IpStackStream::UnknownNetwork(pkt) => {
                log::info!("#0 unknown transport - {} bytes", pkt.len());
                continue;
            }
        }
    }
    Ok(task_count.load(Relaxed))
}

async fn handle_virtual_dns_session(mut udp: IpStackUdpStream, dns: Arc<Mutex<VirtualDns>>) -> crate::Result<()> {
    let mut buf = [0_u8; 4096];
    loop {
        let len = match udp.read(&mut buf).await {
            Err(e) => {
                // indicate UDP read fails not an error.
                log::debug!("Virtual DNS session error: {e}");
                break;
            }
            Ok(len) => len,
        };
        if len == 0 {
            break;
        }
        let (msg, qname, ip) = dns.lock().await.generate_query(&buf[..len])?;
        udp.write_all(&msg).await?;
        log::debug!("Virtual DNS query: {qname} -> {ip}");
    }
    Ok(())
}

async fn try_resolve_from_cache(query_data: &[u8], dns_cache: &dns_mapping::SharedDnsCache, ipv6_enabled: bool) -> Option<Vec<u8>> {
    let message = dns::parse_data_to_dns_message(query_data, false).ok()?;
    let domain = dns::extract_domain_from_dns_message(&message).ok()?;
    let records = dns_cache.lock().await.lookup_with_ttl(&domain)?;
    let mut response = dns::build_dns_response_from_cache(message, &domain, &records).ok()?;
    if !ipv6_enabled {
        dns::remove_ipv6_entries(&mut response);
    }
    if response.answers().is_empty() {
        return None;
    }
    response.to_vec().ok()
}

async fn handle_direct_dns_session(
    mut udp: IpStackUdpStream,
    dns_addr: SocketAddr,
    socket_queue: Option<Arc<SocketQueue>>,
    ipv6_enabled: bool,
    dns_cache: dns_mapping::SharedDnsCache,
) -> crate::Result<()> {
    let mut dns_server = create_udp_stream(&socket_queue, dns_addr).await?;

    let mut buf1 = [0_u8; 4096];
    let mut buf2 = [0_u8; 4096];
    loop {
        tokio::select! {
            len = udp.read(&mut buf1) => {
                let len = len?;
                if len == 0 {
                    break;
                }
                traffic_status::traffic_status_update(len, 0)?;
                if let Some(cached) = try_resolve_from_cache(&buf1[..len], &dns_cache, ipv6_enabled).await {
                    log::debug!("DNS cache hit for direct query");
                    udp.write_all(&cached).await?;
                    continue;
                }
                dns_server.write_all(&buf1[..len]).await?;
            }
            len = dns_server.read(&mut buf2) => {
                let len = len?;
                if len == 0 {
                    break;
                }
                traffic_status::traffic_status_update(0, len)?;

                let buf = snoop_dns_response(&buf2[..len], &dns_cache, ipv6_enabled).await?;
                udp.write_all(&buf).await?;
            }
        }
    }
    Ok(())
}

async fn copy_and_record_traffic<R, W>(reader: &mut R, writer: &mut W, is_tx: bool) -> tokio::io::Result<u64>
where
    R: tokio::io::AsyncRead + Unpin + ?Sized,
    W: tokio::io::AsyncWrite + Unpin + ?Sized,
{
    let mut buf = vec![0; 8192];
    let mut total = 0;
    loop {
        match reader.read(&mut buf).await? {
            0 => break, // EOF
            n => {
                total += n as u64;
                let (tx, rx) = if is_tx { (n, 0) } else { (0, n) };
                if let Err(e) = crate::traffic_status::traffic_status_update(tx, rx) {
                    log::debug!("Record traffic status error: {e}");
                }
                writer.write_all(&buf[..n]).await?;
            }
        }
    }
    Ok(total)
}

async fn handle_tcp_session(
    mut tcp_stack: IpStackTcpStream,
    proxy_handler: Arc<Mutex<dyn ProxyHandler>>,
    socket_queue: Option<Arc<SocketQueue>>,
) -> crate::Result<()> {
    let (session_info, server_addr) = {
        let handler = proxy_handler.lock().await;

        (handler.get_session_info(), handler.get_server_addr())
    };

    let mut server = create_tcp_stream(&socket_queue, server_addr).await?;

    log::info!("Beginning {session_info}");

    match handle_proxy_session(&mut server, proxy_handler).await {
        Err(e) => {
            tcp_stack.shutdown().await?;
            return Err(e);
        }
        Ok(ProxyResult::Bypass(bypass_addr)) => {
            let _ = server.shutdown().await;
            log::info!("{session_info} bypassing proxy, connecting directly to {bypass_addr}");
            server = create_tcp_stream(&socket_queue, bypass_addr).await?;
        }
        Ok(ProxyResult::Established) | Ok(ProxyResult::UdpAssociate(_)) => {}
    }

    let (mut t_rx, mut t_tx) = tokio::io::split(tcp_stack);
    let (mut s_rx, mut s_tx) = tokio::io::split(server);

    let res = tokio::join!(
        async move {
            let r = copy_and_record_traffic(&mut t_rx, &mut s_tx, true).await;
            if let Err(err) = s_tx.shutdown().await {
                log::trace!("{session_info} s_tx shutdown error {err}");
            }
            r
        },
        async move {
            let r = copy_and_record_traffic(&mut s_rx, &mut t_tx, false).await;
            if let Err(err) = t_tx.shutdown().await {
                log::trace!("{session_info} t_tx shutdown error {err}");
            }
            r
        },
    );
    log::info!("Ending {session_info} with {res:?}");

    Ok(())
}

#[cfg(feature = "udpgw")]
async fn handle_udp_gateway_session(
    mut udp_stack: IpStackUdpStream,
    udpgw_client: Arc<UdpGwClient>,
    udp_dst: &socks5_impl::protocol::Address,
    proxy_handler: Arc<Mutex<dyn ProxyHandler>>,
    socket_queue: Option<Arc<SocketQueue>>,
    ipv6_enabled: bool,
    dns_cache: dns_mapping::SharedDnsCache,
) -> crate::Result<()> {
    let proxy_server_addr = { proxy_handler.lock().await.get_server_addr() };
    let udp_mtu = udpgw_client.get_udp_mtu();
    let udp_timeout = udpgw_client.get_udp_timeout();

    let mut stream = loop {
        match udpgw_client.pop_server_connection_from_queue().await {
            Some(stream) => {
                if stream.is_closed() {
                    continue;
                } else {
                    break stream;
                }
            }
            None => {
                let mut tcp_server_stream = create_tcp_stream(&socket_queue, proxy_server_addr).await?;
                match handle_proxy_session(&mut tcp_server_stream, proxy_handler).await {
                    Err(e) => return Err(format!("udpgw connection error: {e}").into()),
                    Ok(ProxyResult::Bypass(bypass_addr)) => {
                        let _ = tcp_server_stream.shutdown().await;
                        log::info!("udpgw bypassing proxy, connecting directly to {bypass_addr}");
                        tcp_server_stream = create_tcp_stream(&socket_queue, bypass_addr).await?;
                    }
                    Ok(ProxyResult::UdpAssociate(_)) => {
                        return Err("unexpected UDP associate response in udpgw session".into());
                    }
                    Ok(ProxyResult::Established) => {}
                }
                break UdpGwClientStream::new(tcp_server_stream);
            }
        }
    };

    let tcp_local_addr = stream.local_addr();
    let sn = stream.serial_number();

    log::info!("[UdpGw] Beginning stream {} {} -> {}", sn, &tcp_local_addr, udp_dst);

    let Some(mut reader) = stream.get_reader() else {
        return Err("get reader failed".into());
    };

    let Some(mut writer) = stream.get_writer() else {
        return Err("get writer failed".into());
    };

    let mut tmp_buf = vec![0; udp_mtu.into()];

    loop {
        tokio::select! {
            len = udp_stack.read(&mut tmp_buf) => {
                let read_len = match len {
                    Ok(0) => {
                        log::info!("[UdpGw] Ending stream {} {} <> {}", sn, &tcp_local_addr, udp_dst);
                        break;
                    }
                    Ok(n) => n,
                    Err(e) => {
                        log::info!("[UdpGw] Ending stream {} {} <> {} with udp stack \"{}\"", sn, &tcp_local_addr, udp_dst, e);
                        break;
                    }
                };
                crate::traffic_status::traffic_status_update(read_len, 0)?;
                if udp_dst.port() == DNS_PORT {
                    if let Some(cached) = try_resolve_from_cache(&tmp_buf[..read_len], &dns_cache, ipv6_enabled).await {
                        log::debug!("DNS cache hit for udpgw query");
                        udp_stack.write_all(&cached).await?;
                        stream.update_activity();
                        continue;
                    }
                }
                let sn = stream.serial_number();
                if let Err(e) = UdpGwClient::send_udpgw_packet(ipv6_enabled, &tmp_buf[0..read_len], udp_dst, sn, &mut writer).await {
                    log::info!("[UdpGw] Ending stream {} {} <> {} with send_udpgw_packet {}", sn, &tcp_local_addr, udp_dst, e);
                    break;
                }
                log::debug!("[UdpGw] stream {} {} -> {} send len {}", sn, &tcp_local_addr, udp_dst, read_len);
                stream.update_activity();
            }
            ret = UdpGwClient::recv_udpgw_packet(udp_mtu, udp_timeout, &mut reader) => {
                if let Ok((len, _)) = ret {
                    crate::traffic_status::traffic_status_update(0, len)?;
                }
                match ret {
                    Err(e) => {
                        log::warn!("[UdpGw] Ending stream {} {} <> {} with recv_udpgw_packet {}", sn, &tcp_local_addr, udp_dst, e);
                        stream.close();
                        break;
                    }
                    Ok((_, packet)) => match packet {
                        //should not received keepalive
                        UdpGwResponse::KeepAlive => {
                            log::error!("[UdpGw] Ending stream {} {} <> {} with recv keepalive", sn, &tcp_local_addr, udp_dst);
                            stream.close();
                            break;
                        }
                        //server udp may be timeout,can continue to receive udp data?
                        UdpGwResponse::Error => {
                            log::info!("[UdpGw] Ending stream {} {} <> {} with recv udp error", sn, &tcp_local_addr, udp_dst);
                            stream.update_activity();
                            continue;
                        }
                        UdpGwResponse::TcpClose => {
                            log::error!("[UdpGw] Ending stream {} {} <> {} with tcp closed", sn, &tcp_local_addr, udp_dst);
                            stream.close();
                            break;
                        }
                        UdpGwResponse::Data(data) => {
                            use socks5_impl::protocol::StreamOperation;
                            let len = data.len();
                            let f = data.header.flags;
                            log::debug!("[UdpGw] stream {sn} {} <- {} receive {f} len {len}", &tcp_local_addr, udp_dst);
                            let payload = if udp_dst.port() == DNS_PORT {
                                match snoop_dns_response(&data.data, &dns_cache, ipv6_enabled).await {
                                    Ok(buf) => buf,
                                    Err(_) => data.data,
                                }
                            } else {
                                data.data
                            };
                            if let Err(e) = udp_stack.write_all(&payload).await {
                                log::error!("[UdpGw] Ending stream {} {} <> {} with send_udp_packet {}", sn, &tcp_local_addr, udp_dst, e);
                                break;
                            }
                        }
                    }
                }
                stream.update_activity();
            }
        }
    }

    if !stream.is_closed() {
        udpgw_client.store_server_connection_full(stream, reader, writer).await;
    }

    Ok(())
}

async fn handle_udp_associate_session(
    mut udp_stack: IpStackUdpStream,
    proxy_type: ProxyType,
    proxy_handler: Arc<Mutex<dyn ProxyHandler>>,
    socket_queue: Option<Arc<SocketQueue>>,
    ipv6_enabled: bool,
    dns_cache: dns_mapping::SharedDnsCache,
) -> crate::Result<()> {
    use socks5_impl::protocol::{Address, StreamOperation, UdpHeader};

    let (session_info, server_addr, domain_name, udp_addr) = {
        let handler = proxy_handler.lock().await;
        (
            handler.get_session_info(),
            handler.get_server_addr(),
            handler.get_domain_name(),
            handler.get_udp_associate(),
        )
    };

    log::info!("Beginning {session_info}");

    // `_server` is meaningful here, it must be alive all the time
    // to ensure that UDP transmission will not be interrupted accidentally.
    let (_server, udp_addr) = match udp_addr {
        Some(udp_addr) => (None, udp_addr),
        None => {
            let mut server = create_tcp_stream(&socket_queue, server_addr).await?;
            let result = handle_proxy_session(&mut server, proxy_handler).await?;
            match result {
                ProxyResult::UdpAssociate(addr) => (Some(server), addr),
                ProxyResult::Established | ProxyResult::Bypass(_) => {
                    return Err("udp associate failed".into());
                }
            }
        }
    };

    let mut udp_server = create_udp_stream(&socket_queue, udp_addr).await?;

    let mut buf1 = [0_u8; 4096];
    let mut buf2 = [0_u8; 4096];
    loop {
        tokio::select! {
            len = udp_stack.read(&mut buf1) => {
                let len = len?;
                if len == 0 {
                    break;
                }
                let buf1 = &buf1[..len];

                crate::traffic_status::traffic_status_update(len, 0)?;

                if session_info.dst.port() == DNS_PORT {
                    if let Some(cached) = try_resolve_from_cache(buf1, &dns_cache, ipv6_enabled).await {
                        log::debug!("DNS cache hit for over-proxy query");
                        udp_stack.write_all(&cached).await?;
                        continue;
                    }
                }

                if let ProxyType::Socks4 | ProxyType::Socks5 = proxy_type {
                    let s5addr = if let Some(domain_name) = &domain_name {
                        Address::DomainAddress(domain_name.clone().into(), session_info.dst.port())
                    } else {
                        session_info.dst.into()
                    };

                    // Add SOCKS5 UDP header to the incoming data
                    let mut s5_udp_data = Vec::<u8>::new();
                    UdpHeader::new(0, s5addr).write_to_stream(&mut s5_udp_data)?;
                    s5_udp_data.extend_from_slice(buf1);

                    udp_server.write_all(&s5_udp_data).await?;
                } else {
                    udp_server.write_all(buf1).await?;
                }
            }
            len = udp_server.read(&mut buf2) => {
                let len = len?;
                if len == 0 {
                    break;
                }
                let buf2 = &buf2[..len];

                crate::traffic_status::traffic_status_update(0, len)?;

                let data = if let ProxyType::Socks4 | ProxyType::Socks5 = proxy_type {
                    // Remove SOCKS5 UDP header from the server data
                    let header = UdpHeader::retrieve_from_stream(&mut &buf2[..])?;
                    &buf2[header.len()..]
                } else {
                    buf2
                };

                if session_info.dst.port() == DNS_PORT {
                    let buf = snoop_dns_response(data, &dns_cache, ipv6_enabled).await?;
                    udp_stack.write_all(&buf).await?;
                } else {
                    udp_stack.write_all(data).await?;
                }
            }
        }
    }

    log::info!("Ending {session_info}");

    Ok(())
}

async fn handle_dns_over_tcp_session(
    mut udp_stack: IpStackUdpStream,
    proxy_handler: Arc<Mutex<dyn ProxyHandler>>,
    socket_queue: Option<Arc<SocketQueue>>,
    ipv6_enabled: bool,
    dns_cache: dns_mapping::SharedDnsCache,
) -> crate::Result<()> {
    let (session_info, server_addr) = {
        let handler = proxy_handler.lock().await;

        (handler.get_session_info(), handler.get_server_addr())
    };

    let mut server = create_tcp_stream(&socket_queue, server_addr).await?;

    log::info!("Beginning {session_info}");

    match handle_proxy_session(&mut server, proxy_handler).await? {
        ProxyResult::Established => {}
        ProxyResult::Bypass(bypass_addr) => {
            let _ = server.shutdown().await;
            log::info!("{session_info} bypassing proxy, connecting directly to {bypass_addr}");
            server = create_tcp_stream(&socket_queue, bypass_addr).await?;
        }
        ProxyResult::UdpAssociate(_) => {
            return Err("unexpected UDP associate response in DNS-over-TCP session".into());
        }
    }

    let mut udp_recv_buf = [0u8; 4096];
    let mut tcp_recv_buf = [0u8; 4096];
    let mut tcp_pending = Vec::new();
    loop {
        tokio::select! {
            len = udp_stack.read(&mut udp_recv_buf) => {
                let len = match len {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) => {
                        log::debug!("{session_info} UDP read error: {e}, closing session");
                        break;
                    }
                };
                let udp_data = &udp_recv_buf[..len];

                if let Some(cached) = try_resolve_from_cache(udp_data, &dns_cache, ipv6_enabled).await {
                    log::debug!("DNS cache hit for over-tcp query");
                    udp_stack.write_all(&cached).await?;
                    continue;
                }

                _ = dns::parse_data_to_dns_message(udp_data, false)?;

                // Insert the DNS message length in front of the payload
                let len = u16::try_from(udp_data.len())?;
                let mut buf = Vec::with_capacity(std::mem::size_of::<u16>() + usize::from(len));
                buf.extend_from_slice(&len.to_be_bytes());
                buf.extend_from_slice(udp_data);

                server.write_all(&buf).await?;

                crate::traffic_status::traffic_status_update(buf.len(), 0)?;
            }
            len = server.read(&mut tcp_recv_buf) => {
                let len = len?;
                if len == 0 {
                    break;
                }
                tcp_pending.extend_from_slice(&tcp_recv_buf[..len]);

                crate::traffic_status::traffic_status_update(0, len)?;

                let mut to_send: VecDeque<Vec<u8>> = VecDeque::new();
                while tcp_pending.len() >= 2 {
                    let msg_len = u16::from_be_bytes([tcp_pending[0], tcp_pending[1]]) as usize;
                    if tcp_pending.len() < msg_len + 2 {
                        break;
                    }

                    // remove the length field
                    let data = tcp_pending[2..msg_len + 2].to_vec();
                    tcp_pending.drain(..msg_len + 2);

                    let mut message = dns::parse_data_to_dns_message(&data, false)?;

                    let name = dns::extract_domain_from_dns_message(&message)?;
                    let ip = dns::extract_ipaddr_from_dns_message(&message);
                    log::trace!("DNS over TCP query result: {name} -> {ip:?}");

                    {
                        let records = dns::extract_dns_records_from_message(&message);
                        if records.iter().any(|r| matches!(r, dns_mapping::DnsRecord::A(..) | dns_mapping::DnsRecord::AAAA(..))) {
                            dns_cache.lock().await.insert(&name, &records);
                        }
                    }

                    if !ipv6_enabled {
                        dns::remove_ipv6_entries(&mut message);
                    }

                    to_send.push_back(message.to_vec()?);
                }

                while let Some(packet) = to_send.pop_front() {
                    udp_stack.write_all(&packet).await?;
                }
            }
        }
    }

    let _ = server.shutdown().await;
    log::info!("Ending {session_info}");

    Ok(())
}

/// This function is used to handle the business logic of tun2proxy and SOCKS5 server.
/// When handling UDP proxy, the return value UDP associate IP address is the result of this business logic.
/// However, when handling TCP business logic, the return value Ok(None) is meaningless, just indicating that the operation was successful.
async fn handle_proxy_session(server: &mut TcpStream, proxy_handler: Arc<Mutex<dyn ProxyHandler>>) -> crate::Result<ProxyResult> {
    let mut launched = false;
    let mut proxy_handler = proxy_handler.lock().await;
    let dir = OutgoingDirection::ToServer;
    let (mut tx, mut rx) = (0, 0);
    let initial_server_addr = proxy_handler.get_server_addr();

    loop {
        if proxy_handler.connection_established() {
            break;
        }

        if !launched {
            let data = proxy_handler.peek_data(dir).buffer;
            let len = data.len();
            if len == 0 {
                return Err("proxy_handler launched went wrong".into());
            }
            server.write_all(data).await?;
            proxy_handler.consume_data(dir, len);
            tx += len;

            launched = true;
        }

        let mut buf = [0_u8; 4096];
        let len = server.read(&mut buf).await?;
        if len == 0 {
            return Err("server closed accidentially".into());
        }
        rx += len;
        let event = IncomingDataEvent {
            direction: IncomingDirection::FromServer,
            buffer: &buf[..len],
        };
        proxy_handler.push_data(event).await?;

        let data = proxy_handler.peek_data(dir).buffer;
        let len = data.len();
        if len > 0 {
            server.write_all(data).await?;
            proxy_handler.consume_data(dir, len);
            tx += len;
        }
    }
    crate::traffic_status::traffic_status_update(tx, rx)?;
    let current_server_addr = proxy_handler.get_server_addr();
    if current_server_addr != initial_server_addr {
        return Ok(ProxyResult::Bypass(current_server_addr));
    }
    match proxy_handler.get_udp_associate() {
        Some(addr) => Ok(ProxyResult::UdpAssociate(addr)),
        None => Ok(ProxyResult::Established),
    }
}

#[cfg(test)]
#[path = "lib_tests.rs"]
mod proxy_result_tests;
