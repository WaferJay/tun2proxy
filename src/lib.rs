#[cfg(feature = "udpgw")]
use crate::udpgw::UdpGwClient;
pub use crate::{
    directions::{IncomingDataEvent, IncomingDirection, OutgoingDirection},
    no_proxy::NoProxyManager,
    session_info::{IpProtocol, SessionInfo},
    virtual_dns::VirtualDns,
};
pub use clap::ValueEnum;
use ipstack::IpStackStream;
pub use proxy_handler::ProxyHandler;
use socks::SocksProxyManager;
pub use socks5_impl::protocol::UserKey;
#[cfg(feature = "udpgw")]
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite},
    sync::Mutex,
};
pub use tokio_util::sync::CancellationToken;
use tproxy_config::is_private_ip;
pub use tun::DEFAULT_MTU;
#[cfg(feature = "udpgw")]
use udpgw::{UDPGW_KEEPALIVE_TIME, UDPGW_MAX_CONNECTIONS};

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
mod dns_over_tcp;
mod dump_logger;
mod error;
mod general_api;
mod http;
mod no_proxy;
mod proxy_handler;
mod session_info;
pub(crate) mod socket_queue;
pub mod socket_transfer;
mod socks;
mod traffic_status;
#[cfg(feature = "udpgw")]
pub mod udpgw;
mod virtual_dns;
#[doc(hidden)]
pub mod win_svc;

use socket_queue::SocketQueue;
pub use socket_queue::{SocketDomain, SocketProtocol};

use dns::DNS_PORT;

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

    let shared_dns_tcp = if args.dns == ArgDns::OverTcp {
        Some(Arc::new(dns_over_tcp::SharedDnsTcpClient::new(
            mgr.clone(),
            SocketAddr::new(dns_addr, DNS_PORT),
            socket_queue.clone(),
        )))
    } else {
        None
    };

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
                let domain_name = dns_mapping::lookup_domain_name(&tcp.peer_addr().ip(), &virtual_dns, &dns_cache).await;
                let mut should_bypass =
                    dns_mapping::check_bypass_ip(&tcp.peer_addr().ip(), &virtual_dns, &dns_cache, &bypass_matcher).await;

                if should_bypass {
                    should_bypass = dns::resolve_bypass_destination(
                        &mut info,
                        &domain_name,
                        virtual_dns.is_some(),
                        dns_addr,
                        &socket_queue,
                        &dns_cache,
                    )
                    .await;
                }

                let handler_mgr = if should_bypass { &no_proxy_mgr } else { &mgr };
                let proxy_handler = handler_mgr.new_proxy_handler(info, domain_name, false).await?;
                let socket_queue = socket_queue.clone();
                tokio::spawn(async move {
                    if let Err(err) = proxy_handler::handle_tcp_session(tcp, proxy_handler, socket_queue).await {
                        log::error!("{info} error \"{err}\"");
                    }
                    log::trace!("Session count {}", task_count.fetch_sub(1, Relaxed).saturating_sub(1));
                });
            }
            IpStackStream::Udp(mut udp) => {
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
                let mut dns_first_packet: Option<Vec<u8>> = None;
                if info.dst.port() == DNS_PORT {
                    if is_private_ip(info.dst.ip()) {
                        info.dst.set_ip(dns_addr); // !!! Here we change the destination address to remote DNS server!!!
                    }
                    // Virtual DNS assigns fake IPs — skip cache check.
                    if args.dns == ArgDns::Virtual {
                        tokio::spawn(async move {
                            if let Some(virtual_dns) = virtual_dns {
                                if let Err(err) = virtual_dns::handle_virtual_dns_session(udp, virtual_dns).await {
                                    log::error!("{info} error \"{err}\"");
                                }
                            }
                            log::trace!("Session count {}", task_count.fetch_sub(1, Relaxed).saturating_sub(1));
                        });
                        continue;
                    }
                    // Read the first DNS packet and try the cache.
                    let mut first_buf = [0u8; 4096];
                    let first_len = match udp.read(&mut first_buf).await {
                        Ok(0) | Err(_) => {
                            log::trace!("Session count {}", task_count.fetch_sub(1, Relaxed).saturating_sub(1));
                            continue;
                        }
                        Ok(n) => n,
                    };
                    let first_packet = first_buf[..first_len].to_vec();
                    if dns::try_respond_from_dns_cache(&mut udp, &first_packet, ipv6_enabled, &dns_cache)
                        .await
                        .unwrap_or(false)
                    {
                        log::trace!("Session count {}", task_count.fetch_sub(1, Relaxed).saturating_sub(1));
                        continue;
                    }
                    // Cache miss — dispatch to the appropriate handler with the first packet.
                    if args.dns == ArgDns::OverTcp {
                        let shared_dns_tcp = shared_dns_tcp.clone().unwrap();
                        let dns_cache = dns_cache.clone();
                        tokio::spawn(async move {
                            if let Err(err) =
                                dns_over_tcp::handle_dns_over_tcp_session(udp, shared_dns_tcp, ipv6_enabled, dns_cache, first_packet).await
                            {
                                log::error!("{info} error \"{err}\"");
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
                            if let Err(err) =
                                dns::handle_direct_dns_session(udp, dns_dest, socket_queue, ipv6_enabled, dns_cache, first_packet).await
                            {
                                log::error!("{info} error \"{err}\"");
                            }
                            log::trace!("Session count {}", task_count.fetch_sub(1, Relaxed).saturating_sub(1));
                        });
                        continue;
                    }
                    // ArgDns::OverProxy falls through to general UDP handling below
                    dns_first_packet = Some(first_packet);
                }
                let domain_name = dns_mapping::lookup_domain_name(&udp.peer_addr().ip(), &virtual_dns, &dns_cache).await;
                let mut should_bypass =
                    dns_mapping::check_bypass_ip(&udp.peer_addr().ip(), &virtual_dns, &dns_cache, &bypass_matcher).await;
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
                        let dns_first_packet = dns_first_packet.take();
                        tokio::spawn(async move {
                            let dst = info.dst; // real UDP destination address
                            let dst_addr = match domain_name {
                                Some(ref d) => socks5_impl::protocol::Address::from((d.clone(), dst.port())),
                                None => dst.into(),
                            };
                            if let Err(e) = udpgw::handle_udp_gateway_session(
                                udp,
                                udpgw,
                                &dst_addr,
                                proxy_handler,
                                queue,
                                ipv6_enabled,
                                dns_cache,
                                dns_first_packet,
                            )
                            .await
                            {
                                log::info!("Ending {info} with \"{e}\"");
                            }
                            log::trace!("Session count {}", task_count.fetch_sub(1, Relaxed).saturating_sub(1));
                        });
                        continue;
                    }
                }

                if should_bypass {
                    should_bypass = dns::resolve_bypass_destination(
                        &mut info,
                        &domain_name,
                        virtual_dns.is_some(),
                        dns_addr,
                        &socket_queue,
                        &dns_cache,
                    )
                    .await;
                }

                let handler_mgr = if should_bypass { &no_proxy_mgr } else { &mgr };
                let ty = if should_bypass { ProxyType::None } else { args.proxy.proxy_type };
                let dns_cache = dns_cache.clone();
                match handler_mgr.new_proxy_handler(info, domain_name, true).await {
                    Ok(proxy_handler) => {
                        let socket_queue = socket_queue.clone();
                        tokio::spawn(async move {
                            if let Err(err) = proxy_handler::handle_udp_associate_session(
                                udp,
                                ty,
                                proxy_handler,
                                socket_queue,
                                ipv6_enabled,
                                dns_cache,
                                dns_first_packet,
                            )
                            .await
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
