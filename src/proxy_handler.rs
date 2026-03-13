use crate::{
    args::ProxyType,
    directions::{IncomingDataEvent, IncomingDirection, OutgoingDataEvent, OutgoingDirection},
    dns, dns_mapping,
    session_info::SessionInfo,
    socket_queue::{SocketQueue, create_tcp_stream, create_udp_stream},
    traffic_status,
};
use ipstack::{IpStackTcpStream, IpStackUdpStream};
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
};

#[async_trait::async_trait]
pub trait ProxyHandler: Send + Sync {
    fn get_server_addr(&self) -> SocketAddr;
    fn get_session_info(&self) -> SessionInfo;
    fn get_domain_name(&self) -> Option<String>;
    async fn push_data(&mut self, event: IncomingDataEvent<'_>) -> std::io::Result<()>;
    fn consume_data(&mut self, dir: OutgoingDirection, size: usize);
    fn peek_data(&mut self, dir: OutgoingDirection) -> OutgoingDataEvent<'_>;
    fn connection_established(&self) -> bool;
    #[allow(dead_code)]
    fn data_len(&self, dir: OutgoingDirection) -> usize;
    #[allow(dead_code)]
    fn reset_connection(&self) -> bool;
    fn get_udp_associate(&self) -> Option<SocketAddr>;
}

#[async_trait::async_trait]
pub trait ProxyHandlerManager: Send + Sync {
    async fn new_proxy_handler(
        &self,
        info: SessionInfo,
        domain_name: Option<String>,
        udp_associate: bool,
    ) -> std::io::Result<Arc<Mutex<dyn ProxyHandler>>>;
}

/// Result of a proxy handshake session.
pub(crate) enum ProxyResult {
    /// Proxy connection established normally.
    Established,
    /// Proxy indicated bypass; connect directly to this address instead.
    Bypass(SocketAddr),
    /// Proxy returned a UDP associate address.
    UdpAssociate(SocketAddr),
}

/// This function is used to handle the business logic of tun2proxy and SOCKS5 server.
/// When handling UDP proxy, the return value UDP associate IP address is the result of this business logic.
/// However, when handling TCP business logic, the return value Ok(None) is meaningless, just indicating that the operation was successful.
pub(crate) async fn handle_proxy_session(
    server: &mut TcpStream,
    proxy_handler: Arc<Mutex<dyn ProxyHandler>>,
) -> crate::Result<ProxyResult> {
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
    traffic_status::traffic_status_update(tx, rx)?;
    let current_server_addr = proxy_handler.get_server_addr();
    if current_server_addr != initial_server_addr {
        return Ok(ProxyResult::Bypass(current_server_addr));
    }
    match proxy_handler.get_udp_associate() {
        Some(addr) => Ok(ProxyResult::UdpAssociate(addr)),
        None => Ok(ProxyResult::Established),
    }
}

pub(crate) async fn copy_and_record_traffic<R, W>(reader: &mut R, writer: &mut W, is_tx: bool) -> tokio::io::Result<u64>
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
                if let Err(e) = traffic_status::traffic_status_update(tx, rx) {
                    log::debug!("Record traffic status error: {e}");
                }
                writer.write_all(&buf[..n]).await?;
            }
        }
    }
    Ok(total)
}

pub(crate) async fn handle_tcp_session(
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

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_udp_associate_session(
    mut udp_stack: IpStackUdpStream,
    proxy_type: ProxyType,
    proxy_handler: Arc<Mutex<dyn ProxyHandler>>,
    socket_queue: Option<Arc<SocketQueue>>,
    ipv6_enabled: bool,
    dns_cache: dns_mapping::SharedDnsCache,
    dns_first_packet: Option<Vec<u8>>,
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

    // Forward the pre-read DNS first packet (already checked for cache miss in the main loop).
    if let Some(first_packet) = dns_first_packet {
        traffic_status::traffic_status_update(first_packet.len(), 0)?;
        if let ProxyType::Socks4 | ProxyType::Socks5 = proxy_type {
            let s5addr = if let Some(domain_name) = &domain_name {
                Address::DomainAddress(domain_name.clone().into(), session_info.dst.port())
            } else {
                session_info.dst.into()
            };
            let mut s5_udp_data = Vec::<u8>::new();
            UdpHeader::new(0, s5addr).write_to_stream(&mut s5_udp_data)?;
            s5_udp_data.extend_from_slice(&first_packet);
            udp_server.write_all(&s5_udp_data).await?;
        } else {
            udp_server.write_all(&first_packet).await?;
        }
    }

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

                traffic_status::traffic_status_update(len, 0)?;

                if session_info.dst.port() == dns::DNS_PORT
                    && dns::try_respond_from_dns_cache(&mut udp_stack, buf1, ipv6_enabled, &dns_cache).await.unwrap_or(false)
                {
                    continue;
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

                traffic_status::traffic_status_update(0, len)?;

                let data = if let ProxyType::Socks4 | ProxyType::Socks5 = proxy_type {
                    // Remove SOCKS5 UDP header from the server data
                    let header = UdpHeader::retrieve_from_stream(&mut &buf2[..])?;
                    &buf2[header.len()..]
                } else {
                    buf2
                };

                if session_info.dst.port() == dns::DNS_PORT {
                    let buf = dns::snoop_dns_response(data, &dns_cache, ipv6_enabled).await?;
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

#[cfg(test)]
#[path = "proxy_handler_tests.rs"]
mod proxy_result_tests;
