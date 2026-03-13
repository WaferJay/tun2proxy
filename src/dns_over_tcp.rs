use crate::{
    dns, dns_mapping,
    proxy_handler::ProxyHandlerManager,
    session_info::{IpProtocol, SessionInfo},
    socket_queue::SocketQueue,
};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::tcp::OwnedWriteHalf,
    sync::{Mutex, oneshot},
    task::JoinHandle,
};

/// Manages a shared, persistent TCP connection through the proxy to a DNS server.
/// Multiplexes concurrent DNS queries using DNS transaction IDs.
pub(crate) struct SharedDnsTcpClient {
    inner: Mutex<ClientInner>,
    mgr: Arc<dyn ProxyHandlerManager>,
    dns_addr: SocketAddr,
    socket_queue: Option<Arc<SocketQueue>>,
    /// Set when a query times out, forcing reconnection on the next query.
    force_reconnect: AtomicBool,
}

type PendingMap = HashMap<u16, Vec<oneshot::Sender<crate::Result<Vec<u8>>>>>;

struct ClientInner {
    /// Pending queries keyed by DNS transaction ID.
    pending: Arc<Mutex<PendingMap>>,
    /// Writer half of the current TCP connection.
    writer: Option<OwnedWriteHalf>,
    /// Handle to the background reader task.
    reader_handle: Option<JoinHandle<()>>,
}

impl SharedDnsTcpClient {
    pub fn new(mgr: Arc<dyn ProxyHandlerManager>, dns_addr: SocketAddr, socket_queue: Option<Arc<SocketQueue>>) -> Self {
        Self {
            inner: Mutex::new(ClientInner {
                pending: Arc::new(Mutex::new(HashMap::new())),
                writer: None,
                reader_handle: None,
            }),
            mgr,
            dns_addr,
            socket_queue,
            force_reconnect: AtomicBool::new(false),
        }
    }

    /// Ensure a connection exists, creating one through the proxy if necessary.
    async fn ensure_connected(&self, inner: &mut ClientInner) -> crate::Result<()> {
        let need_connect = self.force_reconnect.swap(false, Ordering::Relaxed)
            || !matches!(
                (&inner.writer, &inner.reader_handle),
                (Some(_), Some(handle)) if !handle.is_finished()
            );

        if !need_connect {
            return Ok(());
        }

        // Abort the old reader task so its cleanup code doesn't drain pending
        // entries that will belong to the new connection.
        if let Some(handle) = inner.reader_handle.take() {
            handle.abort();
        }
        inner.writer = None;

        // Clean up stale pending queries from the previous dead connection.
        {
            let mut pending = inner.pending.lock().await;
            for (_, senders) in pending.drain() {
                for tx in senders {
                    let _ = tx.send(Err("DNS TCP connection reset".into()));
                }
            }
        }

        // Create a new TCP connection through the proxy to the DNS server.
        let src = SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), 0);
        let info = SessionInfo::new(src, self.dns_addr, IpProtocol::Tcp);
        let proxy_handler = self.mgr.new_proxy_handler(info, None, false).await?;

        let server_addr = proxy_handler.lock().await.get_server_addr();
        let mut server = crate::socket_queue::create_tcp_stream(&self.socket_queue, server_addr).await?;

        match crate::proxy_handler::handle_proxy_session(&mut server, proxy_handler).await? {
            crate::proxy_handler::ProxyResult::Established => {}
            crate::proxy_handler::ProxyResult::Bypass(bypass_addr) => {
                let _ = server.shutdown().await;
                server = crate::socket_queue::create_tcp_stream(&self.socket_queue, bypass_addr).await?;
            }
            crate::proxy_handler::ProxyResult::UdpAssociate(_) => {
                return Err("unexpected UDP associate in DNS-over-TCP".into());
            }
        }

        log::info!("Shared DNS-over-TCP connection established to {}", self.dns_addr);

        let (reader, writer) = server.into_split();
        inner.writer = Some(writer);

        let pending = inner.pending.clone();
        inner.reader_handle = Some(tokio::spawn(async move {
            if let Err(e) = Self::reader_loop(reader, &pending).await {
                log::debug!("DNS-over-TCP reader ended: {e}");
            }
            // Notify all remaining pending queries that the connection is gone.
            let mut pending = pending.lock().await;
            for (_, senders) in pending.drain() {
                for tx in senders {
                    let _ = tx.send(Err("DNS TCP connection closed".into()));
                }
            }
        }));

        Ok(())
    }

    /// Background task: reads DNS responses from TCP and dispatches by transaction ID.
    async fn reader_loop(mut reader: tokio::net::tcp::OwnedReadHalf, pending: &Mutex<PendingMap>) -> crate::Result<()> {
        loop {
            // Read 2-byte length prefix (DNS-over-TCP framing).
            let mut len_buf = [0u8; 2];
            reader.read_exact(&mut len_buf).await?;
            let msg_len = u16::from_be_bytes(len_buf) as usize;

            if msg_len == 0 {
                return Err("DNS TCP: zero-length message".into());
            }

            // Read the full DNS message.
            let mut msg_buf = vec![0u8; msg_len];
            reader.read_exact(&mut msg_buf).await?;

            crate::traffic_status::traffic_status_update(0, 2 + msg_len)?;

            // Transaction ID is the first 2 bytes of the DNS message (RFC 1035 §4.1.1).
            if msg_buf.len() < 2 {
                continue;
            }
            let txn_id = u16::from_be_bytes([msg_buf[0], msg_buf[1]]);

            let mut pending = pending.lock().await;
            if let Some(senders) = pending.remove(&txn_id) {
                for tx in senders {
                    let _ = tx.send(Ok(msg_buf.clone()));
                }
            } else {
                log::debug!("DNS-over-TCP: no pending query for txn_id {txn_id:#06x}, dropping response");
            }
        }
    }

    /// Send a DNS query through the shared connection and wait for its response.
    ///
    /// `raw_query` is the raw DNS message bytes (no TCP length prefix).
    /// Returns the raw DNS response bytes (no TCP length prefix).
    pub async fn query(&self, raw_query: &[u8]) -> crate::Result<Vec<u8>> {
        if raw_query.len() < 2 {
            return Err("DNS query too short".into());
        }
        let txn_id = u16::from_be_bytes([raw_query[0], raw_query[1]]);

        let (rx, pending_ref) = {
            let mut inner = self.inner.lock().await;

            // Reconnect if needed.
            if let Err(e) = self.ensure_connected(&mut inner).await {
                inner.writer = None;
                inner.reader_handle = None;
                return Err(e);
            }

            // Keep a reference to the pending map for guaranteed cleanup on timeout.
            let pending_ref = inner.pending.clone();

            // Register the pending query.  If another session already has an
            // in-flight query with the same txn_id (common: the OS resolver
            // sends identical queries from different UDP source ports), we
            // piggyback on it instead of sending a duplicate.
            let (tx, rx) = oneshot::channel();
            let need_send = {
                let mut pending = inner.pending.lock().await;
                let first = !pending.contains_key(&txn_id);
                pending.entry(txn_id).or_default().push(tx);
                first
            };

            if need_send {
                // Write the query with TCP framing (5s timeout to detect stuck connections).
                let writer = inner.writer.as_mut().unwrap();
                let len = u16::try_from(raw_query.len())?;
                let mut frame = Vec::with_capacity(2 + raw_query.len());
                frame.extend_from_slice(&len.to_be_bytes());
                frame.extend_from_slice(raw_query);

                match tokio::time::timeout(std::time::Duration::from_secs(5), writer.write_all(&frame)).await {
                    Ok(Ok(())) => {
                        crate::traffic_status::traffic_status_update(frame.len(), 0)?;
                    }
                    Ok(Err(e)) => {
                        inner.pending.lock().await.remove(&txn_id);
                        inner.writer = None;
                        return Err(e.into());
                    }
                    Err(_) => {
                        inner.pending.lock().await.remove(&txn_id);
                        inner.writer = None;
                        if let Some(handle) = inner.reader_handle.take() {
                            handle.abort();
                        }
                        return Err("DNS TCP write timed out".into());
                    }
                }
            }

            (rx, pending_ref)
            // inner mutex is dropped here — other tasks can send queries concurrently.
        };

        // Wait for the response from the reader task.
        match tokio::time::timeout(std::time::Duration::from_secs(10), rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err("DNS TCP connection lost while waiting for response".into()),
            Err(_) => {
                // Notify piggybacking senders with a proper error (instead of
                // just dropping them, which produces a confusing "connection lost").
                let mut pending = pending_ref.lock().await;
                if let Some(senders) = pending.remove(&txn_id) {
                    for tx in senders {
                        let _ = tx.send(Err("DNS query timed out".into()));
                    }
                }
                drop(pending);
                // Force reconnect — the connection is likely dead.
                self.force_reconnect.store(true, Ordering::Relaxed);
                Err("DNS query timed out".into())
            }
        }
    }
}

/// Forward a DNS query through the shared TCP connection and write the response to the UDP stream.
async fn forward_dns_over_tcp(
    udp_stack: &mut ipstack::IpStackUdpStream,
    query_data: &[u8],
    shared_client: &SharedDnsTcpClient,
    ipv6_enabled: bool,
    dns_cache: &dns_mapping::SharedDnsCache,
) {
    let domain = match dns::parse_data_to_dns_message(query_data, false).and_then(|m| dns::extract_domain_from_dns_message(&m)) {
        Ok(d) => d,
        Err(e) => {
            log::debug!("Failed to parse DNS query for TCP forwarding: {e}");
            return;
        }
    };
    log::trace!("DNS cache miss for {domain}, forwarding via shared TCP");
    match shared_client.query(query_data).await {
        Ok(response) => {
            let resp_msg = match dns::parse_data_to_dns_message(&response, false) {
                Ok(m) => m,
                Err(e) => {
                    log::debug!("Failed to parse DNS-over-TCP response: {e}");
                    return;
                }
            };

            // Snoop the response into cache.
            let entries = dns::extract_ip_ttl_pairs_from_dns_message(&resp_msg);
            if !entries.is_empty() {
                dns_cache.lock().await.insert(&domain, &entries);
            }

            let mut resp_msg = resp_msg;
            if !ipv6_enabled {
                dns::remove_ipv6_entries(&mut resp_msg);
            }

            if let Ok(bytes) = resp_msg.to_vec() {
                let _ = udp_stack.write_all(&bytes).await;
            }
        }
        Err(e) => {
            log::warn!("DNS-over-TCP query for {domain} failed: {e}");
        }
    }
}

pub(crate) async fn handle_dns_over_tcp_session(
    mut udp_stack: ipstack::IpStackUdpStream,
    shared_client: Arc<SharedDnsTcpClient>,
    ipv6_enabled: bool,
    dns_cache: dns_mapping::SharedDnsCache,
    first_packet: Vec<u8>,
) -> crate::Result<()> {
    // Process the first packet (already checked for cache miss in the main loop).
    forward_dns_over_tcp(&mut udp_stack, &first_packet, &shared_client, ipv6_enabled, &dns_cache).await;

    let mut buf = [0u8; 4096];
    loop {
        let len = match udp_stack.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                log::debug!("DNS-over-TCP UDP read error: {e}");
                break;
            }
        };
        let query_data = &buf[..len];

        // Check cache for subsequent queries.
        match dns::try_respond_from_dns_cache(&mut udp_stack, query_data, ipv6_enabled, &dns_cache).await {
            Ok(true) => continue,
            Ok(false) => {}
            Err(e) => {
                log::debug!("DNS cache check failed: {e}");
                continue;
            }
        }

        // Cache miss — forward through shared TCP connection.
        forward_dns_over_tcp(&mut udp_stack, query_data, &shared_client, ipv6_enabled, &dns_cache).await;
    }
    Ok(())
}

#[cfg(test)]
#[path = "dns_over_tcp_tests.rs"]
mod tests;
