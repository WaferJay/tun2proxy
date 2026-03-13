use crate::{
    dns_mapping,
    session_info::SessionInfo,
    socket_queue::{SocketQueue, create_udp_stream},
    traffic_status,
};
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{
        Name, RData, Record, RecordType,
        rdata::{A, AAAA},
    },
};
use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::Arc,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(crate) const DNS_PORT: u16 = 53;

pub fn build_dns_query(domain: &str, id: u16) -> Result<Vec<u8>, String> {
    let mut msg = Message::new();
    msg.set_id(id);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    let name = Name::from_str(domain).map_err(|e| e.to_string())?;
    msg.add_query(Query::query(name, RecordType::A));
    msg.to_vec().map_err(|e| e.to_string())
}

pub fn build_dns_response(mut request: Message, domain: &str, ip: IpAddr, ttl: u32) -> Result<Message, String> {
    let record = match ip {
        IpAddr::V4(ip) => Record::from_rdata(Name::from_str(domain)?, ttl, RData::A(A(ip))),
        IpAddr::V6(ip) => Record::from_rdata(Name::from_str(domain)?, ttl, RData::AAAA(AAAA(ip))),
    };

    // We must indicate that this message is a response. Otherwise, implementations may not
    // recognize it.
    request.set_message_type(MessageType::Response);

    request.add_answer(record);
    Ok(request)
}

pub fn build_dns_response_multi(mut request: Message, domain: &str, entries: &[(IpAddr, u32)]) -> Result<Message, String> {
    let name = Name::from_str(domain).map_err(|e| e.to_string())?;
    request.set_message_type(MessageType::Response);
    for &(ip, ttl) in entries {
        let record = match ip {
            IpAddr::V4(v4) => Record::from_rdata(name.clone(), ttl, RData::A(A(v4))),
            IpAddr::V6(v6) => Record::from_rdata(name.clone(), ttl, RData::AAAA(AAAA(v6))),
        };
        request.add_answer(record);
    }
    Ok(request)
}

pub fn remove_ipv6_entries(message: &mut Message) {
    message.answers_mut().retain(|answer| !matches!(answer.data(), RData::AAAA(_)));
}

pub fn extract_ipaddr_from_dns_message(message: &Message) -> Result<IpAddr, String> {
    if message.response_code() != ResponseCode::NoError {
        return Err(format!("{:?}", message.response_code()));
    }
    let mut cname = None;
    for answer in message.answers() {
        match answer.data() {
            RData::A(addr) => {
                return Ok(IpAddr::V4((*addr).into()));
            }
            RData::AAAA(addr) => {
                return Ok(IpAddr::V6((*addr).into()));
            }
            RData::CNAME(name) => {
                cname = Some(name.to_utf8());
            }
            _ => {}
        }
    }
    if let Some(cname) = cname {
        return Err(cname);
    }
    Err(format!("{:?}", message.answers()))
}

pub fn extract_ip_ttl_pairs_from_dns_message(message: &Message) -> Vec<(IpAddr, u32)> {
    message
        .answers()
        .iter()
        .filter_map(|answer| {
            let ip = match answer.data() {
                RData::A(addr) => Some(IpAddr::V4((*addr).into())),
                RData::AAAA(addr) => Some(IpAddr::V6((*addr).into())),
                _ => None,
            };
            ip.map(|ip| (ip, answer.ttl()))
        })
        .collect()
}

pub fn extract_domain_from_dns_message(message: &Message) -> Result<String, String> {
    let query = message.queries().first().ok_or("DnsRequest no query body")?;
    let name = query.name().to_string();
    Ok(name)
}

pub fn parse_data_to_dns_message(data: &[u8], used_by_tcp: bool) -> Result<Message, String> {
    if used_by_tcp {
        if data.len() < 2 {
            return Err("invalid dns data".into());
        }
        let len = u16::from_be_bytes([data[0], data[1]]) as usize;
        let data = data.get(2..len + 2).ok_or("invalid dns data")?;
        return parse_data_to_dns_message(data, false);
    }
    let message = Message::from_vec(data).map_err(|e| e.to_string())?;
    Ok(message)
}

pub(crate) async fn resolve_domain(
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
    let query = build_dns_query(domain, id)?;

    let mut dns_server = create_udp_stream(socket_queue, dns_addr).await?;
    dns_server.write_all(&query).await?;

    let mut buf = [0u8; 4096];
    let len = tokio::time::timeout(std::time::Duration::from_secs(5), dns_server.read(&mut buf))
        .await
        .map_err(|_| "DNS resolve timeout")?
        .map_err(|e| format!("DNS resolve read error: {e}"))?;

    let message = parse_data_to_dns_message(&buf[..len], false)?;
    let ip = extract_ipaddr_from_dns_message(&message)?;

    // 3. Store results in cache
    let entries = extract_ip_ttl_pairs_from_dns_message(&message);
    if !entries.is_empty() {
        dns_cache.lock().await.insert(domain, &entries);
    }

    Ok(SocketAddr::new(ip, port))
}

pub(crate) async fn snoop_dns_response(data: &[u8], dns_cache: &dns_mapping::SharedDnsCache, ipv6_enabled: bool) -> crate::Result<Vec<u8>> {
    let mut message = parse_data_to_dns_message(data, false)?;
    if let Ok(name) = extract_domain_from_dns_message(&message) {
        let entries = extract_ip_ttl_pairs_from_dns_message(&message);
        if !entries.is_empty() {
            dns_cache.lock().await.insert(&name, &entries);
        }
    }
    if !ipv6_enabled {
        remove_ipv6_entries(&mut message);
    }
    Ok(message.to_vec()?)
}

/// Try to answer a DNS query from cache. Returns `Ok(true)` if answered, `Ok(false)` on cache miss.
pub(crate) async fn try_respond_from_dns_cache(
    udp_stack: &mut ipstack::IpStackUdpStream,
    query_data: &[u8],
    ipv6_enabled: bool,
    dns_cache: &dns_mapping::SharedDnsCache,
) -> crate::Result<bool> {
    let message = parse_data_to_dns_message(query_data, false)?;
    let domain = extract_domain_from_dns_message(&message)?;

    let cached = dns_cache.lock().await.lookup_ips_with_ttl(&domain);
    if let Some(entries) = cached {
        let filtered: Vec<(IpAddr, u32)> = if !ipv6_enabled {
            entries.into_iter().filter(|(ip, _)| ip.is_ipv4()).collect()
        } else {
            entries
        };
        if !filtered.is_empty() {
            log::trace!("DNS cache hit for {domain}, {} records", filtered.len());
            let response = build_dns_response_multi(message, &domain, &filtered)?;
            udp_stack.write_all(&response.to_vec()?).await?;
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) async fn handle_direct_dns_session(
    mut udp: ipstack::IpStackUdpStream,
    dns_addr: SocketAddr,
    socket_queue: Option<Arc<SocketQueue>>,
    ipv6_enabled: bool,
    dns_cache: dns_mapping::SharedDnsCache,
    first_packet: Vec<u8>,
) -> crate::Result<()> {
    let mut dns_server = create_udp_stream(&socket_queue, dns_addr).await?;

    // Forward the first packet (already checked for cache miss in the main loop).
    traffic_status::traffic_status_update(first_packet.len(), 0)?;
    dns_server.write_all(&first_packet).await?;

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
                if try_respond_from_dns_cache(&mut udp, &buf1[..len], ipv6_enabled, &dns_cache).await.unwrap_or(false) {
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

/// When bypassing in Virtual DNS mode, resolve the fake IP to a real address.
/// Returns `false` if resolution fails, signaling the caller to fall back to proxy.
pub(crate) async fn resolve_bypass_destination(
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

#[cfg(test)]
#[path = "dns_tests.rs"]
mod tests;
