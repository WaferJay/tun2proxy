use crate::{
    dns, dns_mapping,
    error::Result,
    proxy_handler::{self, ProxyHandler},
    socket_queue::{SocketQueue, create_tcp_stream},
};
use socks5_impl::protocol::{Address, AsyncStreamOperation, BufMut, StreamOperation};
use std::{collections::VecDeque, hash::Hash, net::SocketAddr, sync::Arc, sync::atomic::Ordering::Relaxed};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::Mutex,
    time::{Duration, sleep},
};

pub(crate) const UDPGW_LENGTH_FIELD_SIZE: usize = std::mem::size_of::<u16>();
pub(crate) const UDPGW_MAX_CONNECTIONS: usize = 5;
pub(crate) const UDPGW_KEEPALIVE_TIME: tokio::time::Duration = std::time::Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UdpFlag(pub u8);

impl UdpFlag {
    pub const ZERO: UdpFlag = UdpFlag(0x00);
    pub const KEEPALIVE: UdpFlag = UdpFlag(0x01);
    pub const ERR: UdpFlag = UdpFlag(0x20);
    pub const DATA: UdpFlag = UdpFlag(0x02);
}

impl std::fmt::Display for UdpFlag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let flag = match self.0 {
            0x00 => "ZERO",
            0x01 => "KEEPALIVE",
            0x20 => "ERR",
            0x02 => "DATA",
            n => return write!(f, "Unknown UdpFlag(0x{n:02X})"),
        };
        write!(f, "{flag}")
    }
}

impl std::ops::BitAnd for UdpFlag {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self::Output {
        UdpFlag(self.0 & rhs.0)
    }
}

impl std::ops::BitOr for UdpFlag {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        UdpFlag(self.0 | rhs.0)
    }
}

/// UDP Gateway Packet Format
///
/// The format is referenced from SOCKS5 packet format, with additional flags and connection ID fields.
///
/// `LEN`: This field is indicated the length of the packet, not including the length field itself.
///
/// `FLAGS`: This field is used to indicate the packet type. The flags are defined as follows:
/// - `0x01`: Keepalive packet without address and data
/// - `0x20`: Error packet without address and data
/// - `0x02`: Data packet with address and data
///
/// `CONN_ID`: This field is used to indicate the unique connection ID for the packet.
///
/// `ATYP` & `DST.ADDR` & `DST.PORT`: This fields are used to indicate the remote address and port.
/// It can be either an IPv4 address, an IPv6 address, or a domain name, depending on the `ATYP` field.
/// The address format directly uses the address format of the [SOCKS5](https://datatracker.ietf.org/doc/html/rfc1928#section-4) protocol.
/// - `ATYP`: Address Type, 1 byte, indicating the type of address ( 0x01-IPv4, 0x04-IPv6, or 0x03-domain name )
/// - `DST.ADDR`: Destination Address. If `ATYP` is 0x01 or 0x04, it is 4 or 16 bytes of IP address;
///   If `ATYP` is 0x03, it is a domain name, `DST.ADDR` is a variable length field,
///   it begins with a 1-byte length field and then the domain name without null-termination,
///   since the length field is 1 byte, the maximum length of the domain name is 255 bytes.
/// - `DST.PORT`: Destination Port, 2 bytes, the port number of the destination address.
///
/// `DATA`: The data field, a variable length field, the length is determined by the `LEN` field.
///
/// All the digits fields are in big-endian byte order.
///
/// ```plain
/// +-----+  +-------+---------+  +------+----------+----------+  +----------+
/// | LEN |  | FLAGS | CONN_ID |  | ATYP | DST.ADDR | DST.PORT |  |   DATA   |
/// +-----+  +-------+---------+  +------+----------+----------+  +----------+
/// |  2  |  |   1   |    2    |  |  1   | Variable |    2     |  | Variable |
/// +-----+  +-------+---------+  +------+----------+----------+  +----------+
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Packet {
    pub header: UdpgwHeader,
    pub address: Option<Address>,
    pub data: Vec<u8>,
}

impl std::fmt::Display for Packet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let addr = self.address.as_ref().map_or("None".to_string(), |addr| addr.to_string());
        let len = self.data.len();
        write!(f, "Packet {{ {}, address: {}, payload length: {} }}", self.header, addr, len)
    }
}

impl From<Packet> for Vec<u8> {
    fn from(packet: Packet) -> Vec<u8> {
        (&packet).into()
    }
}

impl From<&Packet> for Vec<u8> {
    fn from(packet: &Packet) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![];
        packet.write_to_buf(&mut bytes);
        bytes
    }
}

impl TryFrom<&[u8]> for Packet {
    type Error = std::io::Error;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        if value.len() < UDPGW_LENGTH_FIELD_SIZE {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        let mut iter = std::io::Cursor::new(value);
        use tokio_util::bytes::Buf;
        let length = iter.get_u16();
        if value.len() < length as usize + UDPGW_LENGTH_FIELD_SIZE {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        let header = UdpgwHeader::retrieve_from_stream(&mut iter)?;
        let address = if header.flags & UdpFlag::DATA != UdpFlag::ZERO {
            Some(Address::retrieve_from_stream(&mut iter)?)
        } else {
            None
        };
        Ok(Packet::new(header, address, iter.chunk()))
    }
}

impl Packet {
    pub fn new(header: UdpgwHeader, address: Option<Address>, data: &[u8]) -> Self {
        let data = data.to_vec();
        Packet { header, address, data }
    }

    pub fn build_keepalive_packet(conn_id: u16) -> Self {
        Packet::new(UdpgwHeader::new(UdpFlag::KEEPALIVE, conn_id), None, &[])
    }

    pub fn build_error_packet(conn_id: u16) -> Self {
        Packet::new(UdpgwHeader::new(UdpFlag::ERR, conn_id), None, &[])
    }

    pub fn build_packet_from_address(conn_id: u16, remote_addr: &Address, data: &[u8]) -> std::io::Result<Self> {
        use socks5_impl::protocol::Address::{DomainAddress, SocketAddress};
        let packet = match remote_addr {
            SocketAddress(addr) => Packet::build_ip_packet(conn_id, *addr, data),
            DomainAddress(domain, port) => Packet::build_domain_packet(conn_id, *port, domain, data)?,
        };
        Ok(packet)
    }

    pub fn build_ip_packet(conn_id: u16, remote_addr: SocketAddr, data: &[u8]) -> Self {
        let addr: Address = remote_addr.into();
        Packet::new(UdpgwHeader::new(UdpFlag::DATA, conn_id), Some(addr), data)
    }

    pub fn build_domain_packet(conn_id: u16, port: u16, domain: &str, data: &[u8]) -> std::io::Result<Self> {
        if domain.len() > 255 {
            return Err(std::io::ErrorKind::InvalidInput.into());
        }
        let addr = Address::from((domain, port));
        Ok(Packet::new(UdpgwHeader::new(UdpFlag::DATA, conn_id), Some(addr), data))
    }
}

impl StreamOperation for Packet {
    fn retrieve_from_stream<R>(stream: &mut R) -> std::io::Result<Self>
    where
        R: std::io::Read,
        Self: Sized,
    {
        let mut buf = [0; UDPGW_LENGTH_FIELD_SIZE];
        stream.read_exact(&mut buf)?;
        let length = u16::from_be_bytes(buf) as usize;
        let header = UdpgwHeader::retrieve_from_stream(stream)?;
        let address = if header.flags & UdpFlag::DATA == UdpFlag::DATA {
            Some(Address::retrieve_from_stream(stream)?)
        } else {
            None
        };
        let read_len = header.len() + address.as_ref().map_or(0, |addr| addr.len());
        if length < read_len {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        let mut data = vec![0; length - read_len];
        stream.read_exact(&mut data)?;
        Ok(Packet::new(header, address, &data))
    }

    fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        let len = self.len() - UDPGW_LENGTH_FIELD_SIZE;
        buf.put_u16(len as u16);
        self.header.write_to_buf(buf);
        if let Some(addr) = &self.address {
            addr.write_to_buf(buf);
        }
        buf.put_slice(&self.data);
    }

    fn len(&self) -> usize {
        UDPGW_LENGTH_FIELD_SIZE + self.header.len() + self.address.as_ref().map_or(0, |addr| addr.len()) + self.data.len()
    }
}

#[async_trait::async_trait]
impl AsyncStreamOperation for Packet {
    async fn retrieve_from_async_stream<R>(r: &mut R) -> std::io::Result<Self>
    where
        R: tokio::io::AsyncRead + Unpin + Send + ?Sized,
        Self: Sized,
    {
        let mut buf = [0; UDPGW_LENGTH_FIELD_SIZE];
        r.read_exact(&mut buf).await?;
        let length = u16::from_be_bytes(buf) as usize;
        let header = UdpgwHeader::retrieve_from_async_stream(r).await?;
        let address = if header.flags & UdpFlag::DATA == UdpFlag::DATA {
            Some(Address::retrieve_from_async_stream(r).await?)
        } else {
            None
        };
        let read_len = header.len() + address.as_ref().map_or(0, |addr| addr.len());
        if length < read_len {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        let mut data = vec![0; length - read_len];
        r.read_exact(&mut data).await?;
        Ok(Packet::new(header, address, &data))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UdpgwHeader {
    pub flags: UdpFlag,
    pub conn_id: u16,
}

impl std::fmt::Display for UdpgwHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} conn_id: {}", self.flags, self.conn_id)
    }
}

impl StreamOperation for UdpgwHeader {
    fn retrieve_from_stream<R>(stream: &mut R) -> std::io::Result<Self>
    where
        R: std::io::Read,
        Self: Sized,
    {
        let mut buf = [0; UdpgwHeader::static_len()];
        stream.read_exact(&mut buf)?;
        UdpgwHeader::try_from(&buf[..])
    }

    fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        let bytes: Vec<u8> = self.into();
        buf.put_slice(&bytes);
    }

    fn len(&self) -> usize {
        Self::static_len()
    }
}

#[async_trait::async_trait]
impl AsyncStreamOperation for UdpgwHeader {
    async fn retrieve_from_async_stream<R>(r: &mut R) -> std::io::Result<Self>
    where
        R: tokio::io::AsyncRead + Unpin + Send + ?Sized,
        Self: Sized,
    {
        let mut buf = [0; UdpgwHeader::static_len()];
        r.read_exact(&mut buf).await?;
        UdpgwHeader::try_from(&buf[..])
    }
}

impl UdpgwHeader {
    pub fn new(flags: UdpFlag, conn_id: u16) -> Self {
        UdpgwHeader { flags, conn_id }
    }

    pub const fn static_len() -> usize {
        std::mem::size_of::<u8>() + std::mem::size_of::<u16>()
    }
}

impl TryFrom<&[u8]> for UdpgwHeader {
    type Error = std::io::Error;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        if value.len() < UdpgwHeader::static_len() {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        let conn_id = u16::from_be_bytes([value[1], value[2]]);
        Ok(UdpgwHeader::new(UdpFlag(value[0]), conn_id))
    }
}

impl From<&UdpgwHeader> for Vec<u8> {
    fn from(header: &UdpgwHeader) -> Vec<u8> {
        let mut bytes = vec![0; header.len()];
        bytes[0] = header.flags.0;
        bytes[1..3].copy_from_slice(&header.conn_id.to_be_bytes());
        bytes
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub(crate) enum UdpGwResponse {
    KeepAlive,
    Error,
    TcpClose,
    Data(Packet),
}

impl std::fmt::Display for UdpGwResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UdpGwResponse::KeepAlive => write!(f, "KeepAlive"),
            UdpGwResponse::Error => write!(f, "Error"),
            UdpGwResponse::TcpClose => write!(f, "TcpClose"),
            UdpGwResponse::Data(packet) => write!(f, "Data({packet})"),
        }
    }
}

static SERIAL_NUMBER: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(1);

#[derive(Debug)]
pub(crate) struct UdpGwClientStream {
    local_addr: SocketAddr,
    writer: Option<OwnedWriteHalf>,
    reader: Option<OwnedReadHalf>,
    closed: bool,
    last_activity: std::time::Instant,
    serial_number: u16,
}

impl UdpGwClientStream {
    pub fn close(&mut self) {
        self.closed = true;
    }

    pub fn get_reader(&mut self) -> Option<OwnedReadHalf> {
        self.reader.take()
    }

    pub fn set_reader(&mut self, reader: Option<OwnedReadHalf>) {
        self.reader = reader;
    }

    pub fn set_writer(&mut self, writer: Option<OwnedWriteHalf>) {
        self.writer = writer;
    }

    pub fn get_writer(&mut self) -> Option<OwnedWriteHalf> {
        self.writer.take()
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn update_activity(&mut self) {
        self.last_activity = std::time::Instant::now();
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    pub fn serial_number(&self) -> u16 {
        self.serial_number
    }

    pub fn new(tcp_server_stream: TcpStream) -> Self {
        let default = "0.0.0.0:0".parse::<SocketAddr>().unwrap();
        let local_addr = tcp_server_stream.local_addr().unwrap_or(default);
        let (reader, writer) = tcp_server_stream.into_split();
        let serial_number = SERIAL_NUMBER.fetch_add(1, Relaxed);
        UdpGwClientStream {
            local_addr,
            reader: Some(reader),
            writer: Some(writer),
            last_activity: std::time::Instant::now(),
            closed: false,
            serial_number,
        }
    }
}

#[derive(Debug)]
pub(crate) struct UdpGwClient {
    udp_mtu: u16,
    max_connections: usize,
    udp_timeout: u64,
    keepalive_time: Duration,
    udpgw_server: SocketAddr,
    server_connections: Mutex<VecDeque<UdpGwClientStream>>,
}

impl UdpGwClient {
    pub fn new(udp_mtu: u16, max_connections: usize, keepalive_time: Duration, udp_timeout: u64, udpgw_server: SocketAddr) -> Self {
        let server_connections = Mutex::new(VecDeque::with_capacity(max_connections));
        UdpGwClient {
            udp_mtu,
            max_connections,
            udp_timeout,
            udpgw_server,
            keepalive_time,
            server_connections,
        }
    }

    pub(crate) fn get_udp_mtu(&self) -> u16 {
        self.udp_mtu
    }

    pub(crate) fn get_udp_timeout(&self) -> u64 {
        self.udp_timeout
    }

    pub(crate) async fn pop_server_connection_from_queue(&self) -> Option<UdpGwClientStream> {
        self.server_connections.lock().await.pop_front()
    }

    pub(crate) async fn store_server_connection(&self, stream: UdpGwClientStream) {
        if self.server_connections.lock().await.len() < self.max_connections {
            self.server_connections.lock().await.push_back(stream);
        }
    }

    pub(crate) async fn store_server_connection_full(&self, mut stream: UdpGwClientStream, reader: OwnedReadHalf, writer: OwnedWriteHalf) {
        if self.server_connections.lock().await.len() < self.max_connections {
            stream.set_reader(Some(reader));
            stream.set_writer(Some(writer));
            self.server_connections.lock().await.push_back(stream);
        }
    }

    pub(crate) fn get_udpgw_server_addr(&self) -> SocketAddr {
        self.udpgw_server
    }

    /// Heartbeat task asynchronous function to periodically check and maintain the active state of the server connection.
    pub(crate) async fn heartbeat_task(&self, shutdown_token: tokio_util::sync::CancellationToken) -> std::io::Result<()> {
        log::info!("udpgw: heartbeat task started");
        loop {
            tokio::select! {
                _ = shutdown_token.cancelled() => break,
                _ = sleep(self.keepalive_time) => {}
            };

            let mut streams = Vec::new();

            while let Some(stream) = self.pop_server_connection_from_queue().await {
                if !stream.is_closed() {
                    streams.push(stream);
                }
            }

            let (mut tx, mut rx) = (0, 0);

            for mut stream in streams {
                if stream.last_activity.elapsed() < self.keepalive_time {
                    self.store_server_connection(stream).await;
                    continue;
                }

                let Some(mut stream_reader) = stream.get_reader() else {
                    continue;
                };

                let Some(mut stream_writer) = stream.get_writer() else {
                    continue;
                };
                let local_addr = stream_writer.local_addr()?;
                let sn = stream.serial_number();
                let keepalive_packet: Vec<u8> = Packet::build_keepalive_packet(sn).into();
                tx += keepalive_packet.len();
                if let Err(e) = stream_writer.write_all(&keepalive_packet).await {
                    log::warn!("stream {sn} {local_addr:?} send keepalive failed: {e}");
                    continue;
                }
                match UdpGwClient::recv_udpgw_packet(self.udp_mtu, self.udp_timeout, &mut stream_reader).await {
                    Ok((len, UdpGwResponse::KeepAlive)) => {
                        stream.update_activity();
                        self.store_server_connection_full(stream, stream_reader, stream_writer).await;
                        log::trace!("stream {sn} {local_addr:?} send keepalive and recieve it successfully");
                        rx += len;
                    }
                    Ok((len, v)) => {
                        log::debug!("stream {sn} {local_addr:?} keepalive unexpected response: {v}");
                        rx += len;
                    }
                    Err(e) => log::debug!("stream {sn} {local_addr:?} keepalive no response, error \"{e}\""),
                }
            }
            crate::traffic_status::traffic_status_update(tx, rx)?;
        }
        log::info!("udpgw: heartbeat task exiting");
        Ok(())
    }

    /// Parses the UDP response data.
    pub(crate) fn parse_udp_response(udp_mtu: u16, packet: Packet) -> Result<UdpGwResponse> {
        let flags = packet.header.flags;
        if flags & UdpFlag::ERR == UdpFlag::ERR {
            return Ok(UdpGwResponse::Error);
        }
        if flags & UdpFlag::KEEPALIVE == UdpFlag::KEEPALIVE {
            return Ok(UdpGwResponse::KeepAlive);
        }
        if packet.data.len() > udp_mtu as usize {
            return Err("too much data".into());
        }
        Ok(UdpGwResponse::Data(packet))
    }

    /// Receives a UDP gateway packet.
    ///
    /// This function is responsible for receiving packets from the UDP gateway
    ///
    /// # Arguments
    /// - `udp_mtu`: The maximum transmission unit size for UDP packets.
    /// - `udp_timeout`: The timeout in seconds for receiving UDP packets.
    /// - `stream`: A mutable reference to the UDP gateway client stream reader.
    ///
    /// # Returns
    /// - `Result<UdpGwResponse>`: Returns a result type containing the parsed UDP gateway response, or an error if one occurs.
    pub(crate) async fn recv_udpgw_packet(udp_mtu: u16, udp_timeout: u64, stream: &mut OwnedReadHalf) -> Result<(usize, UdpGwResponse)> {
        let packet = tokio::time::timeout(
            tokio::time::Duration::from_secs(udp_timeout + 2),
            Packet::retrieve_from_async_stream(stream),
        )
        .await
        .map_err(std::io::Error::from)??;
        Ok((packet.len(), UdpGwClient::parse_udp_response(udp_mtu, packet)?))
    }

    /// Sends a UDP gateway packet.
    ///
    /// This function constructs and sends a UDP gateway packet based on the IPv6 enabled status, data length,
    /// remote address, domain (if any), connection ID, and the UDP gateway client writer stream.
    ///
    /// # Arguments
    ///
    /// * `ipv6_enabled` - Whether IPv6 is enabled
    /// * `data` - The data packet
    /// * `remote_addr` - Remote address
    /// * `conn_id` - Connection ID
    /// * `stream` - UDP gateway client writer stream
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the packet is sent successfully, otherwise returns an error.
    pub(crate) async fn send_udpgw_packet(
        ipv6_enabled: bool,
        data: &[u8],
        remote_addr: &socks5_impl::protocol::Address,
        conn_id: u16,
        stream: &mut OwnedWriteHalf,
    ) -> Result<()> {
        if !ipv6_enabled && remote_addr.get_type() == socks5_impl::protocol::AddressType::IPv6 {
            return Err("ipv6 not support".into());
        }
        let out_data: Vec<u8> = Packet::build_packet_from_address(conn_id, remote_addr, data)?.into();
        stream.write_all(&out_data).await?;

        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_udp_gateway_session(
    mut udp_stack: ipstack::IpStackUdpStream,
    udpgw_client: Arc<UdpGwClient>,
    udp_dst: &Address,
    proxy_handler: Arc<Mutex<dyn ProxyHandler>>,
    socket_queue: Option<Arc<SocketQueue>>,
    ipv6_enabled: bool,
    dns_cache: dns_mapping::SharedDnsCache,
    dns_first_packet: Option<Vec<u8>>,
) -> Result<()> {
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
                match proxy_handler::handle_proxy_session(&mut tcp_server_stream, proxy_handler).await {
                    Err(e) => return Err(format!("udpgw connection error: {e}").into()),
                    Ok(proxy_handler::ProxyResult::Bypass(bypass_addr)) => {
                        let _ = tcp_server_stream.shutdown().await;
                        log::info!("udpgw bypassing proxy, connecting directly to {bypass_addr}");
                        tcp_server_stream = create_tcp_stream(&socket_queue, bypass_addr).await?;
                    }
                    Ok(proxy_handler::ProxyResult::UdpAssociate(_)) => {
                        return Err("unexpected UDP associate response in udpgw session".into());
                    }
                    Ok(proxy_handler::ProxyResult::Established) => {}
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

    // Forward the pre-read DNS first packet (already checked for cache miss in the main loop).
    if let Some(first_packet) = dns_first_packet {
        crate::traffic_status::traffic_status_update(first_packet.len(), 0)?;
        let sn = stream.serial_number();
        if let Err(e) = UdpGwClient::send_udpgw_packet(ipv6_enabled, &first_packet, udp_dst, sn, &mut writer).await {
            log::info!(
                "[UdpGw] Ending stream {} {} <> {} with send_udpgw_packet {}",
                sn,
                &tcp_local_addr,
                udp_dst,
                e
            );
            if !stream.is_closed() {
                udpgw_client.store_server_connection_full(stream, reader, writer).await;
            }
            return Ok(());
        }
        log::debug!(
            "[UdpGw] stream {} {} -> {} send first_packet len {}",
            sn,
            &tcp_local_addr,
            udp_dst,
            first_packet.len()
        );
        stream.update_activity();
    }

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
                if udp_dst.port() == dns::DNS_PORT
                    && dns::try_respond_from_dns_cache(&mut udp_stack, &tmp_buf[..read_len], ipv6_enabled, &dns_cache).await.unwrap_or(false)
                {
                    continue;
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
                            let payload = if udp_dst.port() == dns::DNS_PORT {
                                match dns::snoop_dns_response(&data.data, &dns_cache, ipv6_enabled).await {
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
