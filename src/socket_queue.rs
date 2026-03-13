use std::{
    io::ErrorKind,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio::{
    net::{TcpSocket, TcpStream, UdpSocket},
    sync::{Mutex, mpsc::Receiver},
};
use udp_stream::UdpStream;

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

pub(crate) struct SocketQueue {
    pub(crate) tcp_v4: Mutex<Receiver<TcpSocket>>,
    pub(crate) tcp_v6: Mutex<Receiver<TcpSocket>>,
    pub(crate) udp_v4: Mutex<Receiver<UdpSocket>>,
    pub(crate) udp_v6: Mutex<Receiver<UdpSocket>>,
}

impl SocketQueue {
    pub(crate) async fn recv_tcp(&self, domain: SocketDomain) -> Result<TcpSocket, std::io::Error> {
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
    pub(crate) async fn recv_udp(&self, domain: SocketDomain) -> Result<UdpSocket, std::io::Error> {
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

pub(crate) async fn create_tcp_stream(socket_queue: &Option<Arc<SocketQueue>>, peer: SocketAddr) -> std::io::Result<TcpStream> {
    match &socket_queue {
        None => TcpStream::connect(peer).await,
        Some(queue) => queue.recv_tcp(peer.ip().into()).await?.connect(peer).await,
    }
}

pub(crate) async fn create_udp_stream(socket_queue: &Option<Arc<SocketQueue>>, peer: SocketAddr) -> std::io::Result<UdpStream> {
    match &socket_queue {
        None => UdpStream::connect(peer).await,
        Some(queue) => {
            let socket = queue.recv_udp(peer.ip().into()).await?;
            socket.connect(peer).await?;
            UdpStream::from_tokio(socket, peer).await
        }
    }
}
