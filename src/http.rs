use crate::{
    directions::{IncomingDataEvent, IncomingDirection, OutgoingDataEvent, OutgoingDirection},
    error::{Error, Result},
    proxy_handler::{ProxyHandler, ProxyHandlerManager},
    session_info::{IpProtocol, SessionInfo},
};
use httparse::Response;
use socks5_impl::protocol::UserKey;
use std::{collections::VecDeque, net::SocketAddr, str, sync::Arc};
use std::collections::HashMap;
use std::hash::RandomState;
use tokio::sync::Mutex;
use unicase::UniCase;

pub(crate) type DigestState = digest_auth::WwwAuthenticateHeader;

pub enum AuthResult {
    /// Abort the connection – treat the response as a fatal error.
    Abort,
    /// Retry the request with the current authenticator (e.g. Digest stale nonce refresh).
    Retry,
    /// Replace the authenticator and retry (e.g. Basic → Digest upgrade).
    RetryWith(Arc<dyn HttpAuthenticator>),
    /// Bypass the proxy and connect directly to the destination.
    Bypass,
}

#[async_trait::async_trait]
pub trait HttpAuthenticator: Send + Sync {
    /// Generate authentication request headers, returning `(name, value)` pairs.
    async fn generate_auth_headers(&self, uri: &str) -> Result<Vec<(String, String)>>;

    /// Called when the proxy responds with a non-200 status code (e.g. 407).
    /// `is_retry` is `true` when auth has already been attempted on this connection.
    async fn handle_failure(
        &self,
        status_code: u16,
        response_headers: &HashMap<UniCase<&str>, &[u8], RandomState>,
        is_retry: bool,
    ) -> Result<AuthResult>;
}

pub struct BasicPasswordAuthenticator {
    credentials: UserKey,
    digest_state: Arc<Mutex<Option<DigestState>>>,
}

impl BasicPasswordAuthenticator {
    pub fn new(credentials: UserKey) -> Self {
        Self {
            credentials,
            digest_state: Arc::new(Mutex::new(None)),
        }
    }
}

/// Alias for `BasicPasswordAuthenticator` – the standard password authenticator
/// that starts with Basic and automatically upgrades to Digest when challenged.
pub type PasswordAuthenticator = BasicPasswordAuthenticator;

#[async_trait::async_trait]
impl HttpAuthenticator for BasicPasswordAuthenticator {
    async fn generate_auth_headers(&self, _uri: &str) -> Result<Vec<(String, String)>> {
        let auth_b64 =
            base64easy::encode(self.credentials.to_string(), base64easy::EngineKind::Standard);
        Ok(vec![(
            PROXY_AUTHORIZATION.to_string(),
            format!("Basic {auth_b64}"),
        )])
    }

    async fn handle_failure(
        &self,
        status_code: u16,
        response_headers: &HashMap<UniCase<&str>, &[u8], RandomState>,
        _is_retry: bool,
    ) -> Result<AuthResult> {
        if status_code != 407 {
            return Ok(AuthResult::Abort);
        }

        let Some(auth_data) = response_headers.get(&UniCase::new(PROXY_AUTHENTICATE)) else {
            return Err("Proxy requires auth but doesn't send its details".into());
        };

        if auth_data.len() < 6 || !auth_data[..6].eq_ignore_ascii_case(b"digest") {
            return Err("Bad credentials".into());
        }

        // Parse the Digest challenge and store it in the shared state.
        let data = str::from_utf8(auth_data)?;
        let state = digest_auth::parse(data)?;
        self.digest_state.lock().await.replace(state);

        let digest_auth = Arc::new(DigestPasswordAuthenticator {
            credentials: self.credentials.clone(),
            digest_state: self.digest_state.clone(),
        });
        Ok(AuthResult::RetryWith(digest_auth))
    }
}

pub(crate) struct DigestPasswordAuthenticator {
    credentials: UserKey,
    digest_state: Arc<Mutex<Option<DigestState>>>,
}

#[async_trait::async_trait]
impl HttpAuthenticator for DigestPasswordAuthenticator {
    async fn generate_auth_headers(&self, uri: &str) -> Result<Vec<(String, String)>> {
        let context = digest_auth::AuthContext::new_with_method(
            &self.credentials.username,
            &self.credentials.password,
            uri,
            Option::<&'_ [u8]>::None,
            digest_auth::HttpMethod::CONNECT,
        );

        let mut state = self.digest_state.lock().await;
        let response = state
            .as_mut()
            .ok_or_else(|| Error::from("Digest state not initialized"))?
            .respond(&context)
            .map_err(|e| Error::from(e.to_string()))?;

        Ok(vec![(
            PROXY_AUTHORIZATION.to_string(),
            response.to_header_string(),
        )])
    }

    async fn handle_failure(
        &self,
        status_code: u16,
        response_headers: &HashMap<UniCase<&str>, &[u8], RandomState>,
        is_retry: bool,
    ) -> Result<AuthResult> {
        if status_code != 407 {
            return Ok(AuthResult::Abort);
        }

        let Some(auth_data) = response_headers.get(&UniCase::new(PROXY_AUTHENTICATE)) else {
            return Err("Proxy requires auth but doesn't send its details".into());
        };

        let data = str::from_utf8(auth_data)?;
        let state = digest_auth::parse(data)?;

        if is_retry && !state.stale {
            return Err("Bad credentials".into());
        }

        self.digest_state.lock().await.replace(state);
        Ok(AuthResult::Retry)
    }
}

#[derive(Eq, PartialEq, Debug)]
#[allow(dead_code)]
enum HttpState {
    SendRequest,
    ExpectResponseHeaders,
    ExpectResponse,
    Reset,
    Established,
}

pub struct HttpConnection {
    server_addr: SocketAddr,
    state: HttpState,
    client_inbuf: VecDeque<u8>,
    server_inbuf: VecDeque<u8>,
    client_outbuf: VecDeque<u8>,
    server_outbuf: VecDeque<u8>,
    crlf_state: u8,
    counter: usize,
    skip: usize,
    authenticator: Option<Arc<dyn HttpAuthenticator>>,
    shared_auth: Arc<Mutex<Option<Arc<dyn HttpAuthenticator>>>>,
    before: bool,
    info: SessionInfo,
    domain_name: Option<String>,
}

static PROXY_AUTHENTICATE: &str = "Proxy-Authenticate";
static PROXY_AUTHORIZATION: &str = "Proxy-Authorization";
static CONNECTION: &str = "Connection";
static TRANSFER_ENCODING: &str = "Transfer-Encoding";
static CONTENT_LENGTH: &str = "Content-Length";

impl HttpConnection {
    async fn new(
        server_addr: SocketAddr,
        info: SessionInfo,
        domain_name: Option<String>,
        authenticator: Option<Arc<dyn HttpAuthenticator>>,
        shared_auth: Arc<Mutex<Option<Arc<dyn HttpAuthenticator>>>>,
    ) -> Result<Self> {
        let mut res = Self {
            server_addr,
            state: HttpState::ExpectResponseHeaders,
            client_inbuf: VecDeque::default(),
            server_inbuf: VecDeque::default(),
            client_outbuf: VecDeque::default(),
            server_outbuf: VecDeque::default(),
            skip: 0,
            counter: 0,
            crlf_state: 0,
            authenticator,
            shared_auth,
            before: false,
            info,
            domain_name,
        };

        res.send_tunnel_request().await?;
        Ok(res)
    }

    async fn send_tunnel_request(&mut self) -> Result<(), Error> {
        let host = if let Some(domain_name) = &self.domain_name {
            format!("{}:{}", domain_name, self.info.dst.port())
        } else {
            self.info.dst.to_string()
        };

        self.server_outbuf.extend(b"CONNECT ");
        self.server_outbuf.extend(host.as_bytes());
        self.server_outbuf.extend(b" HTTP/1.1\r\nHost: ");
        self.server_outbuf.extend(host.as_bytes());
        self.server_outbuf.extend(b"\r\n");

        if let Some(auth) = &self.authenticator {
            for (name, value) in auth.generate_auth_headers(&host).await? {
                self.server_outbuf
                    .extend(format!("{name}: {value}\r\n").as_bytes());
            }
        }

        self.server_outbuf.extend(b"\r\n");
        Ok(())
    }

    async fn state_change(&mut self) -> Result<()> {
        match self.state {
            HttpState::ExpectResponseHeaders => {
                while self.counter < self.server_inbuf.len() {
                    let b = self.server_inbuf[self.counter];
                    if b == b'\n' {
                        self.crlf_state += 1;
                    } else if b != b'\r' {
                        self.crlf_state = 0;
                    }

                    self.counter += 1;
                    if self.crlf_state == 2 {
                        break;
                    }
                }

                if self.crlf_state != 2 {
                    // Waiting for the end of the headers yet
                    return Ok(());
                }

                let header_size = self.counter;

                self.counter = 0;
                self.crlf_state = 0;

                let mut headers = [httparse::EMPTY_HEADER; 16];

                let (len, status_code, version, reason) = {
                    let mut res = Response::new(&mut headers);
                    let slice = self.server_inbuf.make_contiguous();
                    let status = res.parse(slice)?;
                    if status.is_partial() {
                        return Ok(());
                    }
                    (
                        status.unwrap(),
                        res.code.unwrap(),
                        res.version.unwrap(),
                        res.reason.unwrap_or("").to_string(),
                    )
                };

                if status_code == 200 {
                    // Connection successful
                    self.state = HttpState::Established;
                    // The server may have sent a banner already (SMTP, SSH, etc.).
                    // Therefore, server_inbuf must retain this data.
                    self.server_inbuf.drain(0..header_size);
                    return Box::pin(self.state_change()).await;
                }

                let headers_map: HashMap<UniCase<&str>, &[u8], RandomState> =
                    HashMap::from_iter(headers.map(|x| (UniCase::new(x.name), x.value)));

                let auth = match &self.authenticator {
                    Some(a) => a.clone(),
                    None => {
                        return Err(
                            format!("HTTP {} [{}]", status_code, reason).into()
                        );
                    }
                };

                match auth
                    .handle_failure(status_code, &headers_map, self.before)
                    .await?
                {
                    AuthResult::Retry => { /* use current authenticator */ }
                    AuthResult::RetryWith(new_auth) => {
                        self.authenticator = Some(new_auth.clone());
                        *self.shared_auth.lock().await = Some(new_auth);
                    }
                    AuthResult::Abort => {
                        return Err(
                            format!("HTTP {} [{}]", status_code, reason).into()
                        );
                    }
                    AuthResult::Bypass => {
                        self.server_inbuf.clear();
                        self.server_outbuf.clear();
                        self.client_inbuf.clear();
                        self.client_outbuf.clear();
                        self.server_addr = self.info.dst;
                        self.state = HttpState::Established;
                        return Ok(());
                    }
                }
                self.before = true;

                let closed = match headers_map.get(&UniCase::new(CONNECTION)) {
                    Some(conn_header) => conn_header.eq_ignore_ascii_case(b"close"),
                    None => false,
                };

                if closed || version == 0 {
                    // Close mio stream connection and reset it
                    // Reset all the buffers
                    self.server_inbuf.clear();
                    self.server_outbuf.clear();
                    self.send_tunnel_request().await?;

                    self.state = HttpState::Reset;
                    return Ok(());
                }

                // The HTTP/1.1 expected to be keep alive waiting for the next frame so, we must
                // compute the length of the response in order to detect the next frame (response)
                // [RFC-9112](https://datatracker.ietf.org/doc/html/rfc9112#body.content-length)

                // Transfer-Encoding isn't supported yet
                if headers_map.contains_key(&UniCase::new(TRANSFER_ENCODING)) {
                    unimplemented!("Header Transfer-Encoding not supported");
                }

                let content_length = match headers_map.get(&UniCase::new(CONTENT_LENGTH)) {
                    Some(v) => {
                        let value = str::from_utf8(v)?;

                        // https://www.rfc-editor.org/rfc/rfc9110#section-5.6.1
                        match value.parse::<usize>() {
                            Ok(x) => x,
                            Err(_) => {
                                let mut it = value.split(',').map(|x| x.parse::<usize>());
                                let f = it.next().unwrap()?;
                                for k in it {
                                    if k? != f {
                                        return Err("Malformed response".into());
                                    }
                                }
                                f
                            }
                        }
                    }
                    None => {
                        // Close the connection by information miss
                        self.server_inbuf.clear();
                        self.server_outbuf.clear();
                        self.send_tunnel_request().await?;

                        self.state = HttpState::Reset;
                        return Ok(());
                    }
                };

                // Handshake state
                self.state = HttpState::ExpectResponse;
                self.skip = content_length + len;

                return Box::pin(self.state_change()).await;
            }
            HttpState::ExpectResponse => {
                if self.skip > 0 {
                    let cnt = self.skip.min(self.server_inbuf.len());
                    self.server_inbuf.drain(..cnt);
                    self.skip -= cnt;
                }

                if self.skip == 0 {
                    // Expected to the server_inbuff to be empty

                    // self.server_outbuf.append(&mut self.data_buf);
                    // self.data_buf.clear();
                    self.send_tunnel_request().await?;
                    self.state = HttpState::ExpectResponseHeaders;

                    return Box::pin(self.state_change()).await;
                }
            }
            HttpState::Established => {
                self.client_outbuf.extend(self.server_inbuf.iter());
                self.server_outbuf.extend(self.client_inbuf.iter());
                self.server_inbuf.clear();
                self.client_inbuf.clear();
            }
            HttpState::Reset => {
                self.state = HttpState::ExpectResponseHeaders;
                return Box::pin(self.state_change()).await;
            }
            _ => {}
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl ProxyHandler for HttpConnection {
    fn get_server_addr(&self) -> SocketAddr {
        self.server_addr
    }

    fn get_session_info(&self) -> SessionInfo {
        self.info
    }

    fn get_domain_name(&self) -> Option<String> {
        self.domain_name.clone()
    }

    async fn push_data(&mut self, event: IncomingDataEvent<'_>) -> std::io::Result<()> {
        let direction = event.direction;
        let buffer = event.buffer;
        match direction {
            IncomingDirection::FromServer => {
                self.server_inbuf.extend(buffer.iter());
            }
            IncomingDirection::FromClient => {
                self.client_inbuf.extend(buffer.iter());
            }
        }

        self.state_change().await?;
        Ok(())
    }

    fn consume_data(&mut self, dir: OutgoingDirection, size: usize) {
        let buffer = if dir == OutgoingDirection::ToServer {
            &mut self.server_outbuf
        } else {
            &mut self.client_outbuf
        };
        buffer.drain(0..size);
    }

    fn peek_data(&mut self, dir: OutgoingDirection) -> OutgoingDataEvent<'_> {
        let buffer = if dir == OutgoingDirection::ToServer {
            &mut self.server_outbuf
        } else {
            &mut self.client_outbuf
        };
        OutgoingDataEvent {
            direction: dir,
            buffer: buffer.make_contiguous(),
        }
    }

    fn connection_established(&self) -> bool {
        self.state == HttpState::Established
    }

    fn data_len(&self, dir: OutgoingDirection) -> usize {
        match dir {
            OutgoingDirection::ToServer => self.server_outbuf.len(),
            OutgoingDirection::ToClient => self.client_outbuf.len(),
        }
    }

    fn reset_connection(&self) -> bool {
        self.state == HttpState::Reset
    }

    fn get_udp_associate(&self) -> Option<SocketAddr> {
        None
    }
}

pub struct HttpManager {
    server: SocketAddr,
    authenticator: Arc<Mutex<Option<Arc<dyn HttpAuthenticator>>>>,
}

#[async_trait::async_trait]
impl ProxyHandlerManager for HttpManager {
    async fn new_proxy_handler(
        &self,
        info: SessionInfo,
        domain_name: Option<String>,
        _udp_associate: bool,
    ) -> std::io::Result<Arc<Mutex<dyn ProxyHandler>>> {
        if info.protocol != IpProtocol::Tcp {
            return Err(Error::from("Protocol not supported by HTTP proxy").into());
        }
        let authenticator = self.authenticator.lock().await.clone();
        Ok(Arc::new(Mutex::new(
            HttpConnection::new(
                self.server,
                info,
                domain_name,
                authenticator,
                self.authenticator.clone(),
            )
            .await?,
        )))
    }
}

impl HttpManager {
    pub fn new(server: SocketAddr, authenticator: Option<Arc<dyn HttpAuthenticator>>) -> Self {
        Self {
            server,
            authenticator: Arc::new(Mutex::new(authenticator)),
        }
    }
}

#[cfg(test)]
#[path = "http_tests.rs"]
mod tests;
