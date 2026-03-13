use super::*;
use crate::no_proxy::NoProxyManager;
use crate::proxy_handler::ProxyHandlerManager;
use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

/// Create a connected TCP pair using a loopback listener.
async fn tcp_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();
    (client, server)
}

/// Build a minimal 12-byte DNS header with the given transaction ID.
fn make_dns_msg(txn_id: u16) -> Vec<u8> {
    let mut buf = vec![0u8; 12];
    buf[0..2].copy_from_slice(&txn_id.to_be_bytes());
    buf
}

/// Wrap a DNS message in TCP framing (2-byte big-endian length prefix).
fn tcp_frame(msg: &[u8]) -> Vec<u8> {
    let len = msg.len() as u16;
    let mut frame = Vec::with_capacity(2 + msg.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(msg);
    frame
}

/// Start a mock DNS server that ignores the first `skip` queries, then echoes
/// back each subsequent query with TCP framing (acting as a DNS "response").
async fn start_mock_dns_server(skip: usize) -> (std::net::SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut count = 0usize;
        loop {
            let mut len_buf = [0u8; 2];
            if stream.read_exact(&mut len_buf).await.is_err() {
                break;
            }
            let msg_len = u16::from_be_bytes(len_buf) as usize;
            let mut msg = vec![0u8; msg_len];
            if stream.read_exact(&mut msg).await.is_err() {
                break;
            }
            count += 1;
            if count > skip {
                let _ = stream.write_all(&len_buf).await;
                let _ = stream.write_all(&msg).await;
            }
        }
    });
    (addr, handle)
}

// ── reader_loop unit tests ───────────────────────────────────────

#[tokio::test]
async fn test_reader_loop_dispatches_by_txn_id() {
    let (client, server) = tcp_pair().await;
    let (reader, _writer) = client.into_split();
    let (_, mut server_writer) = server.into_split();

    let pending: Arc<Mutex<PendingMap>> = Arc::new(Mutex::new(HashMap::new()));

    let (tx1, rx1) = oneshot::channel();
    let (tx2, rx2) = oneshot::channel();
    {
        let mut map = pending.lock().await;
        map.insert(0x1111, vec![tx1]);
        map.insert(0x2222, vec![tx2]);
    }

    let pending_clone = pending.clone();
    let _reader_handle = tokio::spawn(async move {
        let _ = SharedDnsTcpClient::reader_loop(reader, &pending_clone).await;
    });

    // Send two TCP-framed DNS responses with different txn_ids.
    server_writer.write_all(&tcp_frame(&make_dns_msg(0x1111))).await.unwrap();
    server_writer.write_all(&tcp_frame(&make_dns_msg(0x2222))).await.unwrap();

    let result1 = rx1.await.unwrap().unwrap();
    let result2 = rx2.await.unwrap().unwrap();
    assert_eq!(&result1[0..2], &0x1111u16.to_be_bytes());
    assert_eq!(&result2[0..2], &0x2222u16.to_be_bytes());

    // Pending map should be empty after dispatch.
    assert!(pending.lock().await.is_empty());
}

#[tokio::test]
async fn test_reader_loop_drops_unknown_txn_id() {
    let (client, server) = tcp_pair().await;
    let (reader, _writer) = client.into_split();
    let (_, mut server_writer) = server.into_split();

    let pending: Arc<Mutex<PendingMap>> = Arc::new(Mutex::new(HashMap::new()));

    let (tx, rx) = oneshot::channel();
    pending.lock().await.insert(0x2222, vec![tx]);

    let pending_clone = pending.clone();
    let _reader_handle = tokio::spawn(async move {
        let _ = SharedDnsTcpClient::reader_loop(reader, &pending_clone).await;
    });

    // Send an unknown txn_id first — should be silently dropped.
    server_writer.write_all(&tcp_frame(&make_dns_msg(0x9999))).await.unwrap();
    // Then send a known txn_id — should be dispatched.
    server_writer.write_all(&tcp_frame(&make_dns_msg(0x2222))).await.unwrap();

    let result = rx.await.unwrap().unwrap();
    assert_eq!(&result[0..2], &0x2222u16.to_be_bytes());
}

#[tokio::test]
async fn test_reader_loop_broadcasts_to_all_senders() {
    let (client, server) = tcp_pair().await;
    let (reader, _writer) = client.into_split();
    let (_, mut server_writer) = server.into_split();

    let pending: Arc<Mutex<PendingMap>> = Arc::new(Mutex::new(HashMap::new()));

    let (tx1, rx1) = oneshot::channel();
    let (tx2, rx2) = oneshot::channel();
    pending.lock().await.insert(0x4444, vec![tx1, tx2]);

    let pending_clone = pending.clone();
    let _reader_handle = tokio::spawn(async move {
        let _ = SharedDnsTcpClient::reader_loop(reader, &pending_clone).await;
    });

    // One response should be cloned to both senders.
    server_writer.write_all(&tcp_frame(&make_dns_msg(0x4444))).await.unwrap();

    let r1 = rx1.await.unwrap().unwrap();
    let r2 = rx2.await.unwrap().unwrap();
    assert_eq!(&r1[0..2], &0x4444u16.to_be_bytes());
    assert_eq!(&r2[0..2], &0x4444u16.to_be_bytes());
}

#[tokio::test]
async fn test_reader_loop_notifies_pending_on_eof() {
    let (client, server) = tcp_pair().await;
    let (reader, _writer) = client.into_split();

    let pending: Arc<Mutex<PendingMap>> = Arc::new(Mutex::new(HashMap::new()));

    let (tx, rx) = oneshot::channel();
    pending.lock().await.insert(0x3333, vec![tx]);

    // Replicate the spawned task wrapper from ensure_connected: after reader_loop
    // exits, all remaining pending queries are notified.
    let pending_clone = pending.clone();
    let reader_handle = tokio::spawn(async move {
        if let Err(e) = SharedDnsTcpClient::reader_loop(reader, &pending_clone).await {
            log::debug!("reader ended: {e}");
        }
        let mut map = pending_clone.lock().await;
        for (_, senders) in map.drain() {
            for tx in senders {
                let _ = tx.send(Err("DNS TCP connection closed".into()));
            }
        }
    });

    // Close the server side — triggers EOF in reader_loop.
    drop(server);

    let result = rx.await.unwrap();
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("closed"));

    let _ = reader_handle.await;
}

// ── SharedDnsTcpClient::query() integration tests ────────────────

#[tokio::test]
async fn test_query_too_short() {
    // query() should reject messages shorter than 2 bytes without connecting.
    let mgr: Arc<dyn ProxyHandlerManager> = Arc::new(NoProxyManager::new());
    let addr = std::net::SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 1);
    let client = SharedDnsTcpClient::new(mgr, addr, None);

    let result = client.query(&[0x01]).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("too short"));
}

#[tokio::test]
async fn test_query_success() {
    let (addr, _server) = start_mock_dns_server(0).await;
    let mgr: Arc<dyn ProxyHandlerManager> = Arc::new(NoProxyManager::new());
    let client = SharedDnsTcpClient::new(mgr, addr, None);

    let response = client.query(&make_dns_msg(0xABCD)).await.unwrap();
    assert_eq!(&response[0..2], &0xABCDu16.to_be_bytes());
    assert_eq!(response.len(), 12);
}

#[tokio::test]
async fn test_concurrent_queries_different_txn_ids() {
    let (addr, _server) = start_mock_dns_server(0).await;
    let mgr: Arc<dyn ProxyHandlerManager> = Arc::new(NoProxyManager::new());
    let client = Arc::new(SharedDnsTcpClient::new(mgr, addr, None));

    let (c1, c2, c3) = (client.clone(), client.clone(), client.clone());
    let (msg1, msg2, msg3) = (make_dns_msg(0x0001), make_dns_msg(0x0002), make_dns_msg(0x0003));
    let (r1, r2, r3) = tokio::join!(
        c1.query(&msg1),
        c2.query(&msg2),
        c3.query(&msg3),
    );

    assert_eq!(&r1.unwrap()[0..2], &0x0001u16.to_be_bytes());
    assert_eq!(&r2.unwrap()[0..2], &0x0002u16.to_be_bytes());
    assert_eq!(&r3.unwrap()[0..2], &0x0003u16.to_be_bytes());
}

/// When multiple sessions send queries with the same txn_id concurrently
/// (common: the OS resolver retries from different UDP source ports),
/// they piggyback on a single in-flight query and all receive the response.
#[tokio::test]
async fn test_same_txn_id_concurrent_queries() {
    let (addr, _server) = start_mock_dns_server(0).await;
    let mgr: Arc<dyn ProxyHandlerManager> = Arc::new(NoProxyManager::new());
    let client = Arc::new(SharedDnsTcpClient::new(mgr, addr, None));

    let (c1, c2) = (client.clone(), client.clone());
    let (msg1, msg2) = (make_dns_msg(0x5555), make_dns_msg(0x5555));
    let (r1, r2) = tokio::join!(c1.query(&msg1), c2.query(&msg2));

    // Both should succeed — the second piggybacks on the first.
    assert_eq!(&r1.unwrap()[0..2], &0x5555u16.to_be_bytes());
    assert_eq!(&r2.unwrap()[0..2], &0x5555u16.to_be_bytes());
}

/// Regression test for the timeout cleanup bug:
///
/// Previously, `query()` used `try_lock()` for cleanup on timeout, which could
/// silently fail under lock contention, leaving stale entries in the pending
/// map. A subsequent query reusing the same transaction ID would then get a
/// false "collision" error instead of proceeding normally.
///
/// After a timeout the client now forces a reconnect, so the mock server must
/// accept a second connection for the retry.
#[tokio::test]
async fn test_timeout_cleanup_allows_txn_id_reuse() {
    tokio::time::pause();

    // Server: first connection reads one query but never responds (triggers timeout).
    // After client reconnects, second connection echoes queries normally.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let _server = tokio::spawn(async move {
        // First connection: accept, read one query, never respond.
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut len_buf = [0u8; 2];
        let _ = stream.read_exact(&mut len_buf).await;
        let msg_len = u16::from_be_bytes(len_buf) as usize;
        let mut msg = vec![0u8; msg_len];
        let _ = stream.read_exact(&mut msg).await;
        // Wait for client to close.
        let mut buf = [0u8; 1];
        let _ = stream.read(&mut buf).await;

        // Second connection: echo all queries.
        let (mut stream, _) = listener.accept().await.unwrap();
        loop {
            let mut len_buf = [0u8; 2];
            if stream.read_exact(&mut len_buf).await.is_err() {
                break;
            }
            let msg_len = u16::from_be_bytes(len_buf) as usize;
            let mut msg = vec![0u8; msg_len];
            if stream.read_exact(&mut msg).await.is_err() {
                break;
            }
            let _ = stream.write_all(&len_buf).await;
            let _ = stream.write_all(&msg).await;
        }
    });

    let mgr: Arc<dyn ProxyHandlerManager> = Arc::new(NoProxyManager::new());
    let client = SharedDnsTcpClient::new(mgr, addr, None);

    // First query — server won't respond, must time out.
    let result = client.query(&make_dns_msg(0x1234)).await;
    assert!(result.is_err());
    assert!(
        result.unwrap_err().to_string().contains("timed out"),
        "first query should time out"
    );

    // Second query with the SAME txn_id — should reconnect and succeed.
    let result = client.query(&make_dns_msg(0x1234)).await;
    assert!(result.is_ok(), "second query should succeed after reconnect");
    assert_eq!(&result.unwrap()[0..2], &0x1234u16.to_be_bytes());
}

#[tokio::test]
async fn test_connection_lost_returns_error() {
    // Server that reads one query then closes the connection.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let _server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        // Read one TCP-framed query.
        let mut len_buf = [0u8; 2];
        let _ = stream.read_exact(&mut len_buf).await;
        let msg_len = u16::from_be_bytes(len_buf) as usize;
        let mut msg = vec![0u8; msg_len];
        let _ = stream.read_exact(&mut msg).await;
        // Close without responding.
        drop(stream);
    });

    let mgr: Arc<dyn ProxyHandlerManager> = Arc::new(NoProxyManager::new());
    let client = SharedDnsTcpClient::new(mgr, addr, None);

    let result = client.query(&make_dns_msg(0xAAAA)).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("closed") || err.contains("lost"),
        "expected connection-related error, got: {err}"
    );
}

#[tokio::test]
async fn test_reconnect_after_connection_drop() {
    // First server: accepts one connection, reads one query, closes.
    let listener1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener1.local_addr().unwrap();
    let _server1 = tokio::spawn(async move {
        // First connection: accept, read query, close without response.
        let (mut stream, _) = listener1.accept().await.unwrap();
        let mut len_buf = [0u8; 2];
        let _ = stream.read_exact(&mut len_buf).await;
        let msg_len = u16::from_be_bytes(len_buf) as usize;
        let mut msg = vec![0u8; msg_len];
        let _ = stream.read_exact(&mut msg).await;
        drop(stream);

        // Second connection: accept and echo.
        let (mut stream, _) = listener1.accept().await.unwrap();
        loop {
            let mut len_buf = [0u8; 2];
            if stream.read_exact(&mut len_buf).await.is_err() {
                break;
            }
            let msg_len = u16::from_be_bytes(len_buf) as usize;
            let mut msg = vec![0u8; msg_len];
            if stream.read_exact(&mut msg).await.is_err() {
                break;
            }
            let _ = stream.write_all(&len_buf).await;
            let _ = stream.write_all(&msg).await;
        }
    });

    let mgr: Arc<dyn ProxyHandlerManager> = Arc::new(NoProxyManager::new());
    let client = SharedDnsTcpClient::new(mgr, addr, None);

    // First query — connection will be dropped, should fail.
    let result = client.query(&make_dns_msg(0xBBBB)).await;
    assert!(result.is_err());

    // Second query — should reconnect and succeed.
    let result = client.query(&make_dns_msg(0xCCCC)).await;
    assert!(result.is_ok());
    assert_eq!(&result.unwrap()[0..2], &0xCCCCu16.to_be_bytes());
}
