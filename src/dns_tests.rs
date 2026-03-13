use super::*;
use crate::dns_mapping::DnsRecord;
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query},
    rr::{
        Name, RData, Record, RecordType,
        rdata::{A, AAAA, CNAME},
    },
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

fn build_test_response(domain: &str, ips: &[IpAddr]) -> Message {
    let name = Name::from_str(domain).unwrap();
    let query = Query::query(name.clone(), RecordType::A);
    let mut msg = Message::new();
    msg.set_id(1234);
    msg.set_message_type(MessageType::Response);
    msg.add_query(query);
    for ip in ips {
        let record = match ip {
            IpAddr::V4(v4) => Record::from_rdata(name.clone(), 300, RData::A(A(*v4))),
            IpAddr::V6(v6) => Record::from_rdata(name.clone(), 300, RData::AAAA(AAAA(*v6))),
        };
        msg.add_answer(record);
    }
    msg
}

// ── Wire format tests (RFC 1035) ────────────────────────────────────

/// Verify build_dns_query produces bytes that conform to DNS wire format:
///
///   Header (12 bytes):
///     ID      (2)  – matches requested id
///     Flags   (2)  – QR=0 (query), OPCODE=0 (standard), RD=1
///     QDCOUNT (2)  – 1
///     ANCOUNT (2)  – 0
///     NSCOUNT (2)  – 0
///     ARCOUNT (2)  – 0 (or 1 if EDNS OPT present)
///
///   Question section:
///     QNAME        – length-prefixed labels, e.g. \x07example\x03com\x00
///     QTYPE   (2)  – 0x0001 (A)
///     QCLASS  (2)  – 0x0001 (IN)
#[test]
fn test_query_wire_format_header() {
    let bytes = build_dns_query("example.com", 0xBEEF).unwrap();
    assert!(bytes.len() >= 12, "DNS message must have at least 12-byte header");

    // ID
    assert_eq!(bytes[0], 0xBE);
    assert_eq!(bytes[1], 0xEF);

    // Flags: QR=0, OPCODE=0000, AA=0, TC=0, RD=1 → byte 2 = 0b0000_0001 = 0x01
    let qr = (bytes[2] >> 7) & 1;
    assert_eq!(qr, 0, "QR must be 0 for query");
    let opcode = (bytes[2] >> 3) & 0xF;
    assert_eq!(opcode, 0, "OPCODE must be 0 (standard query)");
    let rd = bytes[2] & 1;
    assert_eq!(rd, 1, "RD (recursion desired) must be 1");

    // QDCOUNT = 1
    let qdcount = u16::from_be_bytes([bytes[4], bytes[5]]);
    assert_eq!(qdcount, 1, "QDCOUNT must be 1");

    // ANCOUNT = 0
    let ancount = u16::from_be_bytes([bytes[6], bytes[7]]);
    assert_eq!(ancount, 0, "ANCOUNT must be 0 for query");

    // NSCOUNT = 0
    let nscount = u16::from_be_bytes([bytes[8], bytes[9]]);
    assert_eq!(nscount, 0, "NSCOUNT must be 0 for query");
}

/// Verify the question section encodes domain labels correctly per RFC 1035 §4.1.2:
///   "example.com" → \x07example\x03com\x00
#[test]
fn test_query_wire_format_question_section() {
    let bytes = build_dns_query("example.com", 0x1234).unwrap();

    // Question section starts at offset 12
    // QNAME for "example.com": 7 e x a m p l e 3 c o m 0
    let expected_qname: &[u8] = &[
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, // root label terminator
    ];
    let qname_start = 12;
    let qname_end = qname_start + expected_qname.len();
    assert!(bytes.len() >= qname_end + 4, "message too short for question section");
    assert_eq!(&bytes[qname_start..qname_end], expected_qname, "QNAME encoding mismatch");

    // QTYPE = A (0x0001) immediately after QNAME
    let qtype = u16::from_be_bytes([bytes[qname_end], bytes[qname_end + 1]]);
    assert_eq!(qtype, 1, "QTYPE must be 1 (A record)");

    // QCLASS = IN (0x0001)
    let qclass = u16::from_be_bytes([bytes[qname_end + 2], bytes[qname_end + 3]]);
    assert_eq!(qclass, 1, "QCLASS must be 1 (IN)");
}

/// Verify multi-level domain labels encode correctly
#[test]
fn test_query_wire_format_multi_level_domain() {
    let bytes = build_dns_query("a.b.example.com", 0x0001).unwrap();

    // QNAME: 1 a 1 b 7 example 3 com 0
    let expected_qname: &[u8] = &[
        1, b'a', 1, b'b', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
    ];
    assert_eq!(
        &bytes[12..12 + expected_qname.len()],
        expected_qname,
        "multi-level QNAME encoding mismatch"
    );
}

/// Verify response wire format: QR=1, answer section contains correct A record
#[test]
fn test_response_wire_format_header_and_answer() {
    let ip = Ipv4Addr::new(93, 184, 216, 34);
    let query_bytes = build_dns_query("example.com", 0x5678).unwrap();
    let query_msg = parse_data_to_dns_message(&query_bytes, false).unwrap();

    let resp_msg = build_dns_response(query_msg, "example.com", IpAddr::V4(ip), 300).unwrap();
    let resp_bytes = resp_msg.to_vec().unwrap();

    // ID preserved
    assert_eq!(resp_bytes[0], 0x56);
    assert_eq!(resp_bytes[1], 0x78);

    // QR=1 (response)
    let qr = (resp_bytes[2] >> 7) & 1;
    assert_eq!(qr, 1, "QR must be 1 for response");

    // ANCOUNT >= 1
    let ancount = u16::from_be_bytes([resp_bytes[6], resp_bytes[7]]);
    assert!(ancount >= 1, "ANCOUNT must be >= 1 for response with answer");

    // Parse back and verify IP
    let parsed = parse_data_to_dns_message(&resp_bytes, false).unwrap();
    let extracted_ip = extract_ipaddr_from_dns_message(&parsed).unwrap();
    assert_eq!(extracted_ip, IpAddr::V4(ip));
}

/// Simulate the full DNS flow: build query → build response → parse → extract
/// This mirrors what handle_direct_dns_session does end-to-end
#[test]
fn test_full_dns_flow_simulation() {
    let domain = "www.github.com";
    let server_ip = Ipv4Addr::new(140, 82, 121, 4);

    // 1. Client builds query
    let query_bytes = build_dns_query(domain, 0x9999).unwrap();

    // 2. "Server" parses query and builds response
    let query_msg = parse_data_to_dns_message(&query_bytes, false).unwrap();
    let query_domain = extract_domain_from_dns_message(&query_msg).unwrap();
    assert!(query_domain.trim_end_matches('.') == domain);

    let resp_msg = build_dns_response(query_msg, domain, IpAddr::V4(server_ip), 60).unwrap();
    let resp_bytes = resp_msg.to_vec().unwrap();

    // 3. Client parses response (same as tun2proxy snooping)
    let parsed = parse_data_to_dns_message(&resp_bytes, false).unwrap();
    let name = extract_domain_from_dns_message(&parsed).unwrap();
    let pairs = extract_ip_ttl_pairs(&parsed);

    assert!(name.trim_end_matches('.') == domain);
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].0, IpAddr::V4(server_ip));
}

/// Verify DNS-over-TCP framing: 2-byte length prefix + message
#[test]
fn test_dns_over_tcp_framing() {
    let query_bytes = build_dns_query("example.com", 0xAAAA).unwrap();

    // Wrap in TCP framing
    let len = query_bytes.len() as u16;
    let mut tcp_frame = Vec::new();
    tcp_frame.extend_from_slice(&len.to_be_bytes());
    tcp_frame.extend_from_slice(&query_bytes);

    // Parse with used_by_tcp=true
    let parsed = parse_data_to_dns_message(&tcp_frame, true).unwrap();
    assert_eq!(parsed.id(), 0xAAAA);
    assert_eq!(parsed.queries().len(), 1);
}

fn build_test_response_with_ttls(domain: &str, entries: &[(IpAddr, u32)]) -> Message {
    let name = Name::from_str(domain).unwrap();
    let query = Query::query(name.clone(), RecordType::A);
    let mut msg = Message::new();
    msg.set_id(1234);
    msg.set_message_type(MessageType::Response);
    msg.add_query(query);
    for (ip, ttl) in entries {
        let record = match ip {
            IpAddr::V4(v4) => Record::from_rdata(name.clone(), *ttl, RData::A(A(*v4))),
            IpAddr::V6(v6) => Record::from_rdata(name.clone(), *ttl, RData::AAAA(AAAA(*v6))),
        };
        msg.add_answer(record);
    }
    msg
}

/// Test helper: extract (IP, TTL) pairs from a DNS response message's answer section.
fn extract_ip_ttl_pairs(message: &Message) -> Vec<(IpAddr, u32)> {
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

#[test]
fn test_extract_single_ipaddr() {
    let ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
    let msg = build_test_response("example.com", &[ip]);

    let result = extract_ipaddr_from_dns_message(&msg).unwrap();
    assert_eq!(result, ip);
}

#[test]
fn test_extract_domain() {
    let msg = build_test_response("www.example.com", &[IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);
    let domain = extract_domain_from_dns_message(&msg).unwrap();
    // hickory_proto Name::to_string() includes trailing dot
    assert!(domain == "www.example.com." || domain == "www.example.com");
}

#[test]
fn test_build_dns_query_roundtrip() {
    let bytes = build_dns_query("example.com", 0xABCD).unwrap();
    let msg = parse_data_to_dns_message(&bytes, false).unwrap();

    assert_eq!(msg.id(), 0xABCD);
    assert_eq!(msg.message_type(), MessageType::Query);
    assert_eq!(msg.op_code(), OpCode::Query);
    assert!(msg.recursion_desired());
    assert_eq!(msg.queries().len(), 1);

    let query = &msg.queries()[0];
    assert_eq!(query.name().to_string(), "example.com.");
    assert_eq!(query.query_type(), RecordType::A);
}

#[test]
fn test_remove_ipv6_entries_keeps_v4() {
    let v4 = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    let mut msg = build_test_response("example.com", &[v4, v6]);

    assert_eq!(msg.answers().len(), 2);
    remove_ipv6_entries(&mut msg);
    assert_eq!(msg.answers().len(), 1);

    let pairs = extract_ip_ttl_pairs(&msg);
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].0, v4);
}

#[test]
fn test_parse_data_roundtrip() {
    let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    let original = build_test_response("test.example.com", &[ip]);
    let bytes = original.to_vec().unwrap();
    let parsed = parse_data_to_dns_message(&bytes, false).unwrap();

    assert_eq!(parsed.id(), original.id());
    let pairs = extract_ip_ttl_pairs(&parsed);
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].0, ip);
}

// ── build_dns_response_from_cache tests ─────────────────────────────

#[test]
fn test_build_dns_response_from_cache_single_v4() {
    let query_bytes = build_dns_query("example.com", 0x1111).unwrap();
    let query_msg = parse_data_to_dns_message(&query_bytes, false).unwrap();

    let records = vec![DnsRecord::A(Ipv4Addr::new(93, 184, 216, 34), 120)];
    let response = build_dns_response_from_cache(query_msg, "example.com.", &records).unwrap();

    assert_eq!(response.id(), 0x1111);
    assert_eq!(response.message_type(), MessageType::Response);
    assert_eq!(response.answers().len(), 1);

    let pairs = extract_ip_ttl_pairs(&response);
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].0, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
    assert_eq!(pairs[0].1, 120);
}

#[test]
fn test_build_dns_response_from_cache_multiple_records() {
    let query_bytes = build_dns_query("example.com", 0x2222).unwrap();
    let query_msg = parse_data_to_dns_message(&query_bytes, false).unwrap();

    let records = vec![
        DnsRecord::A(Ipv4Addr::new(1, 2, 3, 4), 60),
        DnsRecord::A(Ipv4Addr::new(5, 6, 7, 8), 300),
    ];
    let response = build_dns_response_from_cache(query_msg, "example.com.", &records).unwrap();

    assert_eq!(response.answers().len(), 2);
    let pairs = extract_ip_ttl_pairs(&response);
    assert_eq!(pairs[0], (IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 60));
    assert_eq!(pairs[1], (IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)), 300));
}

#[test]
fn test_build_dns_response_from_cache_mixed_v4_v6() {
    let query_bytes = build_dns_query("dual.example.com", 0x3333).unwrap();
    let query_msg = parse_data_to_dns_message(&query_bytes, false).unwrap();

    let v4 = Ipv4Addr::new(10, 0, 0, 1);
    let v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let records = vec![DnsRecord::A(v4, 200), DnsRecord::AAAA(v6, 400)];
    let response = build_dns_response_from_cache(query_msg, "dual.example.com.", &records).unwrap();

    assert_eq!(response.answers().len(), 2);
    let pairs = extract_ip_ttl_pairs(&response);
    assert_eq!(pairs[0].0, IpAddr::V4(v4));
    assert_eq!(pairs[1].0, IpAddr::V6(v6));
}

#[test]
fn test_build_dns_response_from_cache_empty_entries() {
    let query_bytes = build_dns_query("example.com", 0x4444).unwrap();
    let query_msg = parse_data_to_dns_message(&query_bytes, false).unwrap();

    let records: Vec<DnsRecord> = vec![];
    let response = build_dns_response_from_cache(query_msg, "example.com.", &records).unwrap();

    assert_eq!(response.message_type(), MessageType::Response);
    assert!(response.answers().is_empty());
}

#[test]
fn test_build_dns_response_from_cache_preserves_query_id() {
    let query_bytes = build_dns_query("test.com", 0xBEEF).unwrap();
    let query_msg = parse_data_to_dns_message(&query_bytes, false).unwrap();

    let records = vec![DnsRecord::A(Ipv4Addr::new(1, 1, 1, 1), 60)];
    let response = build_dns_response_from_cache(query_msg, "test.com.", &records).unwrap();

    assert_eq!(response.id(), 0xBEEF);
    // Verify it roundtrips through serialization
    let bytes = response.to_vec().unwrap();
    assert_eq!(bytes[0], 0xBE);
    assert_eq!(bytes[1], 0xEF);
}

#[test]
fn test_build_dns_response_from_cache_with_ipv6_removal() {
    let query_bytes = build_dns_query("example.com", 0x5555).unwrap();
    let query_msg = parse_data_to_dns_message(&query_bytes, false).unwrap();

    let v4 = Ipv4Addr::new(10, 0, 0, 1);
    let v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let records = vec![DnsRecord::A(v4, 200), DnsRecord::AAAA(v6, 400)];
    let mut response = build_dns_response_from_cache(query_msg, "example.com.", &records).unwrap();

    // Simulate what try_resolve_from_cache does when ipv6_enabled=false
    remove_ipv6_entries(&mut response);
    assert_eq!(response.answers().len(), 1);

    let pairs = extract_ip_ttl_pairs(&response);
    assert_eq!(pairs[0].0, IpAddr::V4(v4));
}

// ── extract_dns_records_from_message tests ──────────────────────────

fn build_test_response_with_cname(domain: &str, cname_target: &str, ips: &[(IpAddr, u32)]) -> Message {
    let name = Name::from_str(domain).unwrap();
    let target_name = Name::from_str(cname_target).unwrap();
    let query = Query::query(name.clone(), RecordType::A);
    let mut msg = Message::new();
    msg.set_id(1234);
    msg.set_message_type(MessageType::Response);
    msg.add_query(query);

    // Add CNAME record
    let cname_record = Record::from_rdata(name, 300, RData::CNAME(CNAME(target_name.clone())));
    msg.add_answer(cname_record);

    // Add A/AAAA records with CNAME target as owner
    for (ip, ttl) in ips {
        let record = match ip {
            IpAddr::V4(v4) => Record::from_rdata(target_name.clone(), *ttl, RData::A(A(*v4))),
            IpAddr::V6(v6) => Record::from_rdata(target_name.clone(), *ttl, RData::AAAA(AAAA(*v6))),
        };
        msg.add_answer(record);
    }
    msg
}

#[test]
fn test_extract_dns_records_with_cname() {
    let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    let msg = build_test_response_with_cname("www.example.com", "cdn.example.com", &[(ip, 60)]);

    let records = extract_dns_records_from_message(&msg);
    assert_eq!(records.len(), 2);

    // First record should be the CNAME
    match &records[0] {
        DnsRecord::Cname(from, to, ttl) => {
            assert!(from.trim_end_matches('.') == "www.example.com");
            assert!(to.trim_end_matches('.') == "cdn.example.com");
            assert_eq!(*ttl, 300);
        }
        _ => panic!("Expected CNAME record"),
    }

    // Second should be A
    match &records[1] {
        DnsRecord::A(addr, ttl) => {
            assert_eq!(*addr, Ipv4Addr::new(1, 2, 3, 4));
            assert_eq!(*ttl, 60);
        }
        _ => panic!("Expected A record"),
    }
}

#[test]
fn test_extract_dns_records_no_cname() {
    let ip1 = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    let ip2 = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));
    let msg = build_test_response_with_ttls("example.com", &[(ip1, 60), (ip2, 120)]);

    let records = extract_dns_records_from_message(&msg);
    assert_eq!(records.len(), 2);
    assert!(matches!(&records[0], DnsRecord::A(addr, 60) if *addr == Ipv4Addr::new(1, 2, 3, 4)));
    assert!(matches!(&records[1], DnsRecord::A(addr, 120) if *addr == Ipv4Addr::new(5, 6, 7, 8)));
}

#[test]
fn test_extract_dns_records_empty() {
    let msg = build_test_response("example.com", &[]);
    let records = extract_dns_records_from_message(&msg);
    assert!(records.is_empty());
}

#[test]
fn test_build_response_from_cache_with_cname() {
    let query_bytes = build_dns_query("www.example.com", 0x6666).unwrap();
    let query_msg = parse_data_to_dns_message(&query_bytes, false).unwrap();

    let records = vec![
        DnsRecord::Cname("www.example.com".into(), "cdn.example.com".into(), 300),
        DnsRecord::A(Ipv4Addr::new(1, 2, 3, 4), 60),
    ];
    let response = build_dns_response_from_cache(query_msg, "www.example.com.", &records).unwrap();

    assert_eq!(response.answers().len(), 2);

    // First answer should be CNAME
    let first = &response.answers()[0];
    assert!(matches!(first.data(), RData::CNAME(_)));

    // Second answer should be A with owner = cdn.example.com (CNAME target)
    let second = &response.answers()[1];
    assert!(matches!(second.data(), RData::A(_)));
    assert!(second.name().to_utf8().trim_end_matches('.') == "cdn.example.com");

    // Should still be able to extract the IP
    let ip = extract_ipaddr_from_dns_message(&response).unwrap();
    assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
}

#[test]
fn test_build_response_from_cache_without_cname_uses_domain() {
    let query_bytes = build_dns_query("example.com", 0x7777).unwrap();
    let query_msg = parse_data_to_dns_message(&query_bytes, false).unwrap();

    let records = vec![DnsRecord::A(Ipv4Addr::new(1, 2, 3, 4), 60)];
    let response = build_dns_response_from_cache(query_msg, "example.com.", &records).unwrap();

    assert_eq!(response.answers().len(), 1);
    let answer = &response.answers()[0];
    assert!(answer.name().to_utf8().trim_end_matches('.') == "example.com");
}
