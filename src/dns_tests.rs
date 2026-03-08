use super::*;
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query},
    rr::{Name, RData, Record, RecordType, rdata::{A, AAAA}},
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

#[test]
fn test_extract_all_ipaddrs_multiple_a_records() {
    let ip1 = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    let ip2 = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));
    let msg = build_test_response("example.com", &[ip1, ip2]);

    let ips = extract_all_ipaddrs_from_dns_message(&msg);
    assert_eq!(ips.len(), 2);
    assert!(ips.contains(&ip1));
    assert!(ips.contains(&ip2));
}

#[test]
fn test_extract_all_ipaddrs_mixed_a_and_aaaa() {
    let v4 = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    let msg = build_test_response("example.com", &[v4, v6]);

    let ips = extract_all_ipaddrs_from_dns_message(&msg);
    assert_eq!(ips.len(), 2);
    assert!(ips.contains(&v4));
    assert!(ips.contains(&v6));
}

#[test]
fn test_extract_all_ipaddrs_empty_response() {
    let msg = build_test_response("example.com", &[]);
    let ips = extract_all_ipaddrs_from_dns_message(&msg);
    assert!(ips.is_empty());
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

    let ips = extract_all_ipaddrs_from_dns_message(&msg);
    assert_eq!(ips, vec![v4]);
}

#[test]
fn test_parse_data_roundtrip() {
    let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    let original = build_test_response("test.example.com", &[ip]);
    let bytes = original.to_vec().unwrap();
    let parsed = parse_data_to_dns_message(&bytes, false).unwrap();

    assert_eq!(parsed.id(), original.id());
    let ips = extract_all_ipaddrs_from_dns_message(&parsed);
    assert_eq!(ips, vec![ip]);
}
