use super::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[test]
fn test_insert_and_lookup() {
    let mut mapping = DnsMapping::new();
    let ips = vec![
        IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
    ];
    mapping.insert("example.com", &ips);

    assert_eq!(mapping.lookup(&ips[0]), Some("example.com"));
    assert_eq!(mapping.lookup(&ips[1]), Some("example.com"));
}

#[test]
fn test_lookup_missing() {
    let mapping = DnsMapping::new();
    let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    assert_eq!(mapping.lookup(&ip), None);
}

#[test]
fn test_insert_normalizes_trailing_dot() {
    let mut mapping = DnsMapping::new();
    let ips = vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))];
    mapping.insert("example.com.", &ips);

    assert_eq!(mapping.lookup(&ips[0]), Some("example.com"));
}

#[test]
fn test_insert_normalizes_case() {
    let mut mapping = DnsMapping::new();
    let ips = vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))];
    mapping.insert("Example.COM", &ips);

    assert_eq!(mapping.lookup(&ips[0]), Some("example.com"));
}

#[test]
fn test_insert_overwrites() {
    let mut mapping = DnsMapping::new();
    let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

    mapping.insert("old.com", &[ip]);
    assert_eq!(mapping.lookup(&ip), Some("old.com"));

    mapping.insert("new.com", &[ip]);
    assert_eq!(mapping.lookup(&ip), Some("new.com"));
}

#[test]
fn test_insert_ipv6() {
    let mut mapping = DnsMapping::new();
    let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    mapping.insert("v6.example.com", &[ip]);

    assert_eq!(mapping.lookup(&ip), Some("v6.example.com"));
}

#[test]
fn test_should_bypass_exact_match() {
    let list = vec!["google.com".to_string()];
    assert!(DnsMapping::should_bypass("google.com", &list));
}

#[test]
fn test_should_bypass_subdomain() {
    let list = vec!["google.com".to_string()];
    assert!(DnsMapping::should_bypass("www.google.com", &list));
    assert!(DnsMapping::should_bypass("mail.google.com", &list));
    assert!(DnsMapping::should_bypass("a.b.c.google.com", &list));
}

#[test]
fn test_should_bypass_no_partial_match() {
    let list = vec!["google.com".to_string()];
    // "notgoogle.com" ends with "google.com" but is not a subdomain
    assert!(!DnsMapping::should_bypass("notgoogle.com", &list));
}

#[test]
fn test_should_bypass_case_insensitive() {
    let list = vec!["Google.COM".to_string()];
    assert!(DnsMapping::should_bypass("WWW.GOOGLE.COM", &list));
    assert!(DnsMapping::should_bypass("www.google.com", &list));
}

#[test]
fn test_should_bypass_trailing_dot() {
    let list = vec!["google.com".to_string()];
    assert!(DnsMapping::should_bypass("google.com.", &list));
    assert!(DnsMapping::should_bypass("www.google.com.", &list));
}

#[test]
fn test_should_bypass_pattern_with_leading_dot() {
    let list = vec![".google.com".to_string()];
    assert!(DnsMapping::should_bypass("www.google.com", &list));
    assert!(DnsMapping::should_bypass("google.com", &list));
}

#[test]
fn test_should_bypass_empty_list() {
    let list: Vec<String> = vec![];
    assert!(!DnsMapping::should_bypass("google.com", &list));
}

#[test]
fn test_should_bypass_multiple_patterns() {
    let list = vec!["google.com".to_string(), "github.com".to_string()];
    assert!(DnsMapping::should_bypass("www.google.com", &list));
    assert!(DnsMapping::should_bypass("api.github.com", &list));
    assert!(!DnsMapping::should_bypass("example.com", &list));
}
