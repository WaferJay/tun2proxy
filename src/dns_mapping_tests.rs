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

// --- BypassMatcher tests (migrated from should_bypass) ---

#[test]
fn test_bypass_exact_match() {
    let list = vec!["google.com".to_string()];
    let matcher = BypassMatcher::new(&list);
    assert!(matcher.matches("google.com"));
}

#[test]
fn test_bypass_subdomain() {
    let list = vec!["google.com".to_string()];
    let matcher = BypassMatcher::new(&list);
    assert!(matcher.matches("www.google.com"));
    assert!(matcher.matches("mail.google.com"));
    assert!(matcher.matches("a.b.c.google.com"));
}

#[test]
fn test_bypass_no_partial_match() {
    let list = vec!["google.com".to_string()];
    let matcher = BypassMatcher::new(&list);
    // "notgoogle.com" ends with "google.com" but is not a subdomain
    assert!(!matcher.matches("notgoogle.com"));
}

#[test]
fn test_bypass_case_insensitive() {
    let list = vec!["Google.COM".to_string()];
    let matcher = BypassMatcher::new(&list);
    assert!(matcher.matches("WWW.GOOGLE.COM"));
    assert!(matcher.matches("www.google.com"));
}

#[test]
fn test_bypass_trailing_dot() {
    let list = vec!["google.com".to_string()];
    let matcher = BypassMatcher::new(&list);
    assert!(matcher.matches("google.com."));
    assert!(matcher.matches("www.google.com."));
}

#[test]
fn test_bypass_pattern_with_leading_dot() {
    let list = vec![".google.com".to_string()];
    let matcher = BypassMatcher::new(&list);
    assert!(matcher.matches("www.google.com"));
    assert!(matcher.matches("google.com"));
}

#[test]
fn test_bypass_empty_list() {
    let list: Vec<String> = vec![];
    let matcher = BypassMatcher::new(&list);
    assert!(!matcher.matches("google.com"));
    assert!(matcher.is_empty());
}

#[test]
fn test_bypass_multiple_patterns() {
    let list = vec!["google.com".to_string(), "github.com".to_string()];
    let matcher = BypassMatcher::new(&list);
    assert!(matcher.matches("www.google.com"));
    assert!(matcher.matches("api.github.com"));
    assert!(!matcher.matches("example.com"));
}

// --- Wildcard pattern tests ---

#[test]
fn test_wildcard_star_google_com() {
    let list = vec!["*.google.com".to_string()];
    let matcher = BypassMatcher::new(&list);
    assert!(matcher.matches("www.google.com"));
    assert!(matcher.matches("a.b.google.com"));
    assert!(!matcher.matches("google.org"));
}

#[test]
fn test_wildcard_star_matches_everything() {
    let list = vec!["*".to_string()];
    let matcher = BypassMatcher::new(&list);
    assert!(matcher.matches("anything.example.com"));
    assert!(matcher.matches("google.com"));
    assert!(matcher.matches("x"));
}

#[test]
fn test_wildcard_google_star() {
    let list = vec!["google.*".to_string()];
    let matcher = BypassMatcher::new(&list);
    assert!(matcher.matches("google.com"));
    assert!(matcher.matches("google.org"));
    assert!(!matcher.matches("www.google.com"));
}

#[test]
fn test_wildcard_star_google_star() {
    let list = vec!["*google*".to_string()];
    let matcher = BypassMatcher::new(&list);
    assert!(matcher.matches("www.google.com"));
    assert!(matcher.matches("mygoogle.org"));
    assert!(!matcher.matches("example.com"));
}

#[test]
fn test_wildcard_star_dot_google_dot_star() {
    let list = vec!["*.google.*".to_string()];
    let matcher = BypassMatcher::new(&list);
    assert!(matcher.matches("www.google.com"));
    assert!(matcher.matches("mail.google.org"));
    assert!(!matcher.matches("example.com"));
}

#[test]
fn test_wildcard_case_insensitive() {
    let list = vec!["*.Google.COM".to_string()];
    let matcher = BypassMatcher::new(&list);
    assert!(matcher.matches("www.google.com"));
    assert!(matcher.matches("WWW.GOOGLE.COM"));
}

// --- Edge case tests ---

#[test]
fn test_wildcard_question_mark() {
    let list = vec!["google.co?".to_string()];
    let matcher = BypassMatcher::new(&list);
    assert!(matcher.matches("google.com"));
    assert!(matcher.matches("google.cob"));
    assert!(!matcher.matches("google.com.au"));
    assert!(!matcher.matches("google.co"));
}

#[test]
fn test_wildcard_star_does_not_match_bare_domain() {
    // *.google.com requires at least one char before .google.com
    let list = vec!["*.google.com".to_string()];
    let matcher = BypassMatcher::new(&list);
    assert!(matcher.matches("www.google.com"));
    assert!(!matcher.matches("google.com"));
}

#[test]
fn test_wildcard_pattern_trailing_dot_trimmed() {
    let list = vec!["*.google.com.".to_string()];
    let matcher = BypassMatcher::new(&list);
    assert!(matcher.matches("www.google.com"));
    assert!(matcher.matches("www.google.com."));
}

#[test]
fn test_mixed_suffix_and_wildcard() {
    let list = vec![
        "github.com".to_string(),    // suffix
        "*.google.*".to_string(),    // wildcard
    ];
    let matcher = BypassMatcher::new(&list);
    // suffix path
    assert!(matcher.matches("api.github.com"));
    assert!(matcher.matches("github.com"));
    // wildcard path
    assert!(matcher.matches("www.google.com"));
    assert!(matcher.matches("mail.google.org"));
    // neither
    assert!(!matcher.matches("example.com"));
}

#[test]
fn test_bypass_is_empty() {
    let non_empty = BypassMatcher::new(&vec!["x".to_string()]);
    assert!(!non_empty.is_empty());

    let empty = BypassMatcher::new(&vec![]);
    assert!(empty.is_empty());
}
