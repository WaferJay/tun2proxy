use super::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// --- DnsCache tests (migrated from DnsMapping) ---

#[test]
fn test_insert_and_lookup() {
    let mut cache = DnsCache::new();
    let ips = vec![
        IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
    ];
    cache.insert_with_default_ttl("example.com", &ips);

    assert_eq!(cache.lookup_domains(&ips[0]).unwrap()[0], "example.com");
    assert_eq!(cache.lookup_domains(&ips[1]).unwrap()[0], "example.com");
}

#[test]
fn test_lookup_missing() {
    let cache = DnsCache::new();
    let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    assert!(cache.lookup_domains(&ip).is_none());
}

#[test]
fn test_insert_normalizes_trailing_dot() {
    let mut cache = DnsCache::new();
    let ips = vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))];
    cache.insert_with_default_ttl("example.com.", &ips);

    assert_eq!(cache.lookup_domains(&ips[0]).unwrap()[0], "example.com");
}

#[test]
fn test_insert_normalizes_case() {
    let mut cache = DnsCache::new();
    let ips = vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))];
    cache.insert_with_default_ttl("Example.COM", &ips);

    assert_eq!(cache.lookup_domains(&ips[0]).unwrap()[0], "example.com");
}

#[test]
fn test_insert_multiple_domains_same_ip() {
    let mut cache = DnsCache::new();
    let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

    cache.insert_with_default_ttl("old.com", &[ip]);
    cache.insert_with_default_ttl("new.com", &[ip]);

    // Both domains should be visible, newest first
    let domains = cache.lookup_domains(&ip).unwrap();
    assert_eq!(domains.len(), 2);
    assert_eq!(domains[0], "new.com");
    assert_eq!(domains[1], "old.com");
}

#[test]
fn test_insert_ipv6() {
    let mut cache = DnsCache::new();
    let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    cache.insert_with_default_ttl("v6.example.com", &[ip]);

    assert_eq!(cache.lookup_domains(&ip).unwrap()[0], "v6.example.com");
}

// --- Forward lookup (lookup_ips) tests ---

#[test]
fn test_lookup_ips_basic() {
    let mut cache = DnsCache::new();
    let ip1 = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    let ip2 = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));
    cache.insert_with_default_ttl("example.com", &[ip1, ip2]);

    let ips = cache.lookup_ips("example.com").unwrap();
    assert_eq!(ips.len(), 2);
    assert!(ips.contains(&ip1));
    assert!(ips.contains(&ip2));
}

#[test]
fn test_lookup_ips_missing() {
    let cache = DnsCache::new();
    assert!(cache.lookup_ips("nonexistent.com").is_none());
}

#[test]
fn test_lookup_ips_normalizes_domain() {
    let mut cache = DnsCache::new();
    let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    cache.insert_with_default_ttl("Example.COM.", &[ip]);

    assert!(cache.lookup_ips("example.com").is_some());
    assert!(cache.lookup_ips("Example.COM.").is_some());
}

// --- TTL tests ---

#[test]
fn test_insert_with_ttl() {
    let mut cache = DnsCache::new();
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    // Insert with a 60-second TTL (within [10, 3600] range)
    cache.insert("example.com", &[(ip, 60)]);

    assert!(cache.lookup_ips("example.com").is_some());
    assert!(cache.lookup_domains(&ip).is_some());
}

#[test]
fn test_insert_with_different_ttls() {
    let mut cache = DnsCache::new();
    let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    // Different TTLs for different IPs
    cache.insert("example.com", &[(ip1, 30), (ip2, 600)]);

    let ips = cache.lookup_ips("example.com").unwrap();
    assert_eq!(ips.len(), 2);
}

#[test]
fn test_ttl_clamping() {
    // TTL below MIN_TTL (10s) should be clamped up
    let duration = clamp_ttl(1);
    assert_eq!(duration, MIN_TTL);

    // TTL above MAX_TTL (3600s) should be clamped down
    let duration = clamp_ttl(99999);
    assert_eq!(duration, MAX_TTL);

    // TTL within range should be preserved
    let duration = clamp_ttl(120);
    assert_eq!(duration, std::time::Duration::from_secs(120));
}

// --- Eviction tests ---

#[test]
fn test_evict_expired_no_crash_on_empty() {
    let mut cache = DnsCache::new();
    cache.evict_expired(); // Should not panic
}

#[test]
fn test_evict_expired_keeps_valid_entries() {
    let mut cache = DnsCache::new();
    let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    cache.insert("example.com", &[(ip, 300)]);

    cache.evict_expired();

    assert!(cache.lookup_ips("example.com").is_some());
    assert!(cache.lookup_domains(&ip).is_some());
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
