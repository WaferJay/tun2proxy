use super::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// --- DnsCache tests (migrated from DnsMapping) ---

#[test]
fn test_insert_and_lookup() {
    let mut cache = DnsCache::new();
    let ip1 = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    let ip2 = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));
    cache.insert(
        "example.com",
        &[
            DnsRecord::A(Ipv4Addr::new(1, 2, 3, 4), 300),
            DnsRecord::A(Ipv4Addr::new(5, 6, 7, 8), 300),
        ],
    );

    assert_eq!(cache.lookup_domains(&ip1).unwrap()[0], "example.com");
    assert_eq!(cache.lookup_domains(&ip2).unwrap()[0], "example.com");
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
    let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    cache.insert("example.com.", &[DnsRecord::A(Ipv4Addr::new(1, 1, 1, 1), 300)]);

    assert_eq!(cache.lookup_domains(&ip).unwrap()[0], "example.com");
}

#[test]
fn test_insert_normalizes_case() {
    let mut cache = DnsCache::new();
    let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    cache.insert("Example.COM", &[DnsRecord::A(Ipv4Addr::new(1, 1, 1, 1), 300)]);

    assert_eq!(cache.lookup_domains(&ip).unwrap()[0], "example.com");
}

#[test]
fn test_insert_multiple_domains_same_ip() {
    let mut cache = DnsCache::new();
    let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

    cache.insert("old.com", &[DnsRecord::A(Ipv4Addr::new(1, 2, 3, 4), 300)]);
    cache.insert("new.com", &[DnsRecord::A(Ipv4Addr::new(1, 2, 3, 4), 300)]);

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
    cache.insert(
        "v6.example.com",
        &[DnsRecord::AAAA(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 300)],
    );

    assert_eq!(cache.lookup_domains(&ip).unwrap()[0], "v6.example.com");
}

// --- Forward lookup (lookup_ips) tests ---

#[test]
fn test_lookup_ips_basic() {
    let mut cache = DnsCache::new();
    let ip1 = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    let ip2 = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));
    cache.insert(
        "example.com",
        &[
            DnsRecord::A(Ipv4Addr::new(1, 2, 3, 4), 300),
            DnsRecord::A(Ipv4Addr::new(5, 6, 7, 8), 300),
        ],
    );

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
    cache.insert("Example.COM.", &[DnsRecord::A(Ipv4Addr::new(1, 1, 1, 1), 300)]);

    assert!(cache.lookup_ips("example.com").is_some());
    assert!(cache.lookup_ips("Example.COM.").is_some());
}

// --- TTL tests ---

#[test]
fn test_insert_with_ttl() {
    let mut cache = DnsCache::new();
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    // Insert with a 60-second TTL (within [10, 3600] range)
    cache.insert("example.com", &[DnsRecord::A(Ipv4Addr::new(10, 0, 0, 1), 60)]);

    assert!(cache.lookup_ips("example.com").is_some());
    assert!(cache.lookup_domains(&ip).is_some());
}

#[test]
fn test_insert_with_different_ttls() {
    let mut cache = DnsCache::new();
    // Different TTLs for different IPs
    cache.insert(
        "example.com",
        &[
            DnsRecord::A(Ipv4Addr::new(10, 0, 0, 1), 30),
            DnsRecord::A(Ipv4Addr::new(10, 0, 0, 2), 600),
        ],
    );

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
    cache.insert("example.com", &[DnsRecord::A(Ipv4Addr::new(1, 2, 3, 4), 300)]);

    cache.evict_expired();

    assert!(cache.lookup_ips("example.com").is_some());
    assert!(cache.lookup_domains(&ip).is_some());
}

// --- BypassMatcher tests (migrated from should_bypass) ---

#[test]
fn test_bypass_exact_match() {
    let list = vec!["google.com".to_string()];
    let matcher = BypassMatcher::try_from(&list).unwrap();
    assert!(matcher.matches("google.com", 80));
}

#[test]
fn test_bypass_subdomain() {
    let list = vec!["google.com".to_string()];
    let matcher = BypassMatcher::try_from(&list).unwrap();
    assert!(!matcher.matches("www.google.com", 0));
    assert!(!matcher.matches("mail.google.com", 80));
    assert!(!matcher.matches("a.b.c.google.com", 443));
}

#[test]
fn test_bypass_no_partial_match() {
    let list = vec!["google.com".to_string()];
    let matcher = BypassMatcher::try_from(&list).unwrap();
    // "notgoogle.com" ends with "google.com" but is not a subdomain
    assert!(!matcher.matches("notgoogle.com", 80));
}

#[test]
fn test_bypass_case_insensitive() {
    let list = vec!["Google.COM".to_string()];
    let matcher = BypassMatcher::try_from(&list).unwrap();
    assert!(matcher.matches("GOOGLE.COM", 443));
    assert!(matcher.matches("google.com", 443));
}

#[test]
fn test_bypass_trailing_dot() {
    let list = vec!["google.com".to_string()];
    let matcher = BypassMatcher::try_from(&list).unwrap();
    assert!(matcher.matches("google.com.", 443));
}

#[test]
fn test_bypass_pattern_with_leading_dot() {
    let list = vec![".google.com".to_string()];
    let matcher = BypassMatcher::try_from(&list).unwrap();
    assert!(matcher.matches("google.com", 443));
}

#[test]
fn test_bypass_empty_list() {
    let list: Vec<String> = vec![];
    let matcher = BypassMatcher::try_from(&list).unwrap();
    assert!(!matcher.matches("google.com", 443));
    assert!(matcher.is_empty());
}

#[test]
fn test_bypass_multiple_patterns() {
    let list = vec!["www.google.com".to_string(), "github.com".to_string()];
    let matcher = BypassMatcher::try_from(&list).unwrap();
    assert!(matcher.matches("www.google.com", 443));
    assert!(matcher.matches("github.com", 443));
    assert!(!matcher.matches("example.com", 443));
}

// --- Wildcard pattern tests ---

#[test]
fn test_wildcard_star_google_com() {
    let list = vec!["*.google.com".to_string()];
    let matcher = BypassMatcher::try_from(&list).unwrap();
    assert!(matcher.matches("www.google.com", 443));
    assert!(matcher.matches("a.b.google.com", 443));
    assert!(!matcher.matches("google.org", 443));
}

#[test]
fn test_wildcard_star_matches_everything() {
    let list = vec!["*".to_string()];
    let matcher = BypassMatcher::try_from(&list).unwrap();
    assert!(matcher.matches("anything.example.com", 443));
    assert!(matcher.matches("google.com", 443));
    assert!(matcher.matches("x", 443));
}

#[test]
fn test_wildcard_google_star() {
    let list = vec!["google.*".to_string()];
    let matcher = BypassMatcher::try_from(&list).unwrap();
    assert!(matcher.matches("google.com", 443));
    assert!(matcher.matches("google.org", 443));
    assert!(!matcher.matches("www.google.com", 443));
}

#[test]
fn test_wildcard_star_google_star() {
    let list = vec!["*google*".to_string()];
    let matcher = BypassMatcher::try_from(&list).unwrap();
    assert!(matcher.matches("www.google.com", 443));
    assert!(matcher.matches("mygoogle.org", 443));
    assert!(!matcher.matches("example.com", 443));
}

#[test]
fn test_wildcard_star_dot_google_dot_star() {
    let list = vec!["*.google.*".to_string()];
    let matcher = BypassMatcher::try_from(&list).unwrap();
    assert!(matcher.matches("www.google.com", 443));
    assert!(matcher.matches("mail.google.org", 443));
    assert!(!matcher.matches("example.com", 443));
}

#[test]
fn test_wildcard_case_insensitive() {
    let list = vec!["*.Google.COM".to_string()];
    let matcher = BypassMatcher::try_from(&list).unwrap();
    assert!(matcher.matches("www.google.com", 443));
    assert!(matcher.matches("WWW.GOOGLE.COM", 443));
}

// --- Edge case tests ---

#[test]
fn test_wildcard_question_mark() {
    let list = vec!["google.co?".to_string()];
    let matcher = BypassMatcher::try_from(&list).unwrap();
    assert!(matcher.matches("google.com", 443));
    assert!(matcher.matches("google.cob", 443));
    assert!(!matcher.matches("google.com.au", 443));
    assert!(!matcher.matches("google.co", 443));
}

#[test]
fn test_wildcard_star_does_not_match_bare_domain() {
    // *.google.com requires at least one char before .google.com
    let list = vec!["*.google.com".to_string()];
    let matcher = BypassMatcher::try_from(&list).unwrap();
    assert!(matcher.matches("www.google.com", 443));
    assert!(!matcher.matches("google.com", 443));
}

#[test]
fn test_wildcard_pattern_trailing_dot_trimmed() {
    let list = vec!["*.google.com.".to_string()];
    let matcher = BypassMatcher::try_from(&list).unwrap();
    assert!(matcher.matches("www.google.com", 443));
    assert!(matcher.matches("www.google.com.", 443));
}

#[test]
fn test_mixed_suffix_and_wildcard() {
    let list = vec![
        "github.com".to_string(), // fulltext
        "api.github.com".to_string(), // fulltext
        "*.google.*".to_string(), // wildcard
    ];
    let matcher = BypassMatcher::try_from(&list).unwrap();
    // fulltext path
    assert!(matcher.matches("api.github.com", 443));
    assert!(matcher.matches("github.com", 80));
    // wildcard path
    assert!(matcher.matches("www.google.com", 443));
    assert!(matcher.matches("mail.google.org", 80));
    // neither
    assert!(!matcher.matches("example.com", 443));
}

#[test]
fn test_bypass_is_empty() {
    let non_empty = BypassMatcher::try_from(&vec!["x".to_string()]).unwrap();
    assert!(!non_empty.is_empty());

    let empty = BypassMatcher::try_from(&vec![]).unwrap();
    assert!(empty.is_empty());
}

// --- matches_all tests ---

#[test]
fn test_matches_all_all_match() {
    let matcher = BypassMatcher::try_from(&vec!["*.google.com".to_string()]).unwrap();
    assert!(matcher.matches_all(&["www.google.com", "mail.google.com"], 443));
}

#[test]
fn test_matches_all_one_mismatch() {
    let matcher = BypassMatcher::try_from(&vec!["google.com".to_string()]).unwrap();
    // "evil.org" does not match → should NOT bypass
    assert!(!matcher.matches_all(&vec!["www.google.com", "evil.org"], 443));
}

#[test]
fn test_matches_all_empty_domains() {
    let matcher = BypassMatcher::try_from(&vec!["google.com".to_string()]).unwrap();
    // No domain info → conservative, no bypass
    assert!(!matcher.matches_all(&vec![], 443));
}

#[test]
fn test_matches_all_single_domain() {
    let matcher = BypassMatcher::try_from(&vec!["example.com".to_string()]).unwrap();
    assert!(matcher.matches_all(&["example.com"], 80));
    assert!(!matcher.matches_all(&["other.com"], 443));
}

#[test]
fn test_matches_domain_port() {
    let matcher = BypassMatcher::try_from(&vec!["example.com:80".to_string()]).unwrap();
    assert!(matcher.matches_all(&["example.com"], 80));
    assert!(!matcher.matches_all(&["example.com"], 443));
    let matcher = BypassMatcher::try_from(&vec!["*.example.com:80".to_string()]).unwrap();
    assert!(matcher.matches_all(&["www.example.com"], 80));
    assert!(!matcher.matches_all(&["www.example.com"], 443));
}

// --- lookup_with_ttl tests ---

#[test]
fn test_lookup_with_ttl_basic() {
    let mut cache = DnsCache::new();
    cache.insert(
        "example.com",
        &[
            DnsRecord::A(Ipv4Addr::new(1, 2, 3, 4), 300),
            DnsRecord::A(Ipv4Addr::new(5, 6, 7, 8), 600),
        ],
    );

    let results = cache.lookup_with_ttl("example.com").unwrap();
    // Filter to A/AAAA only for count
    let ip_records: Vec<_> = results
        .iter()
        .filter(|r| matches!(r, DnsRecord::A(..) | DnsRecord::AAAA(..)))
        .collect();
    assert_eq!(ip_records.len(), 2);
    assert!(matches!(ip_records[0], DnsRecord::A(addr, _) if *addr == Ipv4Addr::new(1, 2, 3, 4)));
    assert!(matches!(ip_records[1], DnsRecord::A(addr, _) if *addr == Ipv4Addr::new(5, 6, 7, 8)));
}

#[test]
fn test_lookup_with_ttl_missing_domain() {
    let cache = DnsCache::new();
    assert!(cache.lookup_with_ttl("nonexistent.com").is_none());
}

#[test]
fn test_lookup_with_ttl_normalizes_domain() {
    let mut cache = DnsCache::new();
    cache.insert("Example.COM.", &[DnsRecord::A(Ipv4Addr::new(10, 0, 0, 1), 300)]);

    // Various forms should all resolve
    assert!(cache.lookup_with_ttl("example.com").is_some());
    assert!(cache.lookup_with_ttl("Example.COM").is_some());
    assert!(cache.lookup_with_ttl("example.com.").is_some());
}

#[test]
fn test_lookup_with_ttl_mixed_v4_v6() {
    let mut cache = DnsCache::new();
    let v4 = Ipv4Addr::new(1, 2, 3, 4);
    let v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    cache.insert("dual.example.com", &[DnsRecord::A(v4, 60), DnsRecord::AAAA(v6, 120)]);

    let results = cache.lookup_with_ttl("dual.example.com").unwrap();
    let ip_records: Vec<_> = results
        .iter()
        .filter(|r| matches!(r, DnsRecord::A(..) | DnsRecord::AAAA(..)))
        .collect();
    assert_eq!(ip_records.len(), 2);
    assert!(matches!(ip_records[0], DnsRecord::A(addr, _) if *addr == v4));
    assert!(matches!(ip_records[1], DnsRecord::AAAA(addr, _) if *addr == v6));
}

#[test]
fn test_lookup_with_ttl_returns_remaining_ttl() {
    let mut cache = DnsCache::new();
    cache.insert("example.com", &[DnsRecord::A(Ipv4Addr::new(1, 1, 1, 1), 300)]);

    let results = cache.lookup_with_ttl("example.com").unwrap();
    let a_record = results.iter().find(|r| matches!(r, DnsRecord::A(..))).unwrap();
    if let DnsRecord::A(_, ttl) = a_record {
        // The remaining TTL should be <= the original clamped TTL
        // and > 0 since we just inserted it
        assert!(*ttl > 0);
        assert!(*ttl <= 300);
    }
}

// --- CNAME-specific tests ---

#[test]
fn test_insert_with_cname() {
    let mut cache = DnsCache::new();
    cache.insert(
        "www.example.com",
        &[
            DnsRecord::Cname("www.example.com".into(), "cdn.example.com".into(), 300),
            DnsRecord::A(Ipv4Addr::new(1, 2, 3, 4), 60),
        ],
    );

    // lookup_with_ttl should return both CNAME and A records
    let results = cache.lookup_with_ttl("www.example.com").unwrap();
    assert!(results.iter().any(|r| matches!(r, DnsRecord::Cname(..))));
    assert!(results.iter().any(|r| matches!(r, DnsRecord::A(..))));
}

#[test]
fn test_lookup_ips_ignores_cname() {
    let mut cache = DnsCache::new();
    cache.insert(
        "www.example.com",
        &[
            DnsRecord::Cname("www.example.com".into(), "cdn.example.com".into(), 300),
            DnsRecord::A(Ipv4Addr::new(1, 2, 3, 4), 60),
        ],
    );

    // lookup_ips should only return IP addresses, not CNAME
    let ips = cache.lookup_ips("www.example.com").unwrap();
    assert_eq!(ips.len(), 1);
    assert_eq!(ips[0], IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
}

#[test]
fn test_reverse_lookup_includes_cname_domains() {
    let mut cache = DnsCache::new();
    cache.insert(
        "www.example.com",
        &[
            DnsRecord::Cname("www.example.com".into(), "cdn.example.com".into(), 300),
            DnsRecord::A(Ipv4Addr::new(1, 2, 3, 4), 60),
        ],
    );

    // Reverse lookup should include the query domain (www.example.com)
    let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    let domains = cache.lookup_domains(&ip).unwrap();
    assert!(domains.contains(&"www.example.com"));
}

#[test]
fn test_reverse_lookup_includes_distinct_cname_from_domain() {
    let mut cache = DnsCache::new();
    // Simulate a case where CNAME from is different from the query domain
    // (e.g., a multi-level CNAME chain stored under the original query domain)
    cache.insert(
        "app.example.com",
        &[
            DnsRecord::Cname("app.example.com".into(), "lb.example.com".into(), 300),
            DnsRecord::Cname("lb.example.com".into(), "cdn.example.com".into(), 300),
            DnsRecord::A(Ipv4Addr::new(10, 0, 0, 1), 60),
        ],
    );

    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let domains = cache.lookup_domains(&ip).unwrap();
    // Should include the query domain and both CNAME from domains
    assert!(domains.contains(&"app.example.com"));
    assert!(domains.contains(&"lb.example.com"));
}

#[test]
fn test_evict_expired_with_cname() {
    let mut cache = DnsCache::new();
    cache.insert(
        "www.example.com",
        &[
            DnsRecord::Cname("www.example.com".into(), "cdn.example.com".into(), 300),
            DnsRecord::A(Ipv4Addr::new(1, 2, 3, 4), 300),
        ],
    );

    // Before eviction, everything should be present
    assert!(cache.lookup_with_ttl("www.example.com").is_some());

    // Evict — nothing expired yet, should keep entries
    cache.evict_expired();
    assert!(cache.lookup_with_ttl("www.example.com").is_some());
}

#[test]
fn test_lookup_with_ttl_cname_only_returns_none() {
    let mut cache = DnsCache::new();
    // Insert only a CNAME without any A/AAAA record
    cache.insert(
        "alias.example.com",
        &[DnsRecord::Cname("alias.example.com".into(), "target.example.com".into(), 300)],
    );

    // CNAME alone is useless — should return None
    assert!(cache.lookup_with_ttl("alias.example.com").is_none());
}

#[test]
fn test_bypass_requires_cname_domain_match() {
    let mut cache = DnsCache::new();
    // www.example.com CNAME cdn.otherdomain.com, A 1.2.3.4
    cache.insert(
        "www.example.com",
        &[
            DnsRecord::Cname("www.example.com".into(), "cdn.otherdomain.com".into(), 300),
            DnsRecord::A(Ipv4Addr::new(1, 2, 3, 4), 60),
        ],
    );

    // Bypass matcher only matches example.com
    let matcher = BypassMatcher::try_from(&vec!["www.example.com".to_string()]).unwrap();
    let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    let domains = cache.lookup_domains(&ip).unwrap();

    // www.example.com matches, but if cdn.otherdomain.com were also in the
    // reverse map, matches_all would fail. In this implementation, only the
    // query domain and CNAME from domains are added (not CNAME targets),
    // so "www.example.com" is the only domain → bypass succeeds.
    assert!(matcher.matches_all(&domains, 80));
}

#[test]
fn test_bypass_fails_when_cname_from_doesnt_match() {
    let mut cache = DnsCache::new();
    // Simulate: the CNAME from domain is different and doesn't match bypass rules
    cache.insert(
        "evil.org",
        &[
            DnsRecord::Cname("evil.org".into(), "cdn.example.com".into(), 300),
            DnsRecord::A(Ipv4Addr::new(1, 2, 3, 4), 60),
        ],
    );

    // Bypass matcher only matches example.com
    let matcher = BypassMatcher::try_from(&vec!["example.com".to_string()]).unwrap();
    let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    let domains = cache.lookup_domains(&ip).unwrap();

    // "evil.org" is a domain associated with this IP → does not match → no bypass
    assert!(!matcher.matches_all(&domains, 443));
}

// --- Split-response CNAME chain tests ---

#[test]
fn test_cname_chain_split_responses_lookup_with_ttl() {
    let mut cache = DnsCache::new();

    // Response 1: m.baidu.com CNAME wap.n.shifen.com (no A record)
    cache.insert(
        "m.baidu.com",
        &[DnsRecord::Cname("m.baidu.com".into(), "wap.n.shifen.com".into(), 300)],
    );

    // At this point, lookup should fail — no A record anywhere in the chain
    assert!(cache.lookup_with_ttl("m.baidu.com").is_none());

    // Response 2: wap.n.shifen.com A 1.2.3.4
    cache.insert("wap.n.shifen.com", &[DnsRecord::A(Ipv4Addr::new(1, 2, 3, 4), 60)]);

    // Now lookup_with_ttl should follow the chain and return CNAME + A
    let results = cache.lookup_with_ttl("m.baidu.com").unwrap();
    assert!(
        results
            .iter()
            .any(|r| matches!(r, DnsRecord::Cname(from, to, _) if from == "m.baidu.com" && to == "wap.n.shifen.com"))
    );
    assert!(
        results
            .iter()
            .any(|r| matches!(r, DnsRecord::A(addr, _) if *addr == Ipv4Addr::new(1, 2, 3, 4)))
    );
}

#[test]
fn test_cname_chain_split_responses_lookup_ips() {
    let mut cache = DnsCache::new();

    cache.insert(
        "m.baidu.com",
        &[DnsRecord::Cname("m.baidu.com".into(), "wap.n.shifen.com".into(), 300)],
    );
    assert!(cache.lookup_ips("m.baidu.com").is_none());

    cache.insert("wap.n.shifen.com", &[DnsRecord::A(Ipv4Addr::new(1, 2, 3, 4), 60)]);

    let ips = cache.lookup_ips("m.baidu.com").unwrap();
    assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);
}

#[test]
fn test_cname_chain_split_responses_reverse_map() {
    let mut cache = DnsCache::new();

    // Insert CNAME first
    cache.insert(
        "m.baidu.com",
        &[DnsRecord::Cname("m.baidu.com".into(), "wap.n.shifen.com".into(), 300)],
    );

    // Insert A record for target — reverse map should include m.baidu.com
    cache.insert("wap.n.shifen.com", &[DnsRecord::A(Ipv4Addr::new(1, 2, 3, 4), 60)]);

    let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    let domains = cache.lookup_domains(&ip).unwrap();
    assert!(domains.contains(&"wap.n.shifen.com"));
    assert!(domains.contains(&"m.baidu.com"));
}

#[test]
fn test_cname_chain_multi_level_split() {
    let mut cache = DnsCache::new();

    // a.com CNAME b.com
    cache.insert("a.com", &[DnsRecord::Cname("a.com".into(), "b.com".into(), 300)]);
    // b.com CNAME c.com
    cache.insert("b.com", &[DnsRecord::Cname("b.com".into(), "c.com".into(), 300)]);
    // c.com A 10.0.0.1
    cache.insert("c.com", &[DnsRecord::A(Ipv4Addr::new(10, 0, 0, 1), 60)]);

    // lookup_with_ttl("a.com") should follow: a.com -> b.com -> c.com -> A
    let results = cache.lookup_with_ttl("a.com").unwrap();
    let cnames: Vec<_> = results.iter().filter(|r| matches!(r, DnsRecord::Cname(..))).collect();
    let ips: Vec<_> = results.iter().filter(|r| matches!(r, DnsRecord::A(..))).collect();
    assert_eq!(cnames.len(), 2);
    assert_eq!(ips.len(), 1);

    // lookup_ips should also work
    let ips = cache.lookup_ips("a.com").unwrap();
    assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))]);
}
