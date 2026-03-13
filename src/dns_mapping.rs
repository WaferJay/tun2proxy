use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;
use wildmatch::WildMatch;

pub const MIN_TTL: Duration = Duration::from_secs(10);
const MAX_TTL: Duration = Duration::from_secs(3600);

/// DNS record type with TTL, used as input/output for the cache.
#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::upper_case_acronyms)]
pub enum DnsRecord {
    A(Ipv4Addr, u32),
    AAAA(Ipv6Addr, u32),
    /// CNAME record: (from, to, ttl)
    Cname(String, String, u32),
}

#[derive(Debug, Clone)]
#[allow(clippy::upper_case_acronyms)]
enum CachedRecord {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    Cname(String, String), // (from, to)
}

struct CachedEntry {
    record: CachedRecord,
    expiry: Instant,
}

struct ForwardEntry {
    entries: Vec<CachedEntry>,
}

pub struct DnsCache {
    forward: HashMap<String, ForwardEntry>,
    reverse: HashMap<IpAddr, Vec<(String, Instant)>>,
}

pub type SharedDnsCache = Arc<Mutex<DnsCache>>;

fn clamp_ttl(ttl_secs: u32) -> Duration {
    Duration::from_secs(ttl_secs as u64).clamp(MIN_TTL, MAX_TTL)
}

impl DnsCache {
    pub fn new() -> Self {
        Self {
            forward: HashMap::new(),
            reverse: HashMap::new(),
        }
    }

    pub fn insert(&mut self, domain: &str, records: &[DnsRecord]) {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        let now = Instant::now();

        let cached_entries: Vec<CachedEntry> = records
            .iter()
            .map(|r| match r {
                DnsRecord::A(addr, ttl) => CachedEntry {
                    record: CachedRecord::A(*addr),
                    expiry: now + clamp_ttl(*ttl),
                },
                DnsRecord::AAAA(addr, ttl) => CachedEntry {
                    record: CachedRecord::AAAA(*addr),
                    expiry: now + clamp_ttl(*ttl),
                },
                DnsRecord::Cname(from, to, ttl) => CachedEntry {
                    record: CachedRecord::Cname(
                        from.trim_end_matches('.').to_ascii_lowercase(),
                        to.trim_end_matches('.').to_ascii_lowercase(),
                    ),
                    expiry: now + clamp_ttl(*ttl),
                },
            })
            .collect();

        // Collect all CNAME "from" domains for reverse map association
        let cname_from_domains: Vec<String> = cached_entries
            .iter()
            .filter_map(|e| {
                if let CachedRecord::Cname(from, _) = &e.record {
                    Some(from.clone())
                } else {
                    None
                }
            })
            .collect();

        // Update reverse map: for each IP, add the query domain + CNAME from domains
        for entry in &cached_entries {
            let ip = match &entry.record {
                CachedRecord::A(addr) => IpAddr::V4(*addr),
                CachedRecord::AAAA(addr) => IpAddr::V6(*addr),
                CachedRecord::Cname(..) => continue,
            };
            let rev_entry = self.reverse.entry(ip).or_default();
            // Remove existing entries for this domain and CNAME from domains
            rev_entry.retain(|(d, _)| d != &domain && !cname_from_domains.contains(d));
            // Add the query domain
            rev_entry.push((domain.clone(), entry.expiry));
            // Add CNAME from domains (they are also associated with this IP)
            for cname_from in &cname_from_domains {
                if *cname_from != domain {
                    rev_entry.push((cname_from.clone(), entry.expiry));
                }
            }
        }

        self.forward.insert(domain, ForwardEntry { entries: cached_entries });
    }

    pub fn lookup_ips(&self, domain: &str) -> Option<Vec<IpAddr>> {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        let now = Instant::now();
        self.forward.get(&domain).and_then(|entry| {
            let ips: Vec<IpAddr> = entry
                .entries
                .iter()
                .filter(|e| now <= e.expiry)
                .filter_map(|e| match &e.record {
                    CachedRecord::A(addr) => Some(IpAddr::V4(*addr)),
                    CachedRecord::AAAA(addr) => Some(IpAddr::V6(*addr)),
                    CachedRecord::Cname(..) => None,
                })
                .collect();
            if ips.is_empty() { None } else { Some(ips) }
        })
    }

    pub fn lookup_domains(&self, ip: &IpAddr) -> Option<Vec<&str>> {
        let now = Instant::now();
        self.reverse
            .get(ip)
            .map(|entries| {
                entries
                    .iter()
                    .rev() // newest first (appended at end)
                    .filter(|(_, expiry)| now <= *expiry)
                    .map(|(domain, _)| domain.as_str())
                    .collect()
            })
            .and_then(|domains: Vec<&str>| if domains.is_empty() { None } else { Some(domains) })
    }

    pub fn lookup_with_ttl(&self, domain: &str) -> Option<Vec<DnsRecord>> {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        let now = Instant::now();
        self.forward.get(&domain).and_then(|entry| {
            let results: Vec<DnsRecord> = entry
                .entries
                .iter()
                .filter(|e| now <= e.expiry)
                .map(|e| {
                    let remaining_ttl = e.expiry.duration_since(now).as_secs() as u32;
                    match &e.record {
                        CachedRecord::A(addr) => DnsRecord::A(*addr, remaining_ttl),
                        CachedRecord::AAAA(addr) => DnsRecord::AAAA(*addr, remaining_ttl),
                        CachedRecord::Cname(from, to) => DnsRecord::Cname(from.clone(), to.clone(), remaining_ttl),
                    }
                })
                .collect();
            // Only return if there is at least one A/AAAA record (CNAME alone is useless)
            let has_ip = results.iter().any(|r| matches!(r, DnsRecord::A(..) | DnsRecord::AAAA(..)));
            if has_ip { Some(results) } else { None }
        })
    }

    pub fn evict_expired(&mut self) {
        let now = Instant::now();
        self.forward.retain(|_, entry| {
            entry.entries.retain(|e| now <= e.expiry);
            // Keep entry if any A/AAAA records remain (CNAME alone is meaningless)
            entry
                .entries
                .iter()
                .any(|e| matches!(e.record, CachedRecord::A(_) | CachedRecord::AAAA(_)))
        });
        self.reverse.retain(|_, entries| {
            entries.retain(|(_, expiry)| now <= *expiry);
            !entries.is_empty()
        });
    }
}

enum BypassPattern {
    Suffix(String),
    Wildcard(WildMatch),
}

pub struct BypassMatcher {
    patterns: Vec<BypassPattern>,
}

impl BypassMatcher {
    pub fn new(bypass_list: &[String]) -> Self {
        let patterns = bypass_list
            .iter()
            .map(|p| {
                let p = p.trim_end_matches('.').to_ascii_lowercase();
                if p.contains('*') || p.contains('?') {
                    BypassPattern::Wildcard(WildMatch::new(&p))
                } else {
                    let p = p.trim_start_matches('.').to_owned();
                    BypassPattern::Suffix(p)
                }
            })
            .collect();
        Self { patterns }
    }

    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    pub fn matches(&self, domain: &str) -> bool {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        self.patterns.iter().any(|pat| match pat {
            BypassPattern::Suffix(s) => domain == *s || domain.ends_with(&format!(".{s}")),
            BypassPattern::Wildcard(w) => w.matches(&domain),
        })
    }

    /// Returns true only when ALL the given domains match bypass patterns.
    /// Returns false if the list is empty (conservative: no domain info → no bypass).
    pub fn matches_all(&self, domains: &[&str]) -> bool {
        !domains.is_empty() && domains.iter().all(|d| self.matches(d))
    }
}

#[cfg(test)]
#[path = "dns_mapping_tests.rs"]
mod tests;
