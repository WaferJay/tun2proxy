use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;
use wildmatch::WildMatch;

const DEFAULT_TTL: Duration = Duration::from_secs(300);
const MIN_TTL: Duration = Duration::from_secs(10);
const MAX_TTL: Duration = Duration::from_secs(3600);

struct CachedIp {
    addr: IpAddr,
    expiry: Instant,
}

struct ForwardEntry {
    ips: Vec<CachedIp>,
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

    pub fn insert(&mut self, domain: &str, entries: &[(IpAddr, u32)]) {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        let now = Instant::now();

        let cached_ips: Vec<CachedIp> = entries
            .iter()
            .map(|(addr, ttl)| {
                let expiry = now + clamp_ttl(*ttl);
                CachedIp { addr: *addr, expiry }
            })
            .collect();

        // Update reverse map
        for ci in &cached_ips {
            let rev_entry = self.reverse.entry(ci.addr).or_insert_with(Vec::new);
            // Remove existing entry for this domain (will re-add at end for recency)
            rev_entry.retain(|(d, _)| d != &domain);
            rev_entry.push((domain.clone(), ci.expiry));
        }

        self.forward.insert(domain, ForwardEntry { ips: cached_ips });
    }

    pub fn insert_with_default_ttl(&mut self, domain: &str, ips: &[IpAddr]) {
        let entries: Vec<(IpAddr, u32)> = ips.iter().map(|ip| (*ip, DEFAULT_TTL.as_secs() as u32)).collect();
        self.insert(domain, &entries);
    }

    pub fn lookup_ips(&self, domain: &str) -> Option<Vec<IpAddr>> {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        let now = Instant::now();
        self.forward.get(&domain).map(|entry| {
            entry
                .ips
                .iter()
                .filter(|ci| now <= ci.expiry)
                .map(|ci| ci.addr)
                .collect()
        }).and_then(|ips: Vec<IpAddr>| if ips.is_empty() { None } else { Some(ips) })
    }

    pub fn lookup_domains(&self, ip: &IpAddr) -> Option<Vec<&str>> {
        let now = Instant::now();
        self.reverse.get(ip).map(|entries| {
            entries
                .iter()
                .rev() // newest first (appended at end)
                .filter(|(_, expiry)| now <= *expiry)
                .map(|(domain, _)| domain.as_str())
                .collect()
        }).and_then(|domains: Vec<&str>| if domains.is_empty() { None } else { Some(domains) })
    }

    pub fn evict_expired(&mut self) {
        let now = Instant::now();
        self.forward.retain(|_, entry| {
            entry.ips.retain(|ci| now <= ci.expiry);
            !entry.ips.is_empty()
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
}

#[cfg(test)]
#[path = "dns_mapping_tests.rs"]
mod tests;
