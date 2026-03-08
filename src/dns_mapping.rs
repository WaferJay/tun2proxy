use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;
use wildmatch::WildMatch;

const MAPPING_TTL: Duration = Duration::from_secs(300);

pub struct DnsMapping {
    map: HashMap<IpAddr, (String, Instant)>,
}

pub type SharedDnsMapping = Arc<Mutex<DnsMapping>>;

impl DnsMapping {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    pub fn insert(&mut self, domain: &str, ips: &[IpAddr]) {
        let expiry = Instant::now() + MAPPING_TTL;
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        for ip in ips {
            self.map.insert(*ip, (domain.clone(), expiry));
        }
    }

    pub fn lookup(&self, ip: &IpAddr) -> Option<&str> {
        self.map.get(ip).and_then(|(domain, expiry)| {
            if Instant::now() <= *expiry {
                Some(domain.as_str())
            } else {
                None
            }
        })
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
