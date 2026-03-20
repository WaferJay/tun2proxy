use crate::Error;
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
const MAX_CNAME_CHAIN: usize = 8;

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

        // If this insert has A/AAAA records, also update reverse map for any
        // existing CNAME entries that point to this domain (CNAME chain arriving
        // in separate responses).
        let has_ips = cached_entries
            .iter()
            .any(|e| matches!(e.record, CachedRecord::A(_) | CachedRecord::AAAA(_)));
        if has_ips {
            // Find all domains that have a CNAME pointing to `domain`
            let referring_domains: Vec<String> = self
                .forward
                .iter()
                .filter_map(|(d, fwd)| {
                    let points_here = fwd.entries.iter().any(|e| {
                        if let CachedRecord::Cname(_, to) = &e.record {
                            *to == domain
                        } else {
                            false
                        }
                    });
                    if points_here { Some(d.clone()) } else { None }
                })
                .collect();

            if !referring_domains.is_empty() {
                for entry in &cached_entries {
                    let (ip, expiry) = match &entry.record {
                        CachedRecord::A(addr) => (IpAddr::V4(*addr), entry.expiry),
                        CachedRecord::AAAA(addr) => (IpAddr::V6(*addr), entry.expiry),
                        CachedRecord::Cname(..) => continue,
                    };
                    let rev_entry = self.reverse.entry(ip).or_default();
                    for rd in &referring_domains {
                        rev_entry.retain(|(d, _)| d != rd);
                        rev_entry.push((rd.clone(), expiry));
                    }
                }
            }
        }

        self.forward.insert(domain, ForwardEntry { entries: cached_entries });
    }

    /// Follow CNAME chain from `domain`, returning the final target domain and
    /// all CNAME records along the way. Returns None if `domain` has no forward entry.
    fn follow_cname_chain(&self, domain: &str, now: Instant) -> Option<(String, Vec<DnsRecord>)> {
        let mut current = domain.to_owned();
        let mut cname_records = Vec::new();
        for _ in 0..MAX_CNAME_CHAIN {
            let entry = self.forward.get(&current)?;
            // Find a valid CNAME in this entry
            let cname = entry
                .entries
                .iter()
                .find(|e| now <= e.expiry && matches!(e.record, CachedRecord::Cname(..)));
            if let Some(ce) = cname {
                if let CachedRecord::Cname(from, to) = &ce.record {
                    let remaining_ttl = ce.expiry.duration_since(now).as_secs() as u32;
                    cname_records.push(DnsRecord::Cname(from.clone(), to.clone(), remaining_ttl));
                    current = to.clone();
                    continue;
                }
            }
            // No more CNAMEs — current is the final target
            return Some((current, cname_records));
        }
        // Chain too long, give up
        None
    }

    pub fn lookup_ips(&self, domain: &str) -> Option<Vec<IpAddr>> {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        let now = Instant::now();

        // Try direct lookup first
        if let Some(ips) = self.lookup_ips_direct(&domain, now) {
            return Some(ips);
        }

        // Follow CNAME chain
        let (target, _) = self.follow_cname_chain(&domain, now)?;
        if target == domain {
            return None;
        }
        self.lookup_ips_direct(&target, now)
    }

    fn lookup_ips_direct(&self, domain: &str, now: Instant) -> Option<Vec<IpAddr>> {
        self.forward.get(domain).and_then(|entry| {
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

        // Try direct lookup: if the entry has A/AAAA records, return them
        if let Some(results) = self.lookup_with_ttl_direct(&domain, now) {
            let has_ip = results.iter().any(|r| matches!(r, DnsRecord::A(..) | DnsRecord::AAAA(..)));
            if has_ip {
                return Some(results);
            }
        }

        // Follow CNAME chain to find A/AAAA records at the end
        let (target, cname_records) = self.follow_cname_chain(&domain, now)?;
        if cname_records.is_empty() {
            // No CNAME chain, and direct lookup already failed above
            return None;
        }

        // Look up A/AAAA at the target
        let target_records = self.lookup_with_ttl_direct(&target, now)?;
        let target_ips: Vec<DnsRecord> = target_records
            .into_iter()
            .filter(|r| matches!(r, DnsRecord::A(..) | DnsRecord::AAAA(..)))
            .collect();

        if target_ips.is_empty() {
            return None;
        }

        // Combine: CNAMEs first, then A/AAAA
        let mut combined = cname_records;
        combined.extend(target_ips);
        Some(combined)
    }

    fn lookup_with_ttl_direct(&self, domain: &str, now: Instant) -> Option<Vec<DnsRecord>> {
        self.forward.get(domain).map(|entry| {
            entry
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
                .collect()
        })
    }

    pub fn evict_expired(&mut self) {
        let now = Instant::now();
        self.forward.retain(|_, entry| {
            entry.entries.retain(|e| now <= e.expiry);
            !entry.entries.is_empty()
        });
        self.reverse.retain(|_, entries| {
            entries.retain(|(_, expiry)| now <= *expiry);
            !entries.is_empty()
        });
    }
}

pub enum BypassPattern {
    Fulltext(String),
    Wildcard(WildMatch),
    FulltextWithPort((String, u16)),
    WildcardWithPort((WildMatch, u16)),
}

impl std::fmt::Display for BypassPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BypassPattern::Fulltext(domain) => {
                write!(f, "{}", domain)
            }
            BypassPattern::Wildcard(wild_card) => {
                write!(f, "{}", wild_card)
            }
            BypassPattern::FulltextWithPort((domain, port)) => {
                write!(f, "{}:{}", domain, port)
            }
            BypassPattern::WildcardWithPort((wild_card, port)) => {
                write!(f, "{}:{}", wild_card, port)
            }
        }
    }
}

impl TryFrom<&String> for BypassPattern {
    type Error = Error;

    fn try_from(s: &String) -> crate::Result<Self> {
        let s = &s.trim().trim_start_matches(".").trim_end_matches(".").to_ascii_lowercase();
        if !s.contains(":") {
            return if s.contains('*') || s.contains('?') {
                Ok(Self::Wildcard(WildMatch::new(s)))
            } else {
                Ok(Self::Fulltext(s.to_string()))
            };
        }
        let mut slice = s.splitn(2, ":");
        let domain = slice.next().unwrap().trim_end_matches(".");
        let mut port = 0;
        if let Some(port_str) = slice.next() {
            match port_str.parse::<u16>() {
                Ok(p) => port = p,
                Err(_) => return Err(Error::from(format!("Invalid port number for pattern '{s}'"))),
            }
        };
        if s.contains('*') || s.contains('?') {
            Ok(Self::WildcardWithPort((WildMatch::new(domain), port)))
        } else {
            Ok(Self::FulltextWithPort((domain.to_string(), port)))
        }
    }
}

pub struct BypassMatcher {
    patterns: Vec<BypassPattern>,
}

impl BypassMatcher {
    pub fn new(patterns: Vec<BypassPattern>) -> Self {
        Self { patterns }
    }

    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    pub fn matches(&self, domain: &str, port: u16) -> bool {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        self.patterns.iter().any(|pat| match pat {
            BypassPattern::Fulltext(s) => domain == *s,
            BypassPattern::Wildcard(w) => w.matches(&domain),
            BypassPattern::FulltextWithPort((s, p)) => domain == *s && port == *p,
            BypassPattern::WildcardWithPort((w, p)) => w.matches(&domain) && port == *p,
        })
    }

    /// Returns true only when ALL the given domains match bypass patterns.
    /// Returns false if the list is empty (conservative: no domain info → no bypass).
    pub fn matches_all(&self, domains: &[&str], port: u16) -> bool {
        !domains.is_empty() && domains.iter().all(|d| self.matches(d, port))
    }
}

impl TryFrom<&Vec<String>> for BypassMatcher {
    type Error = Error;
    fn try_from(s: &Vec<String>) -> crate::Result<Self> {
        let mut list: Vec<BypassPattern> = Vec::with_capacity(s.len());
        for e in s {
            let pat = BypassPattern::try_from(e)?;
            list.push(pat);
        }
        Ok(Self::new(list))
    }
}

#[cfg(test)]
#[path = "dns_mapping_tests.rs"]
mod tests;
