use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

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

    pub fn should_bypass(domain: &str, bypass_list: &[String]) -> bool {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        bypass_list.iter().any(|pattern| {
            let pattern = pattern.trim_start_matches('.').to_ascii_lowercase();
            domain == pattern || domain.ends_with(&format!(".{pattern}"))
        })
    }
}

#[cfg(test)]
#[path = "dns_mapping_tests.rs"]
mod tests;
