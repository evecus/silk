//! IP -> domain reverse map fed by the DNS engine.
//!
//! Proxied TCP flows arrive as bare IPs. When the client resolved the name
//! through us, the engine remembers which name each answer address belongs
//! to, so the outbound can be dialled by name (the proxy exit then resolves
//! it itself, immune to local poisoning). An address shared by several live
//! names is ambiguous and yields no name.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const MAX_ENTRIES: usize = 20_000;
const MAX_NAMES_PER_IP: usize = 4;

#[derive(Default)]
pub struct NameCache {
    inner: Mutex<HashMap<IpAddr, Vec<(String, Instant)>>>,
}

impl NameCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, ip: IpAddr, name: &str, ttl: Duration) {
        if name.is_empty() {
            return;
        }
        let ip = ip.to_canonical();
        let now = Instant::now();
        let mut m = self.inner.lock().unwrap();
        if m.len() >= MAX_ENTRIES {
            m.retain(|_, v| {
                v.retain(|(_, exp)| *exp > now);
                !v.is_empty()
            });
            if m.len() >= MAX_ENTRIES {
                m.clear();
            }
        }
        let names = m.entry(ip).or_default();
        names.retain(|(n, exp)| *exp > now && n != name);
        names.push((name.to_string(), now + ttl));
        if names.len() > MAX_NAMES_PER_IP {
            names.remove(0);
        }
    }

    /// The single live name for `ip`, or None when unknown / ambiguous.
    pub fn lookup(&self, ip: IpAddr) -> Option<String> {
        let ip = ip.to_canonical();
        let now = Instant::now();
        let m = self.inner.lock().unwrap();
        let live: Vec<&String> = m
            .get(&ip)?
            .iter()
            .filter(|(_, exp)| *exp > now)
            .map(|(n, _)| n)
            .collect();
        if live.len() == 1 {
            Some(live[0].clone())
        } else {
            None
        }
    }
}
