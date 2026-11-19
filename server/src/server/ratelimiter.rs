use std::{collections::HashMap, hash_map, net::Ipv4Addr, time::Instant};


struct IpRateLimitBucket {
    tokens: u16,
    last_poll: Instant,
    paths: HashMap<String, u16>
}

struct RateLimiter {
    ip_buckets: HashMap<Ipv4Addr, IpRateLimitBucket>,
    unknown_path_rate_limit: u16
}


impl RateLimiter {
    fn new() -> Self {
        Self {
            ip_buckets: HashMap::new(),
            unknown_path_rate_limit: 100
        }
    }

    fn allow(&mut self, ip: Ipv4Addr, path: String) -> bool {
        let entry = self
            .ip_buckets
            .entry(ip)
            .and_modify(|e| {
                e.paths.entry(|ep| ep ).or_insert(default);
            })
            .or_insert(IpRateLimitBucket {
                tokens: 0,
                paths: hash_map! {
                    path => self.unknown_path_rate_limit
                },
                last_poll: Instant::now(),
            });

        true
    }
}
