use std::{
    collections::HashMap,
    net::IpAddr,
    rc::Rc,
    time::{Duration, Instant},
};

use crate::runtime::{
    config::config::Config,
    server::string_cache::{InternedString, StringCache},
};

#[derive(Debug)]
struct IpTokenBucket {
    bucket: Option<TokenBucket>,
    paths: HashMap<InternedString, TokenBucket>,
}

#[derive(Debug)]
struct TokenBucket {
    tokens: u64,
    last_poll: Instant,
}

#[derive(Debug, Clone)]
pub struct RateLimit {
    pub burst: u64,
    pub refill: u64,
}

#[derive(Debug)]
pub struct RateLimiter {
    ip_buckets: HashMap<IpAddr, IpTokenBucket>,
    path_rate_limits: HashMap<InternedString, RateLimit>,
    unknown_path_rate_limit: Option<RateLimit>,
    rate_limit_ip: Option<RateLimit>,
}

impl RateLimiter {
    pub fn from_config(config: &Config) -> Self {
        Self {
            ip_buckets: HashMap::new(),
            path_rate_limits: HashMap::new(),
            rate_limit_ip: Self::make_rate_limit(config.rate_limit_ip, config.burst_limit_ip),
            unknown_path_rate_limit: Self::make_rate_limit(
                config.rate_limit_path,
                config.burst_limit_path,
            ),
        }
    }

    pub fn make_rate_limit(rate: Option<u64>, burst: Option<u64>) -> Option<RateLimit> {
        rate.or(burst).map(|rate| RateLimit {
            refill: rate,
            burst: burst.unwrap_or(rate),
        })
    }

    pub fn insert_path_limit(&mut self, path: InternedString, limit: Option<RateLimit>) {
        if let Some(limit) = limit {
            self.path_rate_limits.insert(path, limit);
        }
    }

    pub fn allow(&mut self, ip: IpAddr, path: &str, string_cache: &StringCache) -> bool {
        let ip_bucket = self.ip_buckets.entry(ip).or_insert_with(|| IpTokenBucket {
            bucket: self.rate_limit_ip.as_ref().map(|limit| TokenBucket {
                tokens: limit.burst,
                last_poll: Instant::now(),
            }),
            paths: HashMap::new(),
        });

        if let Some(limit) = &self.rate_limit_ip
            && let Some(bucket) = &mut ip_bucket.bucket
        {
            bucket.replenish(limit);
            if bucket.tokens == 0 {
                return false;
            }
        }

        let path = string_cache.get(path);

        let path_rate_limit = path
            .as_ref()
            .and_then(|path| self.path_rate_limits.get(path))
            .or(self.unknown_path_rate_limit.as_ref());

        if let Some(limit) = path_rate_limit {
            let path_key = path.unwrap_or_else(|| InternedString(Rc::from("unknown")));

            let bucket = ip_bucket.paths.entry(path_key).or_insert(TokenBucket {
                tokens: limit.burst,
                last_poll: Instant::now(),
            });

            bucket.replenish(limit);

            if bucket.tokens == 0 {
                return false;
            }

            bucket.tokens -= 1;
        }

        if let Some(bucket) = &mut ip_bucket.bucket {
            bucket.tokens -= 1;
        }

        true
    }
}

impl TokenBucket {
    fn replenish(&mut self, limit: &RateLimit) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_poll);

        let replenished = (elapsed.as_nanos() * limit.refill as u128 / 1_000_000_000) as u64;

        if replenished == 0 {
            return;
        }

        let replenished = replenished.min(limit.burst.saturating_sub(self.tokens));

        self.tokens += replenished;
        self.last_poll += Duration::from_nanos(
            (replenished as u128 * 1_000_000_000 / limit.refill as u128) as u64,
        );
    }
}
