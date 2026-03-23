use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use axum::http::HeaderMap;
use axum::http::header::HeaderName;
use hashbrown::HashMap;
use parking_lot::Mutex;

const CLEANUP_EVERY_OPS: usize = 2048;
const MAX_KEY_LEN: usize = 256;
const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
const X_REAL_IP: HeaderName = HeaderName::from_static("x-real-ip");
const FORWARDED: HeaderName = HeaderName::from_static("forwarded");
const PRIVATE_CONNECT_IP_WINDOW_SECS: u64 = 60;
const PRIVATE_CONNECT_IP_RATE_LIMIT: usize = 150;
const PRIVATE_CONNECT_IP_CONCURRENT_MAX: usize = 64;

#[derive(Debug)]
struct SlidingWindowLimiter {
    window: Duration,
    max_keys: usize,
    buckets: Mutex<HashMap<String, VecDeque<Instant>>>,
    op_counter: AtomicUsize,
}

impl SlidingWindowLimiter {
    fn new(window: Duration, max_keys: usize) -> Self {
        Self {
            window,
            max_keys,
            buckets: Mutex::new(HashMap::new()),
            op_counter: AtomicUsize::new(0),
        }
    }

    fn allow(&self, raw_key: &str, limit: usize) -> bool {
        if limit == 0 {
            return false;
        }
        let Some(key) = normalize_key(raw_key) else {
            return true;
        };
        let now = Instant::now();
        let cutoff = now.checked_sub(self.window).unwrap_or(now);
        let mut buckets = self.buckets.lock();
        let queue = buckets.entry(key).or_insert_with(VecDeque::new);
        while queue.front().is_some_and(|ts| *ts <= cutoff) {
            let _ = queue.pop_front();
        }
        if queue.len() >= limit {
            return false;
        }
        queue.push_back(now);
        drop(buckets);

        let ops = self.op_counter.fetch_add(1, Ordering::Relaxed) + 1;
        if ops.is_multiple_of(CLEANUP_EVERY_OPS) {
            self.cleanup();
        }
        true
    }

    fn cleanup(&self) {
        let mut buckets = self.buckets.lock();
        if buckets.len() <= self.max_keys {
            return;
        }
        let now = Instant::now();
        let cutoff = now.checked_sub(self.window).unwrap_or(now);
        let mut stale_keys = Vec::with_capacity(self.max_keys.min(buckets.len()));
        for (key, queue) in buckets.iter_mut() {
            while queue.front().is_some_and(|ts| *ts <= cutoff) {
                let _ = queue.pop_front();
            }
            if queue.is_empty() {
                stale_keys.push(key.clone());
            }
            if stale_keys.len() >= self.max_keys {
                break;
            }
        }
        for key in stale_keys {
            buckets.remove(&key);
        }
    }
}

fn normalize_key(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut normalized = String::with_capacity(trimmed.len().min(MAX_KEY_LEN));
    for ch in trimmed.chars().take(MAX_KEY_LEN) {
        normalized.push(ch.to_ascii_lowercase());
    }
    Some(normalized)
}

/// Security-oriented client IP resolver.
///
/// Priority order: X-Forwarded-For -> X-Real-IP -> Forwarded -> peer socket IP.
/// Intended for deployments where proxy headers are forcibly overwritten upstream.
#[derive(Debug, Clone, Default)]
pub struct ClientIpResolver;

impl ClientIpResolver {
    pub fn resolve(&self, headers: &HeaderMap, peer_ip: Option<IpAddr>) -> Option<String> {
        if let Some(value) = header_value(headers, &X_FORWARDED_FOR)
            && let Some(ip) = parse_xff_first(value)
        {
            return Some(ip.to_string());
        }
        if let Some(value) = header_value(headers, &X_REAL_IP)
            && let Some(ip) = parse_ip_token(value)
        {
            return Some(ip.to_string());
        }
        if let Some(value) = header_value(headers, &FORWARDED)
            && let Some(ip) = parse_forwarded_first(value)
        {
            return Some(ip.to_string());
        }
        peer_ip.map(|ip| ip.to_string())
    }
}

fn header_value<'a>(headers: &'a HeaderMap, name: &HeaderName) -> Option<&'a str> {
    headers.get(name).and_then(|raw| raw.to_str().ok())
}

fn parse_xff_first(raw: &str) -> Option<IpAddr> {
    raw.split(',').find_map(parse_ip_token)
}

fn parse_forwarded_first(raw: &str) -> Option<IpAddr> {
    for segment in raw.split(',') {
        for pair in segment.split(';') {
            let (key, value) = match pair.split_once('=') {
                Some(v) => v,
                None => continue,
            };
            if !key.trim().eq_ignore_ascii_case("for") {
                continue;
            }
            if let Some(ip) = parse_forwarded_for_value(value.trim()) {
                return Some(ip);
            }
        }
    }
    None
}

fn parse_forwarded_for_value(raw: &str) -> Option<IpAddr> {
    if raw.eq_ignore_ascii_case("unknown") {
        return None;
    }
    let unquoted = raw.trim().trim_matches('"').trim();
    if unquoted.starts_with('_') {
        return None;
    }
    parse_ip_token(unquoted)
}

fn parse_ip_token(raw: &str) -> Option<IpAddr> {
    let value = raw.trim().trim_matches('"').trim();
    if value.is_empty() {
        return None;
    }

    if let Ok(ip) = value.parse::<IpAddr>() {
        return Some(ip);
    }

    if value.starts_with('[')
        && let Some(end_idx) = value.find(']')
    {
        let inner = &value[1..end_idx];
        if let Ok(ip) = inner.parse::<Ipv6Addr>() {
            return Some(IpAddr::V6(ip));
        }
    }

    if value.matches(':').count() == 1 {
        let host = value.split(':').next().unwrap_or("").trim();
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            return Some(IpAddr::V4(ip));
        }
    }

    None
}

pub fn parse_peer_remote_ip(remote_addr: Option<&str>) -> Option<String> {
    let raw = remote_addr?.trim();
    if raw.is_empty() {
        return None;
    }
    if let Ok(addr) = raw.parse::<SocketAddr>() {
        return Some(addr.ip().to_string());
    }
    if let Ok(ip) = raw.parse::<IpAddr>() {
        return Some(ip.to_string());
    }
    if raw.starts_with('[')
        && let Some(end_idx) = raw.find(']')
    {
        let inner = &raw[1..end_idx];
        if let Ok(ip) = inner.parse::<Ipv6Addr>() {
            return Some(ip.to_string());
        }
    }
    if raw.matches(':').count() == 1 {
        let host = raw.split(':').next().unwrap_or("").trim();
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            return Some(ip.to_string());
        }
    }
    None
}

#[derive(Debug)]
pub(crate) struct ApiRateLimiter {
    limiter: SlidingWindowLimiter,
}

impl Default for ApiRateLimiter {
    fn default() -> Self {
        Self {
            limiter: SlidingWindowLimiter::new(Duration::from_secs(10), 200_000),
        }
    }
}

impl ApiRateLimiter {
    pub fn allow_ip_global(&self, ip: Option<&str>) -> bool {
        let Some(ip) = normalize_key(ip.unwrap_or("")) else {
            return true;
        };
        let key = build_prefixed_key(&["api:ip:", ip.as_str()]);
        self.limiter.allow(key.as_str(), 1200)
    }

    pub fn allow_ip_route(&self, ip: Option<&str>, method: &str, route: &str) -> bool {
        let Some(ip) = normalize_key(ip.unwrap_or("")) else {
            return true;
        };
        let method = normalize_key(method).unwrap_or_else(|| "unknown".to_string());
        let route = normalize_key(route).unwrap_or_else(|| "unknown".to_string());
        let key = build_prefixed_key(&[
            "api:ip:",
            ip.as_str(),
            ":method:",
            method.as_str(),
            ":route:",
            route.as_str(),
        ]);
        self.limiter.allow(key.as_str(), 800)
    }

    pub fn allow_channel(&self, channel_id: &str) -> bool {
        let Some(channel_id) = normalize_key(channel_id) else {
            return true;
        };
        let key = build_prefixed_key(&["api:channel:", channel_id.as_str()]);
        self.limiter.allow(key.as_str(), 1600)
    }

    pub fn allow_device(&self, device_key: &str) -> bool {
        let Some(device_key) = normalize_key(device_key) else {
            return true;
        };
        let key = build_prefixed_key(&["api:device:", device_key.as_str()]);
        self.limiter.allow(key.as_str(), 1200)
    }
}

#[derive(Debug)]
pub struct PrivateRateLimiter {
    limiter: SlidingWindowLimiter,
    connect_concurrency: Mutex<HashMap<String, usize>>,
}

impl Default for PrivateRateLimiter {
    fn default() -> Self {
        Self {
            limiter: SlidingWindowLimiter::new(
                Duration::from_secs(PRIVATE_CONNECT_IP_WINDOW_SECS),
                100_000,
            ),
            connect_concurrency: Mutex::new(HashMap::new()),
        }
    }
}

impl PrivateRateLimiter {
    pub fn allow_ws_ip(&self, ip: Option<&str>) -> bool {
        let Some(ip) = normalize_key(ip.unwrap_or("")) else {
            return true;
        };
        let key = build_prefixed_key(&["private:ws:ip:", ip.as_str()]);
        self.limiter.allow(key.as_str(), 480)
    }

    pub fn allow_connect_device(&self, device_key: &str) -> bool {
        let Some(device_key) = normalize_key(device_key) else {
            return true;
        };
        let key = build_prefixed_key(&["private:connect:device:", device_key.as_str()]);
        self.limiter.allow(key.as_str(), 180)
    }

    pub fn allow_connect_ip(&self, ip: Option<&str>) -> bool {
        let Some(ip) = normalize_key(ip.unwrap_or("")) else {
            return true;
        };
        let key = build_prefixed_key(&["private:connect:ip:", ip.as_str()]);
        self.limiter
            .allow(key.as_str(), PRIVATE_CONNECT_IP_RATE_LIMIT)
    }

    pub fn try_acquire_connect_ip_slot(&self, ip: Option<&str>) -> bool {
        let Some(ip) = normalize_key(ip.unwrap_or("")) else {
            return true;
        };
        let mut concurrency = self.connect_concurrency.lock();
        let entry = concurrency.entry(ip).or_insert(0);
        if *entry >= PRIVATE_CONNECT_IP_CONCURRENT_MAX {
            return false;
        }
        *entry += 1;
        true
    }

    pub fn release_connect_ip_slot(&self, ip: Option<&str>) {
        let Some(ip) = normalize_key(ip.unwrap_or("")) else {
            return;
        };
        let mut concurrency = self.connect_concurrency.lock();
        let mut should_remove = false;
        if let Some(count) = concurrency.get_mut(&ip) {
            if *count > 0 {
                *count -= 1;
            }
            should_remove = *count == 0;
        }
        if should_remove {
            concurrency.remove(&ip);
        }
    }
}

fn build_prefixed_key(parts: &[&str]) -> String {
    let capacity = parts.iter().map(|part| part.len()).sum();
    let mut out = String::with_capacity(capacity);
    for part in parts {
        out.push_str(part);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::ClientIpResolver;
    use axum::http::{HeaderMap, HeaderValue};
    use std::net::IpAddr;

    #[test]
    fn resolver_prefers_xff_then_x_real_ip() {
        let resolver = ClientIpResolver;
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("198.51.100.9, 10.0.0.1"),
        );
        headers.insert("x-real-ip", HeaderValue::from_static("203.0.113.4"));
        let peer: IpAddr = "172.16.0.8".parse().expect("peer ip should parse");
        let resolved = resolver.resolve(&headers, Some(peer));
        assert_eq!(resolved.as_deref(), Some("198.51.100.9"));
    }

    #[test]
    fn resolver_falls_back_to_peer_ip() {
        let resolver = ClientIpResolver;
        let headers = HeaderMap::new();
        let peer: IpAddr = "172.16.0.8".parse().expect("peer ip should parse");
        let resolved = resolver.resolve(&headers, Some(peer));
        assert_eq!(resolved.as_deref(), Some("172.16.0.8"));
    }
}
