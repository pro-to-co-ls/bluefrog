//! Time-windowed UDP connection-id scheme (BEP-15).
//!
//! A keyed BLAKE3 MAC over `(source_ip, window_index)`, where the window rotates every
//! [`ConnId::window_secs`]. An id is accepted for the current *or* previous window, giving
//! `window..2*window` seconds of validity. With the default 120 s window that is 120–240 s of
//! tracker-side acceptance — satisfying BEP-15 (clients reuse ≤1 min; trackers should accept
//! ≤2 min) while keeping ids short-lived, so a captured id expires quickly.

/// A keyed connection-id generator/validator.
pub struct ConnId {
    key: [u8; 32],
    window_secs: u64,
}

impl ConnId {
    /// Create a generator from a 32-byte secret key and a window length in seconds.
    ///
    /// `window_secs` is clamped to at least 1 to avoid a zero-length window.
    #[must_use]
    pub fn new(key: [u8; 32], window_secs: u64) -> Self {
        Self {
            key,
            window_secs: window_secs.max(1),
        }
    }

    fn for_window(&self, ip: &[u8], window: u64) -> u64 {
        let mut hasher = blake3::Hasher::new_keyed(&self.key);
        hasher.update(ip);
        hasher.update(&window.to_le_bytes());
        let b = hasher.finalize();
        let b = b.as_bytes();
        u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    }

    /// The connection id to hand out for `ip` at time `now_secs` (current window).
    #[must_use]
    pub fn generate(&self, ip: &[u8], now_secs: u64) -> u64 {
        self.for_window(ip, now_secs / self.window_secs)
    }

    /// Whether `id` is a valid connection id for `ip` at `now_secs` (current or previous window).
    #[must_use]
    pub fn validate(&self, id: u64, ip: &[u8], now_secs: u64) -> bool {
        let window = now_secs / self.window_secs;
        id == self.for_window(ip, window) || (window > 0 && id == self.for_window(ip, window - 1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [0x5a; 32];
    const IP: [u8; 16] = [1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    #[test]
    fn generate_is_deterministic_and_ip_specific() {
        let c = ConnId::new(KEY, 120);
        assert_eq!(c.generate(&IP, 1000), c.generate(&IP, 1000));
        let other = [9u8; 16];
        assert_ne!(c.generate(&IP, 1000), c.generate(&other, 1000));
    }

    #[test]
    fn validate_accepts_current_and_previous_window() {
        let c = ConnId::new(KEY, 120);
        let now = 10_000u64;
        let id = c.generate(&IP, now);
        assert!(c.validate(id, &IP, now));
        // id issued in the previous window is still accepted a window later
        let prev_id = c.generate(&IP, now);
        assert!(c.validate(prev_id, &IP, now + 120));
        // but not two windows later
        assert!(!c.validate(prev_id, &IP, now + 240));
    }

    #[test]
    fn validate_rejects_forged_and_wrong_ip() {
        let c = ConnId::new(KEY, 120);
        let now = 10_000u64;
        assert!(!c.validate(0xdead_beef_dead_beef, &IP, now));
        let id = c.generate(&IP, now);
        assert!(!c.validate(id, &[9u8; 16], now));
    }

    #[test]
    fn early_time_only_checks_current_window() {
        let c = ConnId::new(KEY, 120);
        // now_secs < window_secs -> window 0, no previous window to check
        let id = c.generate(&IP, 5);
        assert!(c.validate(id, &IP, 5));
        assert!(!c.validate(id.wrapping_add(1), &IP, 5));
    }

    #[test]
    fn zero_window_is_clamped() {
        let c = ConnId::new(KEY, 0);
        // must not divide by zero
        let id = c.generate(&IP, 42);
        assert!(c.validate(id, &IP, 42));
    }
}
