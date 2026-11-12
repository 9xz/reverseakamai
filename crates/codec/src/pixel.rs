//! The `/akam/13/<hash>` pixel challenge: endpoint hash derivation and `t` token.

use sha1::{Digest, Sha1};

/// Compute the 8-hex suffix in `/akam/13/pixel_<hash>` from `bazadebezolkohpepadr`.
pub fn endpoint_hash(seed: u64) -> String {
    format!("{:x}", 77 ^ seed)
}

/// `t` field posted in the pixel form body: lowercase hex SHA-1 of the seed.
pub fn seed_token(seed: &str) -> String {
    let digest = Sha1::digest(seed.as_bytes());
    let mut out = String::with_capacity(40);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Decode the 4th-from-last path segment's configuration bits (1 bit per pair,
/// `1` if either character is in `"aeiouy13579"`).
pub fn url_config_bits(path: &str) -> Option<String> {
    if path.contains("/akam/") {
        return None;
    }
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if segments.len() < 4 {
        return None;
    }
    let segment = segments[segments.len() - 4];
    if segment.len() <= 6 || !segment.len().is_multiple_of(2) {
        return None;
    }
    const MARK: &[u8] = b"aeiouy13579";
    let bytes = segment.as_bytes();
    let mut bits = String::with_capacity(bytes.len() / 2);
    for &[first, second] in bytes.as_chunks::<2>().0 {
        let f = first.to_ascii_lowercase();
        let s = second.to_ascii_lowercase();
        let bit = MARK.contains(&f) || MARK.contains(&s);
        bits.push(if bit { '1' } else { '0' });
    }
    Some(bits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_matches_documented_example() {
        assert_eq!(endpoint_hash(1_320_943_881), "4ebc0144");
    }

    #[test]
    fn url_bits_match_measured_segment() {
        let path = "/Gcv/aYOGDfhYcEiODrXO/Zr9/LxN/Qj4";
        assert_eq!(url_config_bits(path).as_deref(), Some("11011101"));
    }

    #[test]
    fn token_is_40_hex_sha1() {
        assert_eq!(seed_token("1320943881").len(), 40);
    }
}
