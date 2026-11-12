//! The shared 23-bit LCG and the two passes built on it.
//!
//! Generation 2 and generation 3 share the cipher core: a 92-character
//! substitution over ASCII 32..=126 minus `"`, `'` and `\`, driven by this
//! LCG, plus an element permutation whose key differs per generation.

pub use native_payload::cipher::{
    ALPHABET_92 as ALPHABET, desubstitute_92 as desubstitute, draw_lcg23 as draw, permute,
    permute_join, step_lcg23 as step, substitute_92 as substitute, swaps_lcg23 as swaps, unpermute,
    unpermute_join,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alphabet_is_printable_and_excludes_quotes() {
        assert_eq!(ALPHABET.len(), 92);
        assert!(ALPHABET.iter().all(|b| (32..=126).contains(b)));
        for excluded in *b"\"'\\" {
            assert!(!ALPHABET.contains(&excluded));
        }
    }

    #[test]
    fn substitution_round_trips_and_keeps_outside_bytes() {
        let text = "3;0;1,0 abc\"quoted\"\\slash";
        let encoded = substitute(text, 8_647_519);
        assert!(encoded.contains('"'));
        assert_eq!(desubstitute(&encoded, 8_647_519), text);
    }

    #[test]
    fn substitution_is_keyed() {
        let text = "the quick brown fox";
        assert_ne!(substitute(text, 1), substitute(text, 2));
    }

    #[test]
    fn permutation_round_trips() {
        let parts: Vec<String> = (0..17).map(|i| format!("p{i}")).collect();
        let joined = parts.join(":");
        let encoded = permute_join(&joined, ':', 123_456);
        assert_eq!(unpermute_join(&encoded, ':', 123_456), joined);
    }

    #[test]
    fn lcg_stays_in_range() {
        let mut state = 0x7f_ffff;
        for _ in 0..1000 {
            state = step(state);
            assert!(state <= 0x7f_ffff);
        }
    }
}
