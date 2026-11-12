//! Proof-of-work solvers: the in-sensor `_abck` challenge and the `428 sec-cpt`
//! escalation challenge. Both reduce to a big-endian SHA-256 modulo search.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::abck::WorkItem;
use crate::{CodecError, Result};
use sha2::{Digest, Sha256};

/// Solved 10-round in-sensor proof-of-work answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub nonces: Vec<String>,
    pub millis: Vec<u64>,
    pub attempts: Vec<u64>,
    pub trace: String,
}

impl Answer {
    /// Wire representation inside `sensor_data`:
    /// `<nonces>;<ms per round>;<attempts per round>;<trace>;`.
    pub fn to_wire(&self) -> String {
        let join_u64 = |items: &[u64]| {
            items
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(",")
        };
        format!(
            "{};{};{};{};",
            self.nonces.join(","),
            join_u64(&self.millis),
            join_u64(&self.attempts),
            self.trace
        )
    }
}

/// Big-endian SHA-256 of `message` modulo `modulus`.
pub fn sha256_mod(message: &[u8], modulus: u32) -> u32 {
    if modulus <= 1 {
        return 0;
    }
    digest_mod(&Sha256::digest(message), modulus)
}

#[inline(always)]
fn digest_mod(digest: &[u8], modulus: u32) -> u32 {
    let m = u128::from(modulus);
    let c0 = u64::from_be_bytes(digest[0..8].try_into().unwrap());
    let c1 = u64::from_be_bytes(digest[8..16].try_into().unwrap());
    let c2 = u64::from_be_bytes(digest[16..24].try_into().unwrap());
    let c3 = u64::from_be_bytes(digest[24..32].try_into().unwrap());
    let rem = ((u128::from(c0) << 64) | u128::from(c1)) % m;
    let rem = ((rem << 64) | u128::from(c2)) % m;
    (((rem << 64) | u128::from(c3)) % m) as u32
}

#[inline(always)]
fn format_hex_u64(mut value: u64, buf: &mut [u8; 16]) -> &[u8] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    if value == 0 {
        buf[15] = b'0';
        return &buf[15..16];
    }
    let mut pos = 16;
    while value != 0 {
        pos -= 1;
        buf[pos] = HEX[(value & 0xf) as usize];
        value >>= 4;
    }
    &buf[pos..16]
}

/// Find the smallest `step` in `start..=end` whose `SHA256(base || hex(step)) % modulus == 0`.
fn search_first_nonce(
    base: &Sha256,
    modulus: u32,
    start: u64,
    end: u64,
    parallel_threads: usize,
) -> Option<u64> {
    if start > end {
        return None;
    }
    if modulus <= 1 {
        return Some(start);
    }
    if parallel_threads <= 1 || modulus < 2_048 || end - start < 2_048 {
        let mut hex_buf = [0u8; 16];
        for step in start..=end {
            let mut hasher = base.clone();
            hasher.update(format_hex_u64(step, &mut hex_buf));
            if digest_mod(&hasher.finalize(), modulus) == 0 {
                return Some(step);
            }
        }
        return None;
    }
    // Chunked parallel search preserving exact lowest-step determinism:
    // once any worker finds a match at `best`, no worker searches past `best`.
    const CHUNK: u64 = 512;
    let next_chunk = AtomicU64::new(start);
    let best = AtomicU64::new(u64::MAX);
    std::thread::scope(|scope| {
        for _ in 0..parallel_threads {
            let next_chunk = &next_chunk;
            let best = &best;
            scope.spawn(move || {
                let mut hex_buf = [0u8; 16];
                loop {
                    let chunk_start = next_chunk.fetch_add(CHUNK, Ordering::Relaxed);
                    let current_best = best.load(Ordering::Relaxed);
                    if chunk_start > end || chunk_start >= current_best {
                        break;
                    }
                    let chunk_end = chunk_start
                        .saturating_add(CHUNK - 1)
                        .min(end)
                        .min(current_best.saturating_sub(1));
                    for step in chunk_start..=chunk_end {
                        if step >= best.load(Ordering::Relaxed) {
                            break;
                        }
                        let mut hasher = base.clone();
                        hasher.update(format_hex_u64(step, &mut hex_buf));
                        if digest_mod(&hasher.finalize(), modulus) == 0 {
                            best.fetch_min(step, Ordering::Relaxed);
                            break;
                        }
                    }
                }
            });
        }
    });
    let winner = best.load(Ordering::Relaxed);
    (winner != u64::MAX).then_some(winner)
}

/// Verify one round of the in-sensor challenge.
pub fn verify_round(
    token: &str,
    start_ts: u64,
    salt: &str,
    difficulty: u32,
    round: u32,
    nonce: &str,
) -> bool {
    let modulus = difficulty.saturating_add(round);
    let message = format!("{token}{start_ts}{salt}{difficulty}{nonce}");
    sha256_mod(message.as_bytes(), modulus) == 0
}

/// Solve `rounds` rounds (default 10) for `item`, searching at most `budget`
/// nonces per round.
pub fn solve_in_sensor(
    token: &str,
    start_ts: u64,
    item: &WorkItem,
    rounds: u32,
    budget: u64,
) -> Result<Answer> {
    if item.difficulty == 0 {
        return Err(CodecError::Key("difficulty must be >= 1".to_owned()));
    }
    let prefix = format!("{token}{start_ts}{}", item.salt);
    let full_prefix = format!("{prefix}{}", item.difficulty);
    let mut base = Sha256::new();
    base.update(full_prefix.as_bytes());
    let threads = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1);
    let solve_round = |round: u32, inner_threads: usize| -> Result<(String, u64, u64)> {
        let modulus = item.difficulty + round;
        let tries = search_first_nonce(&base, modulus, 1, budget, inner_threads)
            .ok_or(CodecError::Budget { tries: budget })?;
        let nonce = format!("{tries:x}");
        let ms = (tries / 300).max(1);
        Ok((nonce, ms, tries))
    };
    let results: Vec<Result<(String, u64, u64)>> =
        if rounds > 1 && item.difficulty >= 512 && threads > 1 {
            let inner_threads = if item.difficulty >= 8_192 {
                (threads / 4).clamp(2, 4)
            } else {
                1
            };
            std::thread::scope(|scope| {
                let handles: Vec<_> = (0..rounds)
                    .map(|round| scope.spawn(move || solve_round(round, inner_threads)))
                    .collect();
                handles.into_iter().map(|h| h.join().unwrap()).collect()
            })
        } else {
            let inner_threads = if item.difficulty >= 2_048 { threads } else { 1 };
            (0..rounds)
                .map(|round| solve_round(round, inner_threads))
                .collect()
        };
    let mut nonces = Vec::with_capacity(rounds as usize);
    let mut millis = Vec::with_capacity(rounds as usize);
    let mut attempts = Vec::with_capacity(rounds as usize);
    let mut trace = String::new();
    for (round, res) in results.into_iter().enumerate() {
        let (nonce, ms, tries) = res?;
        if round == 0 {
            let modulus = item.difficulty;
            let message = format!("{full_prefix}{nonce}");
            let hash = hex_sha256(message.as_bytes());
            trace = format!(
                "{},{start_ts},{},{prefix},{},{modulus},{nonce},{message},{hash},1",
                item.salt, item.id, item.difficulty
            );
        }
        nonces.push(nonce);
        millis.push(ms);
        attempts.push(tries);
    }

    Ok(Answer {
        nonces,
        millis,
        attempts,
        trace,
    })
}

/// Solve the `428 sec-cpt` crypto challenge: `sec || timestamp || nonce || difficulty || candidate`
/// hashed with SHA-256, modulo `difficulty + round == 0`.
pub fn solve_sec_cpt(
    timestamp: u64,
    nonce: &str,
    difficulty: u32,
    rounds: u32,
    budget: u64,
) -> Result<Vec<String>> {
    if !(1..=65_536).contains(&difficulty) {
        return Err(CodecError::Key(
            "difficulty must be in 1..=65536".to_owned(),
        ));
    }
    let prefix = format!("sec{timestamp}{nonce}{difficulty}");
    let threads = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1);
    let solve_round = |round: u32, inner_threads: usize| -> Result<String> {
        let modulus = difficulty + round;
        let round_prefix = format!("{prefix}{round:04x}");
        let mut base = Sha256::new();
        base.update(round_prefix.as_bytes());
        let end = budget.saturating_sub(1);
        let step = search_first_nonce(&base, modulus, 0, end, inner_threads)
            .ok_or(CodecError::Budget { tries: budget })?;
        Ok(format!("{round:04x}{step:x}"))
    };
    if rounds > 1 && difficulty >= 512 && threads > 1 {
        let inner_threads = if difficulty >= 8_192 {
            (threads / 4).clamp(2, 4)
        } else {
            1
        };
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..rounds)
                .map(|round| scope.spawn(move || solve_round(round, inner_threads)))
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        })
    } else {
        let inner_threads = if difficulty >= 2_048 { threads } else { 1 };
        (0..rounds)
            .map(|round| solve_round(round, inner_threads))
            .collect()
    }
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_sensor_pow_solves_and_verifies() {
        let item = WorkItem {
            id: "1".to_owned(),
            salt: "s".to_owned(),
            difficulty: 5,
            delay_ms: 0,
            slice_ms: 1000,
            version: Some(2),
        };
        let answer = solve_in_sensor("TOK", 1000, &item, 4, 10_000).expect("answer");
        assert_eq!(answer.nonces.len(), 4);
        for (round, nonce) in answer.nonces.iter().enumerate() {
            assert!(verify_round("TOK", 1000, "s", 5, round as u32, nonce));
        }
        assert!(answer.to_wire().ends_with(';'));
    }

    #[test]
    fn sec_cpt_pow_produces_requested_rounds() {
        let answers = solve_sec_cpt(1_700_000_000, "abc", 8, 3, 10_000).expect("cpt");
        assert_eq!(answers.len(), 3);
    }

    #[test]
    fn parallel_nonce_search_matches_sequential_lowest_winner() {
        let mut base = Sha256::new();
        base.update(b"TOK1000s4096");
        let seq = search_first_nonce(&base, 4096, 1, 100_000, 1).expect("seq");
        let par = search_first_nonce(&base, 4096, 1, 100_000, 4).expect("par");
        assert_eq!(seq, par);
    }
}
