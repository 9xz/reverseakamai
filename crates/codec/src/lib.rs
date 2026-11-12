//! Akamai primitives implemented in Rust: `_abck` state, the v2/v3 sensor
//! cipher, the in-sensor and `sec-cpt` proof-of-work, the pixel beacon, and the
//! BMP bytecode VM.
//!
//! Everything here is byte-exact against the formats documented in `docs/`; the
//! VM interpreter covers the stack/arithmetic subset of the opcode table and
//! reports the rest as unsupported rather than guessing.

pub mod abck;
pub mod lcg;
pub mod pixel;
pub mod pow;
pub mod script;
pub mod sensor;
pub mod vm;

use std::fmt;

/// Things the codec can refuse to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    /// Input did not have the expected framing.
    Format(String),
    /// A key or difficulty was missing or unusable.
    Key(String),
    /// A search exceeded its attempt budget.
    Budget { tries: u64 },
    /// A VM instruction the interpreter does not implement.
    Unsupported { offset: usize, opcode: u8 },
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Format(message) => write!(f, "format: {message}"),
            Self::Key(message) => write!(f, "key: {message}"),
            Self::Budget { tries } => write!(f, "no answer after {tries} attempts"),
            Self::Unsupported { offset, opcode } => {
                write!(f, "unsupported opcode 0x{opcode:02x} at {offset}")
            }
        }
    }
}

impl std::error::Error for CodecError {}

pub type Result<T, E = CodecError> = std::result::Result<T, E>;
